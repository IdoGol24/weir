"""Stage 2: pure mapping (wire -> CanonicalTrace + ledger). Never raises on
content - everything semantically wrong degrades (M4 design section 2).

Kind derives from real OTel signals ONLY: gen_ai.operation.name, span kind
(CLIENT=3 vs INTERNAL=1), gen_ai.tool.name presence, the parent link.
Everything under weir.* is producer self-description and untrusted - it may
be surfaced in reporting but never decides an analysis-bearing field.
Actor reconstructs from kind via the invariant tracegen pins by test.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import cast

import msgspec

from weir.adapters.otel._contract import Degradation, DegradationReason
from weir.adapters.otel._wire import SpanInContext, WireInput, WireSpan
from weir.schema.dialect import DIALECT_REGISTRY, OTEL_GENAI_1_42_0, DialectProfile
from weir.schema.trace import (
    SCHEMA_VERSION,
    CanonicalTrace,
    JoinConfidence,
    JoinRecord,
    LlmCallPayload,
    NodeKind,
    Payload,
    ToolCallPayload,
    ToolResultPayload,
    TraceMetadata,
    TraceNode,
    UserInputPayload,
)

_SPAN_KIND_CLIENT = 3

_SPAN_KIND_NAMES = {
    "SPAN_KIND_UNSPECIFIED": 0,
    "SPAN_KIND_INTERNAL": 1,
    "SPAN_KIND_SERVER": 2,
    "SPAN_KIND_CLIENT": 3,
    "SPAN_KIND_PRODUCER": 4,
    "SPAN_KIND_CONSUMER": 5,
}


def span_kind_int(kind: str | int) -> int:
    """Permissive like the nano fields: OTLP/JSON mandates int enums, but
    default-options protojson emits the proto enum NAMES; both are real."""
    if isinstance(kind, int):
        return kind
    return _SPAN_KIND_NAMES.get(kind, 0)


_ACTOR_BY_KIND = {
    NodeKind.USER_INPUT: "user",
    NodeKind.LLM_CALL: "agent",
    NodeKind.TOOL_CALL: "agent",
    NodeKind.TOOL_RESULT: "tool",
}

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)


def attr_str(attributes: list[dict[str, object]], key: str) -> str | None:
    for raw_entry in cast("list[object]", attributes):
        if not isinstance(raw_entry, dict):
            continue
        entry = cast("dict[str, object]", raw_entry)
        if entry.get("key") == key:
            value = entry.get("value")
            if isinstance(value, dict):
                s = cast("dict[str, object]", value).get("stringValue")
                if isinstance(s, str):
                    return s
            return None
    return None


def has_genai_marker(attributes: list[dict[str, object]]) -> bool:
    for raw_entry in cast("list[object]", attributes):
        if not isinstance(raw_entry, dict):
            continue
        key = cast("dict[str, object]", raw_entry).get("key")
        if isinstance(key, str) and key.startswith("gen_ai."):
            return True
    return False


def derive_kind(span: WireSpan) -> NodeKind | None:
    """From real signals only; None means unmappable (a named degradation)."""
    operation = attr_str(span.attributes, "gen_ai.operation.name")
    client = span_kind_int(span.kind) == _SPAN_KIND_CLIENT
    if operation == "execute_tool":
        return NodeKind.TOOL_CALL if client else NodeKind.TOOL_RESULT
    if operation == "chat":
        return NodeKind.LLM_CALL if client else NodeKind.USER_INPUT
    if operation is None and attr_str(span.attributes, "gen_ai.tool.name") is not None:
        return NodeKind.TOOL_CALL if client else NodeKind.TOOL_RESULT
    return None


def actor_for(kind: NodeKind) -> str:
    return _ACTOR_BY_KIND[kind]


def span_content_digest(raw_token_fields: tuple[str, ...]) -> str:
    """Order-independent tie-break material (M4 design section 2): a digest
    over the span's identifying content, never its input position."""
    joined = "\x1f".join(raw_token_fields)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _wire_span_digest(span: WireSpan) -> str:
    """Digest over the WHOLE wire span (M4 final-review fix): the identity
    tie-break must cover every field (parentSpanId included), not a chosen
    subset - two differing spans must never conflate as identical just
    because the fields this module happened to hash agreed. msgspec struct
    encoding has stable field order, so this is deterministic."""
    return span_content_digest((msgspec.json.encode(span).decode(),))


def iso_from_nanos(value: str | int) -> str | None:
    """OTLP nanos -> the exact ISO shape SeededClock produces
    (isoformat + Z, microseconds shown only when nonzero). Sub-microsecond
    precision truncates silently - ISO-8601 at this shape cannot carry it.
    Returns None when unparseable (a named degradation upstream)."""
    try:
        nanos = int(value)
    except (TypeError, ValueError):
        return None
    if nanos < 0:
        return None
    instant = _EPOCH + datetime.timedelta(microseconds=nanos // 1000)
    return instant.isoformat().replace("+00:00", "Z")


def parse_json_object(text: str) -> tuple[dict[str, object] | None, bool]:
    """(parsed, truncation_fingerprint). The fingerprint covers the two
    shapes a payload limit leaves: the decode error sits at end-of-input
    (cut between tokens), or the input ends inside an unterminated string
    (cut mid-value - json reports these at the OPENING quote, so position
    alone cannot catch them). Anything else unparseable is
    UNPARSEABLE_CONTENT, not TRUNCATED_CONTENT."""
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        truncated = exc.pos >= len(text.rstrip()) or exc.msg.startswith(
            "Unterminated string"
        )
        return None, truncated
    if isinstance(parsed, dict):
        return cast("dict[str, object]", parsed), False
    return None, False


JOIN_SOURCE_EXPLICIT = "attr:gen_ai.tool.call.id"
JOIN_SOURCE_NESTED = "parent_span"
JOIN_SOURCE_MINED = "content:tool_call_id"


class MappedSpan(msgspec.Struct, frozen=True):
    """The join-relevant projection of one mapped span. `mined_id` is the
    dialect-pinned content path (tool_call args key `tool_call_id`; result
    content JSON key `tool_call_id`) - never a regex over a blob."""

    source_ref: str
    kind: NodeKind
    call_id_attr: str | None
    parent_token: str
    mined_id: str | None


def build_joins(
    spans: list[MappedSpan],
) -> tuple[list[JoinRecord], list[Degradation]]:
    """Precedence per R1.4 + M4 section 3: explicit > nested > content_mined.
    Content-mined fills ABSENCES only; the envelope wins conflicts, named on
    the ledger. Ambiguity yields no join, never a pick - and it is SYMMETRIC:
    an id shared by multiple CALLS is exactly as ambiguous as an id matching
    multiple results, because a positional pick on the call side would be
    silent greedy stealing in the one place an injected document can
    manufacture the duplicate. Envelope tiers run for ALL calls before any
    content-mined tier runs, so mined evidence can never claim a result out
    from under envelope evidence regardless of call order. HEURISTIC is
    never assigned. Deterministic: spans arrive in the caller's
    order-independent sort (time, then id)."""
    degradations: list[Degradation] = []
    calls = [s for s in spans if s.kind == NodeKind.TOOL_CALL]
    results = [s for s in spans if s.kind == NodeKind.TOOL_RESULT]

    def duplicated(values: list[str | None]) -> set[str]:
        counts: dict[str, int] = {}
        for v in values:
            if v:
                counts[v] = counts.get(v, 0) + 1
        return {v for v, n in counts.items() if n > 1}

    # Call-side ambiguity, precomputed per tier: one ledger entry per
    # duplicated id, and the tier that carried it is dead for every call
    # involved - but the call's OTHER, unambiguous tiers still apply.
    ambiguous_explicit = duplicated([c.call_id_attr for c in calls])
    ambiguous_mined = duplicated([c.mined_id for c in calls])
    for value in sorted(ambiguous_explicit):
        degradations.append(Degradation(
            reason=DegradationReason.AMBIGUOUS_JOIN, subject=value,
            note="gen_ai.tool.call.id shared by multiple calls"))
    for value in sorted(ambiguous_mined):
        degradations.append(Degradation(
            reason=DegradationReason.AMBIGUOUS_JOIN, subject=value,
            note="mined id shared by multiple calls"))

    def unique_match(candidates: list[MappedSpan], *, subject: str,
                     note: str) -> MappedSpan | None:
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            degradations.append(
                Degradation(reason=DegradationReason.AMBIGUOUS_JOIN,
                            subject=subject, note=note)
            )
        return None

    records: list[JoinRecord | None] = [None] * len(calls)
    joined_results: set[str] = set()

    # Pass 1: envelope tiers (explicit, nested) for every call, in order -
    # this claims results before any content-mined evidence is consulted.
    for i, call in enumerate(calls):
        record: JoinRecord | None = None
        # Tier 1: explicit attribute (skipped when the id is call-side
        # ambiguous - already ledgered above - or empty, which is
        # semantically absent, never evidence).
        if call.call_id_attr and call.call_id_attr not in ambiguous_explicit:
            matches = [r for r in results if r.call_id_attr == call.call_id_attr
                       and r.source_ref not in joined_results]
            found = unique_match(
                matches, subject=call.source_ref,
                note=f"gen_ai.tool.call.id {call.call_id_attr!r} matches "
                     f"{len(matches)} results")
            if found is not None:
                record = JoinRecord(
                    tool_call_source_ref=call.source_ref,
                    tool_result_source_ref=found.source_ref,
                    join_confidence=JoinConfidence.EXPLICIT,
                    join_source=JOIN_SOURCE_EXPLICIT,
                )
        # Tier 2: parent/child nesting.
        if record is None:
            matches = [r for r in results if r.parent_token == call.source_ref
                       and r.source_ref not in joined_results]
            found = unique_match(
                matches, subject=call.source_ref,
                note=f"{len(matches)} results parent to this call")
            if found is not None:
                record = JoinRecord(
                    tool_call_source_ref=call.source_ref,
                    tool_result_source_ref=found.source_ref,
                    join_confidence=JoinConfidence.NESTED,
                    join_source=JOIN_SOURCE_NESTED,
                )
        if record is not None:
            records[i] = record
            joined_results.add(record.tool_result_source_ref)

    # Pass 2: content-mined - fills absences only (and never from a
    # call-side-ambiguous or empty mined id) - and the conflict check for
    # calls the envelope already claimed.
    for i, call in enumerate(calls):
        record = records[i]
        if record is None and call.mined_id and call.mined_id not in ambiguous_mined:
            matches = [r for r in results if r.mined_id == call.mined_id
                       and r.source_ref not in joined_results]
            found = unique_match(
                matches, subject=call.source_ref,
                note=f"mined id {call.mined_id!r} matches {len(matches)} results")
            if found is not None:
                record = JoinRecord(
                    tool_call_source_ref=call.source_ref,
                    tool_result_source_ref=found.source_ref,
                    join_confidence=JoinConfidence.CONTENT_MINED,
                    join_source=JOIN_SOURCE_MINED,
                )
                records[i] = record
                joined_results.add(record.tool_result_source_ref)
        elif record is not None and call.mined_id and call.mined_id not in ambiguous_mined:
            # Envelope join exists AND mined evidence points elsewhere:
            # resolved per precedence, conflict named, never silent.
            mined_elsewhere = [
                r for r in results
                if r.mined_id == call.mined_id
                and r.source_ref != record.tool_result_source_ref
            ]
            if mined_elsewhere:
                degradations.append(
                    Degradation(
                        reason=DegradationReason.CONFLICTING_JOIN_EVIDENCE,
                        subject=call.source_ref,
                        note=(
                            f"envelope join to {record.tool_result_source_ref} "
                            f"but mined id {call.mined_id!r} also matches "
                            + ",".join(r.source_ref for r in mined_elsewhere)
                        ),
                    )
                )

    joins = [r for r in records if r is not None]
    return joins, degradations


ADAPTER_NAME = "otel"
ADAPTER_VERSION = "0.1.0"
_SCOPE_PREFIX = "opentelemetry.instrumentation."
_HEX_ID_WIDTHS = {16, 32}


class AdapterResult(msgspec.Struct, frozen=True):
    trace: CanonicalTrace
    degradations: list[Degradation]


def _select_profile(
    spans: list[SpanInContext], degradations: list[Degradation]
) -> tuple[DialectProfile, bool]:
    """schemaUrl + structural fingerprint ONLY - never weir.* (untrusted).
    Returns (profile, unknown_dialect_flag)."""
    for ctx in spans:
        for profile in DIALECT_REGISTRY.values():
            if ctx.schema_url == profile.schema_url:
                return profile, False
    # Structural fingerprint: any registered-profile attribute key present.
    profile_keys = {spec.key for spec in OTEL_GENAI_1_42_0.attributes}
    for ctx in spans:
        for raw_entry in cast("list[object]", ctx.span.attributes):
            if not isinstance(raw_entry, dict):
                continue
            entry = cast("dict[str, object]", raw_entry)
            if entry.get("key") in profile_keys:
                return OTEL_GENAI_1_42_0, False
    degradations.append(
        Degradation(
            reason=DegradationReason.UNKNOWN_DIALECT,
            subject="resource",
            note="no schemaUrl or attribute fingerprint matched a registered "
                 "dialect; mapped under the default row",
        )
    )
    return OTEL_GENAI_1_42_0, True


def _is_hex_id(token: str) -> bool:
    return len(token) in _HEX_ID_WIDTHS and all(
        c in "0123456789abcdef" for c in token
    )


def _payload_for(
    ctx: SpanInContext, kind: NodeKind, degradations: list[Degradation],
    subject: str,
) -> tuple[Payload, bool, str | None]:
    """Returns (payload, degraded, mined_id)."""
    attrs = ctx.span.attributes
    degraded = False
    mined_id: str | None = None
    if kind == NodeKind.TOOL_CALL:
        tool_name = attr_str(attrs, "gen_ai.tool.name") or ""
        raw_args = attr_str(attrs, "gen_ai.tool.call.arguments")
        args: dict[str, object] = {}
        if raw_args is None:
            degraded = True
            degradations.append(Degradation(
                reason=DegradationReason.MISSING_CONTENT, subject=subject))
        else:
            parsed, truncated = parse_json_object(raw_args)
            if parsed is None:
                degraded = True
                degradations.append(Degradation(
                    reason=(DegradationReason.TRUNCATED_CONTENT if truncated
                            else DegradationReason.UNPARSEABLE_CONTENT),
                    subject=subject))
            else:
                args = parsed
                token = parsed.get("tool_call_id")
                # AMENDMENT 2: empty string never becomes a mined id.
                mined_id = token if isinstance(token, str) and token else None
        return ToolCallPayload(tool_name=tool_name, args=args), degraded, mined_id

    key_by_kind = {
        NodeKind.TOOL_RESULT: "gen_ai.tool.call.result",
        NodeKind.LLM_CALL: "gen_ai.output.messages",
        NodeKind.USER_INPUT: "gen_ai.input.messages",
    }
    raw = attr_str(attrs, key_by_kind[kind])
    if raw is None:
        degraded = True
        degradations.append(Degradation(
            reason=DegradationReason.MISSING_CONTENT, subject=subject))
        raw = ""
    if kind == NodeKind.TOOL_RESULT and raw.startswith("{"):
        parsed, _ = parse_json_object(raw)
        if parsed is not None:
            token = parsed.get("tool_call_id")
            # AMENDMENT 2: empty string never becomes a mined id.
            mined_id = token if isinstance(token, str) and token else None
    payload: Payload
    if kind == NodeKind.TOOL_RESULT:
        payload = ToolResultPayload(content=raw)
    elif kind == NodeKind.LLM_CALL:
        payload = LlmCallPayload(content=raw)
    else:
        payload = UserInputPayload(content=raw)
    return payload, degraded, mined_id


def map_wire(wire: WireInput) -> AdapterResult:
    degradations = list(wire.degradations)
    # single-row registry: row data already drives attr keys above, so the
    # profile itself is unused here (pinned by test_adapter_contract.py's
    # test_mapper_attribute_keys_come_from_the_profile).
    _profile, all_degraded = _select_profile(wire.spans, degradations)

    genai = [c for c in wire.spans if has_genai_marker(c.span.attributes)]
    filtered = len(wire.spans) - len(genai)
    if filtered:
        degradations.append(Degradation(
            reason=DegradationReason.NON_GENAI_SPANS_FILTERED,
            subject="resource", note=str(filtered)))

    # source_ref = raw wire token, case-normalized. Hex validity is
    # COMMENTARY; joins always match on the raw token (M4 design section 2).
    nonstandard = False
    prepared: list[tuple[str, SpanInContext]] = []
    for ctx in genai:
        token = ctx.span.span_id.strip().lower()
        if token and not _is_hex_id(token):
            nonstandard = True
        if not token:
            surrogate = "surrogate-" + _wire_span_digest(ctx.span)[:16]
            degradations.append(Degradation(
                reason=DegradationReason.MISSING_SPAN_ID, subject=surrogate))
            token = surrogate
        prepared.append((token, ctx))
    if nonstandard:
        degradations.append(Degradation(
            reason=DegradationReason.NONSTANDARD_ID_ENCODING, subject="resource"))

    # Duplicate ids: byte-identical -> dedupe; differing -> digest suffix.
    by_token: dict[str, list[tuple[str, SpanInContext]]] = {}
    for token, ctx in prepared:
        by_token.setdefault(token, []).append((token, ctx))
    deduped: list[tuple[str, SpanInContext]] = []
    ambiguous_tokens: set[str] = set()
    ambiguous_refs: set[str] = set()
    for token, group in sorted(by_token.items()):
        if len(group) == 1:
            deduped.append(group[0])
            continue
        digests = {_wire_span_digest(g[1].span): g for g in group}
        if len(digests) == 1:
            deduped.append(group[0])
            degradations.append(Degradation(
                reason=DegradationReason.DUPLICATE_SPAN_ID, subject=token,
                note="byte-identical duplicates deduplicated"))
            continue
        ambiguous_tokens.add(token)
        degradations.append(Degradation(
            reason=DegradationReason.DUPLICATE_SPAN_ID, subject=token,
            note="differing spans share an id; digest-suffixed"))
        for digest in sorted(digests):
            g_token, g_ctx = digests[digest]
            ref = f"{g_token}#{digest[:8]}"
            ambiguous_refs.add(ref)
            deduped.append((ref, g_ctx))

    # Order-independent node ordering: (start_nanos, source_ref token).
    def _sort_key(item: tuple[str, SpanInContext]):
        token, ctx = item
        iso = iso_from_nanos(ctx.span.start_time_unix_nano)
        return (iso is None, iso or "", token)

    ordered = sorted(deduped, key=_sort_key)

    known_tokens = {token for token, _ in ordered}
    nodes: list[TraceNode] = []
    mapped_spans: list[MappedSpan] = []
    framework_name: str | None = None
    framework_version: str | None = None
    # Evidence for remediation selection (not analysis): the first GenAI
    # span's scope name, verbatim, no prefix filter - any scope name is
    # recorded, unlike framework_version above which only reads scopes
    # already known to be an instrumentation scope.
    instrumentation_scope: str | None = None
    for token, ctx in ordered:
        kind = derive_kind(ctx.span)
        if kind is None:
            degradations.append(Degradation(
                reason=DegradationReason.UNMAPPABLE_GENAI_SPAN, subject=token))
            continue
        iso = iso_from_nanos(ctx.span.start_time_unix_nano)
        node_degraded = all_degraded
        if iso is None:
            degradations.append(Degradation(
                reason=DegradationReason.INVALID_TIMESTAMP, subject=token))
            iso = "1970-01-01T00:00:00Z"
            node_degraded = True
        payload, content_degraded, mined_id = _payload_for(
            ctx, kind, degradations, token)
        parent = ctx.span.parent_span_id.strip().lower()
        if parent and parent in ambiguous_tokens:
            degradations.append(Degradation(
                reason=DegradationReason.AMBIGUOUS_JOIN, subject=token,
                note=f"parent {parent} is a duplicated span id"))
            parent = ""
        elif parent and parent not in known_tokens:
            degradations.append(Degradation(
                reason=DegradationReason.ORPHANED_PARENT, subject=token,
                note=f"parent {parent} absent from export"))
            parent = ""
        provider = attr_str(ctx.span.attributes, "gen_ai.provider.name")
        if provider and framework_name is None:
            framework_name = provider
        if ctx.scope.name.startswith(_SCOPE_PREFIX) and framework_version is None:
            framework_version = ctx.scope.version or None
        if ctx.scope.name and instrumentation_scope is None:
            instrumentation_scope = ctx.scope.name
        nodes.append(TraceNode(
            id=f"n{len(nodes)}", kind=kind, timestamp=iso,
            actor=actor_for(kind), source_ref=token, payload=payload,
            degraded=node_degraded or content_degraded,
        ))
        mapped_spans.append(MappedSpan(
            source_ref=token, kind=kind,
            # AMENDMENT 1: empty string maps to None (semantically absent).
            call_id_attr=attr_str(ctx.span.attributes, "gen_ai.tool.call.id") or None,
            parent_token=parent, mined_id=mined_id,
        ))

    joins, join_degradations = build_joins(mapped_spans)
    degradations.extend(join_degradations)
    # Joins touching a digest-suffixed duplicated span id are ambiguous: a
    # pick between differing twins is a silent resolution of ambiguous
    # evidence, never allowed to stand. Never silent - the drop is ledgered.
    kept_joins: list[JoinRecord] = []
    for j in joins:
        touched = next(
            (ref for ref in (j.tool_call_source_ref, j.tool_result_source_ref)
             if ref in ambiguous_refs),
            None,
        )
        if touched is not None:
            degradations.append(Degradation(
                reason=DegradationReason.AMBIGUOUS_JOIN, subject=touched,
                note="join evidence touches a duplicated span id"))
            continue
        kept_joins.append(j)
    joins = kept_joins

    trace = CanonicalTrace(
        schema_version=SCHEMA_VERSION,
        nodes=nodes,
        joins=joins,
        metadata=TraceMetadata(
            adapter_name=ADAPTER_NAME, adapter_version=ADAPTER_VERSION,
            framework_name=framework_name, framework_version=framework_version,
            instrumentation_scope=instrumentation_scope,
        ),
    )
    # Canonical ledger order (amendment C applies to the commentary too):
    # wire- and map-stage entries are emitted in traversal order, which span
    # reordering would permute while the trace held. line:N subjects are
    # legitimately per-input facts; everything else must be re-export-stable.
    def _ledger_key(d: Degradation) -> tuple[str, str, str]:
        subject = d.subject
        if subject.startswith("line:"):
            suffix = subject.removeprefix("line:")
            if suffix.isdigit():
                subject = f"line:{int(suffix):09d}"
        return (d.reason, subject, d.note)

    degradations.sort(key=_ledger_key)
    return AdapterResult(trace=trace, degradations=degradations)
