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
from weir.adapters.otel._wire import WireSpan
from weir.schema.trace import JoinConfidence, JoinRecord, NodeKind

_SPAN_KIND_CLIENT = 3

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
    client = span.kind == _SPAN_KIND_CLIENT
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
    """(parsed, truncation_fingerprint). The fingerprint: decode fails AND
    the error position is end-of-string - the shape a payload limit leaves.
    Anything else unparseable is UNPARSEABLE_CONTENT, not TRUNCATED_CONTENT."""
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, exc.pos >= len(text.rstrip())
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
