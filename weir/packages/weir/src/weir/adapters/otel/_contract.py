"""The reject-vs-degrade contract in executable form (M4 design section 2).

Exit-2 rejects are exactly two conditions and live in _wire.OtlpRejectError.
EVERYTHING else is a named row here. The corrupt corpus derives its expected
verdicts from these rows; the capability ladder prints the remediation
strings. A malformation without a row is a bug in this contract, never a
judgment call in the mapper - add the row WITH its corpus item.
"""

from __future__ import annotations

import enum

import msgspec


class DegradationReason(enum.StrEnum):
    INVALID_ENCODING = "invalid_encoding"
    UNDECODABLE_BATCH = "undecodable_batch"
    NON_TRACE_BATCHES_SKIPPED = "non_trace_batches_skipped"
    UNDECODABLE_SPAN = "undecodable_span"
    UNDECODABLE_SCOPE = "undecodable_scope"
    ORPHANED_PARENT = "orphaned_parent"
    DUPLICATE_SPAN_ID = "duplicate_span_id"
    MISSING_SPAN_ID = "missing_span_id"
    NONSTANDARD_ID_ENCODING = "nonstandard_id_encoding"
    UNMAPPABLE_GENAI_SPAN = "unmappable_genai_span"
    NON_GENAI_SPANS_FILTERED = "non_genai_spans_filtered"
    MISSING_CONTENT = "missing_content"
    UNPARSEABLE_CONTENT = "unparseable_content"
    TRUNCATED_CONTENT = "truncated_content"
    INVALID_TIMESTAMP = "invalid_timestamp"
    AMBIGUOUS_JOIN = "ambiguous_join"
    CONFLICTING_JOIN_EVIDENCE = "conflicting_join_evidence"
    UNKNOWN_DIALECT = "unknown_dialect"


REMEDIATION: dict[DegradationReason, str] = {
    DegradationReason.INVALID_ENCODING: (
        "the input is not valid UTF-8; invalid bytes were replaced with "
        "U+FFFD, which can silently alter content-mined join evidence and "
        "taint payloads - fix the exporter's encoding"
    ),
    DegradationReason.NON_TRACE_BATCHES_SKIPPED: (
        "lines that decoded but carry no resourceSpans list (logs/metrics "
        "in a mixed export, or a malformed traces batch) were skipped; "
        "export traces to their own well-formed file"
    ),
    DegradationReason.UNDECODABLE_BATCH: (
        "one or more JSONL lines could not be decoded; re-export the batch or "
        "check the exporter's file rotation for mid-write truncation"
    ),
    DegradationReason.UNDECODABLE_SPAN: (
        "a span failed structural decode and was quarantined; check the "
        "exporter for schema-violating span serialization"
    ),
    DegradationReason.UNDECODABLE_SCOPE: (
        "an instrumentation scope failed structural decode and was dropped; "
        "framework identity for its spans is lost - check the exporter's "
        "scope serialization"
    ),
    DegradationReason.ORPHANED_PARENT: (
        "a span references a parent absent from this export; include the full "
        "trace in one export (or concatenate the batches into one JSONL file)"
    ),
    DegradationReason.DUPLICATE_SPAN_ID: (
        "two spans share a span id; check the instrumentation's id generator "
        "or de-duplicate the export"
    ),
    DegradationReason.MISSING_SPAN_ID: (
        "a span carries no id; upgrade the exporter - joins to this span "
        "cannot be trusted"
    ),
    DegradationReason.NONSTANDARD_ID_ENCODING: (
        "span ids are not OTLP/JSON lowercase hex (base64 protojson output is "
        "the usual cause); linkage is unaffected, but spec-true hex ids are "
        "recommended"
    ),
    DegradationReason.UNMAPPABLE_GENAI_SPAN: (
        "a GenAI span's operation could not be derived; set "
        "gen_ai.operation.name on every GenAI span"
    ),
    DegradationReason.NON_GENAI_SPANS_FILTERED: (
        "non-GenAI spans (http/db/plumbing) were filtered from analysis; this "
        "is normal and not a defect"
    ),
    DegradationReason.MISSING_CONTENT: (
        "content capture is off; for OTel GenAI instrumentations built on the "
        "util-genai layer, set "
        "OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental and "
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY to capture "
        "gen_ai.input.messages / gen_ai.output.messages / "
        "gen_ai.tool.call.arguments and unlock cross-step analysis"
    ),
    DegradationReason.UNPARSEABLE_CONTENT: (
        "a content attribute was present but not parseable; check the "
        "instrumentation's payload serialization"
    ),
    DegradationReason.TRUNCATED_CONTENT: (
        "a content attribute appears truncated (payload limit hit); raise the "
        "exporter's attribute length limit"
    ),
    DegradationReason.INVALID_TIMESTAMP: (
        "a span timestamp was unparseable; ordering fell back to span id - "
        "fix the exporter's clock fields"
    ),
    DegradationReason.AMBIGUOUS_JOIN: (
        "join evidence matched multiple candidate spans, so no join was "
        "recorded; ensure tool call ids are unique per trace"
    ),
    DegradationReason.CONFLICTING_JOIN_EVIDENCE: (
        "two join sources disagreed and precedence resolved it; this is the "
        "fingerprint of malformed instrumentation or attempted linkage "
        "forgery - inspect the named spans"
    ),
    DegradationReason.UNKNOWN_DIALECT: (
        "the trace matched no registered dialect; it was mapped under the "
        "default profile with every node degraded - tell us which "
        "instrumentation produced it at "
        "https://github.com/IdoGol24/weir/issues"
    ),
}


TRIGGER: dict[DegradationReason, str] = {
    DegradationReason.INVALID_ENCODING: (
        "input bytes are not valid UTF-8"
    ),
    DegradationReason.UNDECODABLE_BATCH: (
        "a JSONL line failed to parse as JSON"
    ),
    DegradationReason.NON_TRACE_BATCHES_SKIPPED: (
        "a batch decoded fine but carries no resourceSpans list"
    ),
    DegradationReason.UNDECODABLE_SPAN: (
        "a span object failed structural decode against the wire schema"
    ),
    DegradationReason.UNDECODABLE_SCOPE: (
        "an instrumentation scope object failed structural decode"
    ),
    DegradationReason.ORPHANED_PARENT: (
        "a span's parentSpanId names no span present in this export"
    ),
    DegradationReason.DUPLICATE_SPAN_ID: (
        "two or more spans carry the same span id"
    ),
    DegradationReason.MISSING_SPAN_ID: (
        "a span's spanId is empty"
    ),
    DegradationReason.NONSTANDARD_ID_ENCODING: (
        "a span id is not OTLP/JSON lowercase hex"
    ),
    DegradationReason.UNMAPPABLE_GENAI_SPAN: (
        "gen_ai.operation.name is absent and no gen_ai.tool.name marker is "
        "present either"
    ),
    DegradationReason.NON_GENAI_SPANS_FILTERED: (
        "a span carries no gen_ai.* attribute"
    ),
    DegradationReason.MISSING_CONTENT: (
        "the content attribute for this node's kind is absent"
    ),
    DegradationReason.UNPARSEABLE_CONTENT: (
        "a content attribute is present but its JSON does not parse, and "
        "the failure does not fingerprint as truncation"
    ),
    DegradationReason.TRUNCATED_CONTENT: (
        "a content attribute's JSON cuts off at end-of-input or inside an "
        "unterminated string"
    ),
    DegradationReason.INVALID_TIMESTAMP: (
        "startTimeUnixNano is missing, non-numeric, or negative"
    ),
    DegradationReason.AMBIGUOUS_JOIN: (
        "join evidence (explicit id, nesting, or a mined id) matches more "
        "than one candidate, or a duplicated id is shared"
    ),
    DegradationReason.CONFLICTING_JOIN_EVIDENCE: (
        "an envelope join (explicit or nested) already exists for a call, "
        "and mined content evidence points to a different result"
    ),
    DegradationReason.UNKNOWN_DIALECT: (
        "no schemaUrl or attribute fingerprint matches a registered dialect"
    ),
}


DISPOSITION: dict[DegradationReason, str] = {
    DegradationReason.INVALID_ENCODING: (
        "decoding continues with U+FFFD in place of the invalid bytes; no "
        "node is marked degraded, but content-derived joins and taint can "
        "be silently wrong"
    ),
    DegradationReason.UNDECODABLE_BATCH: (
        "the line is skipped; decoding continues with the remaining lines"
    ),
    DegradationReason.NON_TRACE_BATCHES_SKIPPED: (
        "the batch is skipped entirely; its spans never enter the trace"
    ),
    DegradationReason.UNDECODABLE_SPAN: (
        "the span is discarded; it never becomes a node - absent from the "
        "trace"
    ),
    DegradationReason.UNDECODABLE_SCOPE: (
        "the scope is replaced with an empty scope; its spans are still "
        "mapped but lose framework identity"
    ),
    DegradationReason.ORPHANED_PARENT: (
        "the parent link is cleared; the node is kept but appears "
        "unlinked, not marked degraded by this alone"
    ),
    DegradationReason.DUPLICATE_SPAN_ID: (
        "byte-identical duplicates collapse to one node; differing "
        "duplicates keep a digest-suffixed id and any join touching them "
        "is dropped"
    ),
    DegradationReason.MISSING_SPAN_ID: (
        "a digest-derived surrogate id is assigned so the node can still "
        "be created and joined"
    ),
    DegradationReason.NONSTANDARD_ID_ENCODING: (
        "processing continues unaffected; linkage still matches on the "
        "raw token"
    ),
    DegradationReason.UNMAPPABLE_GENAI_SPAN: (
        "the span is dropped; it never becomes a node - absent from the "
        "trace"
    ),
    DegradationReason.NON_GENAI_SPANS_FILTERED: (
        "the span is filtered before mapping and never becomes a node - "
        "expected, not a defect"
    ),
    DegradationReason.MISSING_CONTENT: (
        "the node is created with empty payload content and marked "
        "degraded -> excluded from verdict-eligible coverage"
    ),
    DegradationReason.UNPARSEABLE_CONTENT: (
        "the node is created with empty payload content and marked "
        "degraded -> excluded from verdict-eligible coverage"
    ),
    DegradationReason.TRUNCATED_CONTENT: (
        "the node is created with the truncated payload and marked "
        "degraded -> excluded from verdict-eligible coverage"
    ),
    DegradationReason.INVALID_TIMESTAMP: (
        "the node gets a synthetic epoch timestamp, ordering falls back "
        "to span id, and it is marked degraded -> excluded from "
        "verdict-eligible coverage"
    ),
    DegradationReason.AMBIGUOUS_JOIN: (
        "no join is recorded for the affected call; without an eligible "
        "join confidence it is excluded from verdict-eligible coverage"
    ),
    DegradationReason.CONFLICTING_JOIN_EVIDENCE: (
        "the envelope join is kept per precedence; the disagreement is "
        "only recorded, coverage for that call is unaffected"
    ),
    DegradationReason.UNKNOWN_DIALECT: (
        "mapping proceeds under the default profile but every resulting "
        "node is marked degraded -> excluded from verdict-eligible "
        "coverage"
    ),
}


def render_contract_doc() -> str:
    """The reject-vs-degrade contract as markdown, generated from the enum
    so the committed doc (docs/contract.md) cannot drift from the code."""
    lines = [
        "# The reject-vs-degrade contract",
        "",
        "Exit-2 rejects are exactly two conditions: the input is not JSON at "
        "all (neither a JSON document nor JSON Lines), or the input is JSON "
        "but not OTLP-shaped (no `resourceSpans` list found anywhere). "
        "Everything else degrades, named by one of the rows below.",
        "",
        "| reason | trigger | what weir does | remediation |",
        "| --- | --- | --- | --- |",
    ]
    for reason in DegradationReason:
        trigger = TRIGGER[reason].replace("|", "\\|")
        disposition = DISPOSITION[reason].replace("|", "\\|")
        remediation = REMEDIATION[reason].replace("|", "\\|")
        lines.append(
            f"| {reason.value} | {trigger} | {disposition} | {remediation} |"
        )
    return "\n".join(lines) + "\n"


class Degradation(msgspec.Struct, frozen=True):
    """One ledger entry. `subject` names what it applies to: a span id wire
    token, `resource`, or `line:<n>` for JSONL batches. NOT part of
    CanonicalTrace - the ledger is adapter commentary about one ingestion."""

    reason: DegradationReason
    subject: str
    note: str = ""
