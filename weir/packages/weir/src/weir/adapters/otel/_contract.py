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
        "content capture is off; enable gen_ai.input.messages / "
        "gen_ai.output.messages / gen_ai.tool.call.arguments capture to "
        "unlock cross-step analysis"
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
        "instrumentation produced it"
    ),
}


class Degradation(msgspec.Struct, frozen=True):
    """One ledger entry. `subject` names what it applies to: a span id wire
    token, `resource`, or `line:<n>` for JSONL batches. NOT part of
    CanonicalTrace - the ledger is adapter commentary about one ingestion."""

    reason: DegradationReason
    subject: str
    note: str = ""
