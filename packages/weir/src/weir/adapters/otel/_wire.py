"""Stage 1: bytes -> wire structs. The ENTIRE reject side lives here, and it
is exactly two conditions (M4 design section 2): not JSON (document or
JSONL), or nothing OTLP-shaped anywhere in the input. Everything below that
is a degradation, produced here (line/span granularity) or in stage 2.
Log records (`resourceLogs`) are decoded for the exposure scan only; the
trace is built from spans alone.

Wire scalars are permissive by design: nano fields accept str|int, ids are
arbitrary strings (hex validity is stage-2 COMMENTARY, never a decode gate),
attribute values stay raw, and so do status/events - a span failing struct
decode is quarantined, never fatal. Both key spellings are accepted:
camelCase per OTLP/JSON spec, snake_case for vanilla-protojson exporters.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import cast

import msgspec

from weir.adapters.otel._contract import Degradation, DegradationReason

_BOM = b"\xef\xbb\xbf"

# snake_case -> camelCase for the structural keys weir reads. Attribute
# entry keys ("key"/"value") are identical in both variants; the AnyValue
# wrappers inside a value ("stringValue"/"string_value") are not renamed
# here, the exposure walk reads both spellings.
_KEY_ALIASES = {
    "resource_spans": "resourceSpans",
    "scope_spans": "scopeSpans",
    "resource_logs": "resourceLogs",
    "scope_logs": "scopeLogs",
    "log_records": "logRecords",
    "schema_url": "schemaUrl",
    "trace_id": "traceId",
    "span_id": "spanId",
    "parent_span_id": "parentSpanId",
    "start_time_unix_nano": "startTimeUnixNano",
    "end_time_unix_nano": "endTimeUnixNano",
}


class OtlpRejectError(Exception):
    """Exit-2 material: this input is not telemetry at all."""


class WireScope(msgspec.Struct, frozen=True):
    name: str = ""
    version: str = ""
    attributes: list[dict[str, object]] = []


class WireSpan(msgspec.Struct, frozen=True, rename="camel"):
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    name: str = ""
    kind: str | int = 0
    start_time_unix_nano: str | int = 0
    end_time_unix_nano: str | int = 0
    attributes: list[dict[str, object]] = []
    # Exposure-scan payloads only, never a decode gate: kept raw exactly like
    # `attributes` above, so no exporter shape can quarantine a span that
    # decoded before. The consumer guards element access, as stage 2 already
    # does for attributes.
    status: object = None
    events: object = None


class SpanInContext(msgspec.Struct, frozen=True):
    """A wire span plus the resource/scope context it arrived under."""

    span: WireSpan
    scope: WireScope
    schema_url: str
    resource_attributes: list[dict[str, object]]


class LogRecordInContext(msgspec.Struct, frozen=True):
    """A wire log record, kept raw (the exposure scan guards every access),
    plus the resource/scope context it arrived under."""

    record: dict[str, object]
    scope: WireScope
    resource_attributes: list[dict[str, object]]
    # 0-based position among every log record element in the input,
    # counting the ones that could not be read.
    position: int


class WireInput(msgspec.Struct, frozen=True):
    spans: list[SpanInContext]
    degradations: list[Degradation]
    log_records: list[LogRecordInContext] = []
    # Batches holding anything but a resourceSpans or resourceLogs list
    # (metrics, another signal, or nothing OTLP-shaped): the exposure scan
    # reports them as not scanned rather than clean.
    batches_not_scanned: int = 0
    # Resources, scopes, records and lists inside a logs batch whose shape
    # could not be read: counted toward the same not-scanned report.
    values_not_scanned: int = 0
    # False when no batch holds a resourceSpans list (a logs-only export):
    # there is no flow trace to measure, only the exposure scan.
    has_traces: bool = True


def _normalize_keys(value: object) -> object:
    """Bounded to the STRUCTURAL depth: never recurses into attribute
    values or a log record's body, so a user kvlist that happens to carry a
    `span_id` key is not silently renamed, and a hostile nesting depth in
    content never reaches this recursion."""
    if isinstance(value, dict):
        items = cast("dict[str, object]", value)
        return {
            _KEY_ALIASES.get(k, k): (v if k in ("attributes", "body") else _normalize_keys(v))
            for k, v in items.items()
        }
    if isinstance(value, list):
        return [_normalize_keys(v) for v in cast("list[object]", value)]
    return value


def _parse_lines(data: bytes) -> tuple[list[dict[str, object]], list[Degradation]]:
    """One JSON document, a top-level JSON array of batch objects, or JSONL
    (one batch per line). Raises OtlpRejectError only when NOTHING decodes
    as JSON. Encoding is STRICT first: invalid UTF-8 is a named degradation
    with its byte offset, never a silent U+FFFD - content bytes feed
    mined-id extraction and taint payloads, so a lossy decode cannot be
    silent in this system."""
    stripped = data.removeprefix(_BOM)
    degradations: list[Degradation] = []
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError as exc:
        degradations.append(
            Degradation(
                reason=DegradationReason.INVALID_ENCODING,
                subject="input",
                note=f"invalid UTF-8 at byte offset {exc.start}",
            )
        )
        text = stripped.decode("utf-8", errors="replace")
    try:
        document: object = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        return [cast("dict[str, object]", document)], degradations
    if isinstance(document, list):
        wrapped = [
            cast("dict[str, object]", d)
            for d in cast("list[object]", document)
            if isinstance(d, dict)
        ]
        if wrapped:
            return wrapped, degradations

    batches: list[dict[str, object]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed: object = json.loads(line)
        except json.JSONDecodeError as exc:
            degradations.append(
                Degradation(
                    reason=DegradationReason.UNDECODABLE_BATCH,
                    subject=f"line:{line_no}",
                    note=str(exc),
                )
            )
            continue
        if isinstance(parsed, dict):
            batches.append(cast("dict[str, object]", parsed))
    if not batches:
        raise OtlpRejectError(
            "input is not JSON: neither a JSON document nor JSON Lines"
        )
    return batches, degradations


_READ_SIGNALS = ("resourceSpans", "resourceLogs")


def _scoped(
    resources: list[object], scope_key: str, record_key: str, degradations: list[Degradation]
) -> Iterator[tuple[object, WireScope, str, list[dict[str, object]]] | None]:
    """Every raw record under one resource list, with its scope, schema URL
    and resource attributes. Spans and log records nest the same way. A
    None marks a resource, scope or list whose shape could not be read; the
    log path counts it as not scanned, the span path passes over it."""
    for rs in resources:
        if not isinstance(rs, dict):
            yield None
            continue
        rs = cast("dict[str, object]", rs)
        resource = rs.get("resource")
        resource_attrs: object = (
            cast("dict[str, object]", resource).get("attributes", [])
            if isinstance(resource, dict)
            else []
        )
        if not isinstance(resource, dict | None) or not isinstance(resource_attrs, list | None):
            yield None
        if not isinstance(resource_attrs, list):
            resource_attrs = []
        rs_schema_url = rs.get("schemaUrl", "")
        scoped = rs.get(scope_key, [])
        if not isinstance(scoped, list):
            yield None
            continue
        for ss in cast("list[object]", scoped):
            if not isinstance(ss, dict):
                yield None
                continue
            ss = cast("dict[str, object]", ss)
            try:
                scope = msgspec.convert(ss.get("scope", {}), type=WireScope)
            except msgspec.ValidationError as exc:
                degradations.append(
                    Degradation(
                        reason=DegradationReason.UNDECODABLE_SCOPE,
                        subject="scope",
                        note=str(exc),
                    )
                )
                scope = WireScope()
                yield None
            schema_url = ss.get("schemaUrl") or rs_schema_url
            if not isinstance(schema_url, str):
                schema_url = ""
            records = ss.get(record_key, [])
            if not isinstance(records, list):
                yield None
                continue
            for raw in cast("list[object]", records):
                # Element types are unverified by design: raw pass-through,
                # stage 2 and the exposure scan guard element access.
                yield raw, scope, schema_url, cast("list[dict[str, object]]", resource_attrs)


def decode_input(data: bytes) -> WireInput:
    batches, degradations = _parse_lines(data)
    spans: list[SpanInContext] = []
    log_records: list[LogRecordInContext] = []
    log_position = -1
    saw_otlp_shape = False
    has_traces = False
    non_trace_batches = 0
    batches_not_scanned = 0
    values_not_scanned = 0

    for batch in batches:
        normalized = cast("dict[str, object]", _normalize_keys(batch))
        resource_spans = normalized.get("resourceSpans")
        resource_logs = normalized.get("resourceLogs")
        if not isinstance(resource_spans, list):
            # Decoded fine but not a traces payload (logs/metrics in a
            # mixed export): counted, never silently skipped.
            non_trace_batches += 1
        if not normalized or any(
            key not in _READ_SIGNALS or not isinstance(value, list)
            for key, value in normalized.items()
        ):
            batches_not_scanned += 1
        if isinstance(resource_spans, list):
            saw_otlp_shape = has_traces = True
            for item in _scoped(
                cast("list[object]", resource_spans), "scopeSpans", "spans", degradations
            ):
                if item is None:
                    continue
                raw, scope, schema_url, resource_attrs = item
                try:
                    span = msgspec.convert(raw, type=WireSpan, strict=False)
                except msgspec.ValidationError as exc:
                    # G4: name the shape, never the bytes. A raw JSON
                    # slice here would put an exported credential into
                    # the ledger, the report, and CI logs.
                    keys = (
                        ",".join(sorted(cast("dict[str, object]", raw)))
                        if isinstance(raw, dict)
                        else type(raw).__name__
                    )
                    degradations.append(
                        Degradation(
                            reason=DegradationReason.UNDECODABLE_SPAN,
                            subject=f"span with keys: {keys}"[:120],
                            note=str(exc),
                        )
                    )
                    continue
                spans.append(
                    SpanInContext(
                        span=span,
                        scope=scope,
                        schema_url=schema_url,
                        resource_attributes=resource_attrs,
                    )
                )
        if isinstance(resource_logs, list):
            saw_otlp_shape = True
            for item in _scoped(
                cast("list[object]", resource_logs), "scopeLogs", "logRecords", degradations
            ):
                if item is None:
                    values_not_scanned += 1
                    continue
                raw, scope, _, resource_attrs = item
                log_position += 1
                if not isinstance(raw, dict):
                    values_not_scanned += 1
                    continue
                log_records.append(
                    LogRecordInContext(
                        record=cast("dict[str, object]", raw),
                        scope=scope,
                        resource_attributes=resource_attrs,
                        position=log_position,
                    )
                )

    if not saw_otlp_shape:
        raise OtlpRejectError(
            "input is JSON but not OTLP-shaped: no resourceSpans or resourceLogs "
            "list found in any document or line"
        )
    if non_trace_batches:
        degradations.append(
            Degradation(
                reason=DegradationReason.NON_TRACE_BATCHES_SKIPPED,
                subject="input",
                note=str(non_trace_batches),
            )
        )
    return WireInput(
        spans=spans,
        degradations=degradations,
        log_records=log_records,
        batches_not_scanned=batches_not_scanned,
        values_not_scanned=values_not_scanned,
        has_traces=has_traces,
    )
