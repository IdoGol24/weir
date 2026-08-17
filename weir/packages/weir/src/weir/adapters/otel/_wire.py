"""Stage 1: bytes -> wire structs. The ENTIRE reject side lives here, and it
is exactly two conditions (M4 design section 2): not JSON (document or
JSONL), or nothing OTLP-shaped anywhere in the input. Everything below that
is a degradation, produced here (line/span granularity) or in stage 2.

Wire scalars are permissive by design: nano fields accept str|int, ids are
arbitrary strings (hex validity is stage-2 COMMENTARY, never a decode gate),
attribute values stay raw. A span failing struct decode is quarantined,
never fatal. Both key spellings are accepted: camelCase per OTLP/JSON spec,
snake_case for vanilla-protojson exporters.
"""

from __future__ import annotations

import json
from typing import cast

import msgspec

from weir.adapters.otel._contract import Degradation, DegradationReason

_BOM = b"\xef\xbb\xbf"

# snake_case -> camelCase for the structural keys weir reads. Attribute
# entry keys ("key"/"value"/"stringValue") are identical in both variants.
_KEY_ALIASES = {
    "resource_spans": "resourceSpans",
    "scope_spans": "scopeSpans",
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


class WireSpan(msgspec.Struct, frozen=True, rename="camel"):
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    name: str = ""
    kind: int = 0
    start_time_unix_nano: str | int = 0
    end_time_unix_nano: str | int = 0
    attributes: list[dict[str, object]] = []


class SpanInContext(msgspec.Struct, frozen=True):
    """A wire span plus the resource/scope context it arrived under."""

    span: WireSpan
    scope: WireScope
    schema_url: str
    resource_attributes: list[dict[str, object]]


class WireInput(msgspec.Struct, frozen=True):
    spans: list[SpanInContext]
    degradations: list[Degradation]


def _normalize_keys(value: object) -> object:
    """Bounded to the STRUCTURAL depth: never recurses into attribute
    values, so a user kvlist that happens to carry a `span_id` key is not
    silently renamed."""
    if isinstance(value, dict):
        items = cast("dict[str, object]", value)
        return {
            _KEY_ALIASES.get(k, k): (v if k == "attributes" else _normalize_keys(v))
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


def decode_input(data: bytes) -> WireInput:
    batches, degradations = _parse_lines(data)
    spans: list[SpanInContext] = []
    saw_otlp_shape = False
    non_trace_batches = 0

    for batch in batches:
        normalized = cast("dict[str, object]", _normalize_keys(batch))
        resource_spans = normalized.get("resourceSpans")
        if not isinstance(resource_spans, list):
            # Decoded fine but not a traces payload (logs/metrics in a
            # mixed export): counted, never silently skipped.
            non_trace_batches += 1
            continue
        saw_otlp_shape = True
        for rs in cast("list[object]", resource_spans):
            if not isinstance(rs, dict):
                continue
            rs_dict = cast("dict[str, object]", rs)
            resource = rs_dict.get("resource")
            resource_attrs: object = (
                cast("dict[str, object]", resource).get("attributes", [])
                if isinstance(resource, dict)
                else []
            )
            if not isinstance(resource_attrs, list):
                resource_attrs = []
            rs_schema_url = rs_dict.get("schemaUrl", "")
            scope_spans = rs_dict.get("scopeSpans", [])
            if not isinstance(scope_spans, list):
                continue
            for ss in cast("list[object]", scope_spans):
                if not isinstance(ss, dict):
                    continue
                ss_dict = cast("dict[str, object]", ss)
                try:
                    scope = msgspec.convert(ss_dict.get("scope", {}), type=WireScope)
                except msgspec.ValidationError:
                    scope = WireScope()
                schema_url = ss_dict.get("schemaUrl") or rs_schema_url
                if not isinstance(schema_url, str):
                    schema_url = ""
                raw_spans = ss_dict.get("spans", [])
                if not isinstance(raw_spans, list):
                    continue
                for raw in cast("list[object]", raw_spans):
                    try:
                        span = msgspec.convert(raw, type=WireSpan, strict=False)
                    except msgspec.ValidationError as exc:
                        degradations.append(
                            Degradation(
                                reason=DegradationReason.UNDECODABLE_SPAN,
                                subject=str(raw)[:80],
                                note=str(exc),
                            )
                        )
                        continue
                    spans.append(
                        SpanInContext(
                            span=span,
                            scope=scope,
                            schema_url=schema_url,
                            resource_attributes=cast(
                                "list[dict[str, object]]", resource_attrs
                            ),
                        )
                    )

    if not saw_otlp_shape:
        raise OtlpRejectError(
            "input is JSON but not OTLP-shaped: no resourceSpans list found in "
            "any document or line"
        )
    if non_trace_batches:
        degradations.append(
            Degradation(
                reason=DegradationReason.NON_TRACE_BATCHES_SKIPPED,
                subject="input",
                note=str(non_trace_batches),
            )
        )
    return WireInput(spans=spans, degradations=degradations)
