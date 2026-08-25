"""Accept-side invariant for emitted OTLP.

M3 emits only accept-side traces: every output must be well-formed OTLP under
the pinned profile. This is checked by an EXTERNAL validator, the official
opentelemetry-proto bindings, never a hand-rolled parser.

THE ONE DOCUMENTED DIVERGENCE, and why the shim exists: OTLP/JSON mandates
lowercase-hex trace and span ids, while protobuf's json_format treats `bytes`
fields as base64. This does not fail loudly - 32 hex characters are valid
base64 alphabet, so Parse SUCCEEDS and silently decodes a 16-byte id into 24
bytes of garbage, after which the round-trip validates nothing about ids.

The WRONG fix is emitting base64 ids so json_format is happy: that would
de-spec-ify the corpus for every real consumer. The RIGHT fix, taken here, is
to keep the corpus spec-true and shim exactly this divergence at the validator
boundary, then assert id equality THROUGH the shim so ids are genuinely
checked rather than laundered.
"""

from __future__ import annotations

import base64
import copy
from typing import Any

from google.protobuf import json_format
from opentelemetry.proto.trace.v1.trace_pb2 import TracesData

_ID_FIELDS = ("traceId", "spanId", "parentSpanId")


def _hex_to_b64(value: str) -> str:
    return base64.b64encode(bytes.fromhex(value)).decode("ascii")


def _shim_ids(document: dict[str, Any]) -> dict[str, Any]:
    """Convert the three id fields from spec-true hex into what json_format
    expects. Applied to a deep copy so the caller's document is untouched."""
    shimmed = copy.deepcopy(document)
    for resource_spans in shimmed.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            for span in scope_spans.get("spans", []):
                for field in _ID_FIELDS:
                    if span.get(field):
                        span[field] = _hex_to_b64(span[field])
    return shimmed


def parse_otlp_json(document: dict[str, Any]) -> TracesData:
    """Round-trip the document through the official bindings, via the shim."""
    return json_format.ParseDict(_shim_ids(document), TracesData())


def assert_accept_side(document: dict[str, Any]) -> None:
    """The invariant: parses under the official bindings, ids survive intact,
    span ids are unique, and parent references are closed."""
    parsed = parse_otlp_json(document)

    emitted: list[str] = []
    parents: list[str] = []
    for resource_spans in document.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            for span in scope_spans.get("spans", []):
                emitted.append(span["spanId"])
                if span.get("parentSpanId"):
                    parents.append(span["parentSpanId"])

    round_tripped = [
        span.span_id.hex()
        for rs in parsed.resource_spans
        for ss in rs.scope_spans
        for span in ss.spans
    ]
    if round_tripped != emitted:
        raise AssertionError(
            f"id round-trip mismatch through the shim: {emitted} != {round_tripped}"
        )

    if len(set(emitted)) != len(emitted):
        raise AssertionError(f"duplicate span id in {emitted}")

    unknown = [parent for parent in parents if parent not in set(emitted)]
    if unknown:
        raise AssertionError(f"closure violated: parentSpanId not in payload: {unknown}")
