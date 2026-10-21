"""The OTLP/HTTP receiver: request bodies in, OTLP/JSON capture lines out.

A body arrives as protobuf or JSON, possibly compressed. The receiver writes
it decompressed, one export request per line, in the protobuf JSON mapping
with trace and span ids as lowercase hex, the OTLP/JSON convention
(docs/canary.md, "The capture"). Request headers never enter the capture.

A body the receiver cannot decode is not dropped: it is written as its own
swept file, so the judge still sweeps its bytes, and a marker line that
holds none of the three OTLP fields goes into the signal's telemetry file,
so the judge counts an unparsed record and the run is incomplete rather
than quietly clean.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, cast

from google.protobuf import json_format
from google.protobuf.message import DecodeError, Message
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
    ExportMetricsServiceResponse,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from weir_run.capture import Capture

PATHS = {"/v1/traces": "traces", "/v1/logs": "logs", "/v1/metrics": "metrics"}
TOP_FIELD = {"traces": "resourceSpans", "logs": "resourceLogs", "metrics": "resourceMetrics"}

_REQUESTS: dict[str, type[Message]] = {
    "traces": ExportTraceServiceRequest,
    "logs": ExportLogsServiceRequest,
    "metrics": ExportMetricsServiceRequest,
}
_RESPONSES: dict[str, type[Message]] = {
    "traces": ExportTraceServiceResponse,
    "logs": ExportLogsServiceResponse,
    "metrics": ExportMetricsServiceResponse,
}
_ID_FIELDS = frozenset({"traceId", "spanId", "parentSpanId"})


def _hex_ids(node: object) -> None:
    """Rewrite protobuf-JSON base64 ids to OTLP/JSON lowercase hex, in place.

    Only message field names are dict keys in this mapping (attribute keys
    live in `{"key": ..., "value": ...}` lists), so an attribute can never be
    mistaken for an id field.
    """
    if isinstance(node, dict):
        mapping = cast(dict[str, Any], node)
        for key, value in mapping.items():
            if key in _ID_FIELDS and isinstance(value, str):
                mapping[key] = base64.b64decode(value).hex()
            else:
                _hex_ids(value)
    elif isinstance(node, list):
        for item in cast(list[Any], node):
            _hex_ids(item)


def to_json_line(signal: str, body: bytes, content_type: str) -> bytes:
    """One OTLP/JSON line for a decompressed body. Raises ValueError when the
    body is not an export request of this signal in the declared encoding."""
    if content_type.split(";")[0].strip().lower() == "application/json":
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("not JSON") from None
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
    else:
        message = _REQUESTS[signal]()
        try:
            message.ParseFromString(body)
            doc = json_format.MessageToDict(
                message, preserving_proto_field_name=False, use_integers_for_enums=True
            )
            _hex_ids(doc)
        except (DecodeError, binascii.Error):
            raise ValueError("not an OTLP protobuf export request") from None
        # An empty export still names its signal, so it parses as a request
        # with no records instead of counting as an unparsed line.
        doc.setdefault(TOP_FIELD[signal], [])
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def receive(
    capture: Capture, signal: str, body: bytes | None, raw: bytes, content_type: str
) -> tuple[int, bytes, str]:
    """Write one request to the capture; return the HTTP reply.

    body is the decompressed body, or None when it could not be
    decompressed; raw is the body as received.
    """
    json_reply = content_type.split(";")[0].strip().lower() == "application/json"
    line: bytes | None = None
    if body is not None:
        try:
            line = to_json_line(signal, body, content_type)
        except ValueError:
            line = None
    if line is None:
        name = capture.swept_file(f"otlp-{signal}-undecodable", raw if body is None else body)
        capture.otlp_line(signal, json.dumps({"undecodable": name}).encode())
        return 400, b'{"code":3,"message":"undecodable export request"}', "application/json"
    capture.otlp_line(signal, line)
    if json_reply:
        return 200, b"{}", "application/json"
    return 200, _RESPONSES[signal]().SerializeToString(), "application/x-protobuf"
