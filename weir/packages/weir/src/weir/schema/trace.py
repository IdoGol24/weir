"""Seam-1 CanonicalTrace schema (msgspec frozen structs).

This is the one schema built in this demo slice; the full rule/catalog/report/
gauge schema layer (execution-plan L4/L5) is deferred (see
weir-demo-slice-L17-first.md, L3 notes) - later layers define their own
minimal inline structs as they're reached.
"""

from __future__ import annotations

import enum

import msgspec

SCHEMA_VERSION = "1.0.0"


class NodeKind(enum.StrEnum):
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    USER_INPUT = "user_input"


class JoinConfidence(enum.StrEnum):
    """Join precedence per R1.4: explicit id > parent/child nesting > heuristic."""

    EXPLICIT = "explicit"
    NESTED = "nested"
    HEURISTIC = "heuristic"


class _PayloadBase(msgspec.Struct, frozen=True, forbid_unknown_fields=True, tag_field="type"):
    pass


class ToolCallPayload(_PayloadBase, frozen=True, tag="tool_call"):
    tool_name: str
    # Opaque pass-through JSON - whatever the traced agent actually sent, not
    # a weir-authored numeric field, so §3.3's no-floats-at-seams rule doesn't
    # apply here. `object` accepts any decoded JSON value (dict/list/str/
    # int/float/bool/None); see json_schema_hook() for schema generation.
    args: dict[str, object]


class ToolResultPayload(_PayloadBase, frozen=True, tag="tool_result"):
    content: str


class LlmCallPayload(_PayloadBase, frozen=True, tag="llm_call"):
    content: str


class UserInputPayload(_PayloadBase, frozen=True, tag="user_input"):
    content: str


Payload = ToolCallPayload | ToolResultPayload | LlmCallPayload | UserInputPayload


class JoinRecord(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Ties a tool_call node to its tool_result node (R1.4). `join_confidence`
    is carried permanently - never discarded after joining - because it feeds
    the §7 verdict-grade decision downstream."""

    tool_call_source_ref: str
    tool_result_source_ref: str
    join_confidence: JoinConfidence


class TraceMetadata(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """R1.6: adapter + detected framework versions, so the Gauge can flag drift."""

    adapter_name: str
    adapter_version: str
    framework_name: str | None = None
    framework_version: str | None = None


class TraceNode(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: str
    kind: NodeKind
    timestamp: str
    actor: str
    # Native step identifier (span id / message id / event index) - R1.7. The
    # stable join key for anything produced outside weir over the same trace.
    source_ref: str
    payload: Payload
    # R1.3/G9: unmappable input becomes a degraded node, never a crash.
    degraded: bool = False


class CanonicalTrace(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema_version: str
    nodes: list[TraceNode]
    joins: list[JoinRecord]
    metadata: TraceMetadata


def decode_canonical_trace(data: bytes | str) -> CanonicalTrace:
    """Decode + validate a Seam-1 CanonicalTrace. Raises msgspec.ValidationError
    or msgspec.DecodeError with a precise field path/reason on rejection (G9)."""
    return msgspec.json.decode(data, type=CanonicalTrace, strict=True)


def encode_canonical_trace(trace: CanonicalTrace) -> bytes:
    return msgspec.json.encode(trace)


_ANY_JSON_VALUE_SCHEMA: dict[str, object] = {
    "type": ["null", "boolean", "integer", "number", "string", "array", "object"]
}


def _json_schema_hook(t: type) -> dict[str, object]:
    if t is object:
        return _ANY_JSON_VALUE_SCHEMA  # args is opaque pass-through JSON data
    raise TypeError(f"no JSON schema mapping registered for type {t!r}")


def canonical_trace_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for CanonicalTrace (G7 versioning)."""
    return msgspec.json.schema(CanonicalTrace, schema_hook=_json_schema_hook)
