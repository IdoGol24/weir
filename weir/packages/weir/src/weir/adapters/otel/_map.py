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

from weir.adapters.otel._wire import WireSpan
from weir.schema.trace import NodeKind

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
