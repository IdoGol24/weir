"""Stage 2: kind from real OTel signals only, actor from kind (the pinned
invariant), payloads with named degradations."""

from weir.adapters.otel._map import attr_str, derive_kind
from weir.adapters.otel._wire import WireSpan
from weir.schema.trace import NodeKind


def _span(kind: int, attrs: dict[str, str]) -> WireSpan:
    return WireSpan(
        trace_id="ab" * 16, span_id="cd" * 8, name="n", kind=kind,
        start_time_unix_nano="1", end_time_unix_nano="2",
        attributes=[{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    )


def test_kind_derivation_from_operation_and_span_kind() -> None:
    assert derive_kind(_span(3, {"gen_ai.operation.name": "chat"})) == NodeKind.LLM_CALL
    assert derive_kind(_span(1, {"gen_ai.operation.name": "chat"})) == NodeKind.USER_INPUT
    assert derive_kind(_span(3, {"gen_ai.operation.name": "execute_tool"})) == NodeKind.TOOL_CALL
    assert derive_kind(_span(1, {"gen_ai.operation.name": "execute_tool"})) == NodeKind.TOOL_RESULT


def test_kind_falls_back_to_tool_name_presence_without_operation() -> None:
    assert derive_kind(_span(3, {"gen_ai.tool.name": "search"})) == NodeKind.TOOL_CALL
    assert derive_kind(_span(1, {"gen_ai.tool.name": "search"})) == NodeKind.TOOL_RESULT


def test_unknown_operation_is_unmappable() -> None:
    assert derive_kind(_span(3, {"gen_ai.operation.name": "embeddings"})) is None


def test_kind_never_reads_weir_attributes() -> None:
    # weir.* is producer self-description: untrusted. A weir.kind "hint" must
    # not rescue an otherwise unmappable span.
    assert derive_kind(_span(3, {"weir.kind": "tool_call"})) is None


def test_attr_str_reads_string_values_only() -> None:
    span = _span(3, {"gen_ai.operation.name": "chat"})
    assert attr_str(span.attributes, "gen_ai.operation.name") == "chat"
    assert attr_str(span.attributes, "absent") is None
