"""Attribute-driven execute_tool split (spec 2026-08-30). Real instrumentation
emits ONE execute_tool span carrying both arguments and result; weir must derive
a tool_call (args) and tool_result (result) node from it, so the sink's arguments
reach the taint matcher."""

from weir.adapters.otel._map import map_wire
from weir.adapters.otel._wire import SpanInContext, WireInput, WireScope, WireSpan
from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.rules_commons import load_rules
from weir.schema.trace import NodeKind
from weir.taint import build_tainted_graph

_PLANTED_IBAN = "DE89370400440532013000"


def _span(span_id: str, kind: int, attrs: dict[str, str], *, start: str = "1",
          end: str = "2", parent: str = "") -> WireSpan:
    return WireSpan(
        trace_id="ab" * 16, span_id=span_id, parent_span_id=parent, name="s",
        kind=kind, start_time_unix_nano=start, end_time_unix_nano=end,
        attributes=[{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    )


def _wire(*spans: WireSpan) -> WireInput:
    return WireInput(
        spans=[
            SpanInContext(
                span=s,
                scope=WireScope(name="opentelemetry.instrumentation.langchain", version="0.1"),
                schema_url="",
                resource_attributes=[],
            )
            for s in spans
        ],
        degradations=[],
    )


def _findings(wire: WireInput):
    trace = map_wire(wire).trace
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    return evaluate(tainted, load_rules()).findings


def _single_span_injection() -> WireInput:
    # A source tool_result carrying the planted IBAN, then a single INTERNAL
    # send_email execute_tool span whose ARGUMENTS carry the same IBAN.
    source = _span(
        "11" * 8, 1,
        {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "fetch_tickets",
         "gen_ai.tool.call.id": "call_src",
         "gen_ai.tool.call.result": f"Settlement account: {_PLANTED_IBAN}"},
        start="10", end="20",
    )
    sink = _span(
        "22" * 8, 1,
        {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "send_email",
         "gen_ai.tool.call.id": "call_sink",
         "gen_ai.tool.call.arguments": f'{{"to": "x@y.example", "body": "{_PLANTED_IBAN}"}}',
         "gen_ai.tool.call.result": "queued"},
        start="30", end="40",
    )
    return _wire(source, sink)


def test_single_span_injection_produces_one_verdict_grade_finding() -> None:
    (finding,) = _findings(_single_span_injection())
    assert finding.rule_id == "injection-exfil-to-outbound-sink"
    assert finding.matched_value == _PLANTED_IBAN
    assert finding.is_verdict_grade is True


def _nodes(*spans: WireSpan):
    trace = map_wire(_wire(*spans)).trace
    return [(n.kind, n.source_ref) for n in trace.nodes], trace.joins


def test_both_attrs_internal_split_into_call_and_result() -> None:
    nodes, joins = _nodes(_span("aa" * 8, 1, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.id": "c1",
        "gen_ai.tool.call.arguments": '{"q": "x"}', "gen_ai.tool.call.result": "y"}))
    assert nodes == [(NodeKind.TOOL_CALL, "aa" * 8), (NodeKind.TOOL_RESULT, "aa" * 8 + "#result")]
    assert len(joins) == 1  # explicit, via shared gen_ai.tool.call.id


def test_both_attrs_client_also_splits() -> None:
    nodes, _ = _nodes(_span("bb" * 8, 3, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.id": "c2",
        "gen_ai.tool.call.arguments": '{"q": "x"}', "gen_ai.tool.call.result": "y"}))
    assert [k for k, _ in nodes] == [NodeKind.TOOL_CALL, NodeKind.TOOL_RESULT]


def test_args_only_internal_is_a_tool_call() -> None:
    # The failed-call shape: today a degraded TOOL_RESULT reading absent result.
    nodes, _ = _nodes(_span("cc" * 8, 1, {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.call.arguments": '{"q": "x"}'}))
    assert nodes == [(NodeKind.TOOL_CALL, "cc" * 8)]


def test_args_only_client_is_a_tool_call() -> None:
    nodes, _ = _nodes(_span("dd" * 8, 3, {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.call.arguments": '{"q": "x"}'}))
    assert nodes == [(NodeKind.TOOL_CALL, "dd" * 8)]


def test_result_only_internal_is_a_tool_result() -> None:
    nodes, _ = _nodes(_span("ee" * 8, 1, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.result": "y"}))
    assert nodes == [(NodeKind.TOOL_RESULT, "ee" * 8)]


def test_result_only_client_is_a_tool_result() -> None:
    # Second divergent shape: today a degraded TOOL_CALL reading absent args.
    nodes, _ = _nodes(_span("ff" * 8, 3, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.result": "y"}))
    assert nodes == [(NodeKind.TOOL_RESULT, "ff" * 8)]


def test_no_content_tool_span_keeps_kind_driven_single_node() -> None:
    internal, _ = _nodes(_span("1a" * 8, 1, {"gen_ai.operation.name": "execute_tool"}))
    client, _ = _nodes(_span("2b" * 8, 3, {"gen_ai.operation.name": "execute_tool"}))
    assert [k for k, _ in internal] == [NodeKind.TOOL_RESULT]
    assert [k for k, _ in client] == [NodeKind.TOOL_CALL]


def test_non_tool_span_is_unchanged() -> None:
    nodes, _ = _nodes(_span("3c" * 8, 3, {
        "gen_ai.operation.name": "chat", "gen_ai.output.messages": "hi"}))
    assert [k for k, _ in nodes] == [NodeKind.LLM_CALL]


def test_duplicated_span_id_with_both_attrs_suffixes_deterministically() -> None:
    # Two DIFFERING spans share an id -> digest-suffixed; the both-attrs one
    # still splits, and #result composes onto the digest suffix, call before result.
    a = _span("44" * 8, 1, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.id": "d1",
        "gen_ai.tool.call.arguments": '{"q": "a"}', "gen_ai.tool.call.result": "ra"})
    b = _span("44" * 8, 1, {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.id": "d2",
        "gen_ai.tool.call.result": "rb"})
    refs = [r for _, r in _nodes(a, b)[0]]
    split_refs = [r for r in refs if r.startswith("44" * 8)]
    # The dual-content span contributes <token>#<8hex> and <token>#<8hex>#result.
    # Which of the two differing spans is the dual-content one depends on digest
    # sort, so identify the call as the ref that has a #result sibling.
    call = next(r for r in split_refs if r + "#result" in split_refs)
    assert split_refs.index(call) < split_refs.index(call + "#result")
