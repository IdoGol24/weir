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
