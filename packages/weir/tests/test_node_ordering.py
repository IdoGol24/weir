"""Node ordering must be chronological by raw start nanos, not by the ISO
string. `iso_from_nanos` omits microseconds when they are zero, so a span at a
whole second renders "...:0NZ" and sorted AFTER a same-second fractional span
("...:0N.500000Z") because 'Z' > '.'. Node order drives next_edges, so an
inverted pair can corrupt reachability. The module's own comment already says
the order is "(start_nanos, source_ref token)"; this pins it.
"""

from __future__ import annotations

from weir.adapters.otel._map import map_wire
from weir.adapters.otel._wire import SpanInContext, WireInput, WireScope, WireSpan


def _chat(span_id: str, start_ns: int, end_ns: int) -> WireSpan:
    return WireSpan(
        trace_id="a" * 32, span_id=span_id, name="chat", kind=3,
        start_time_unix_nano=str(start_ns), end_time_unix_nano=str(end_ns),
        attributes=[
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.output.messages", "value": {"stringValue": span_id}},
        ],
    )


def _order(*spans: WireSpan) -> list[str]:
    wire = WireInput(
        spans=[
            SpanInContext(span=s, scope=WireScope(name="x"), schema_url="",
                          resource_attributes=[])
            for s in spans
        ],
        degradations=[],
    )
    return [n.payload.content for n in map_wire(wire).trace.nodes]


_A = "aaaaaaaaaaaaaaaa"  # start 2.0s exactly
_B = "bbbbbbbbbbbbbbbb"  # start 2.5s


def test_whole_second_span_sorts_before_same_second_fractional_span() -> None:
    a = _chat(_A, 2_000_000_000, 2_100_000_000)
    b = _chat(_B, 2_500_000_000, 2_600_000_000)
    assert _order(a, b) == [_A, _B]


def test_node_order_is_independent_of_input_order() -> None:
    a = _chat(_A, 2_000_000_000, 2_100_000_000)
    b = _chat(_B, 2_500_000_000, 2_600_000_000)
    assert _order(b, a) == [_A, _B]
