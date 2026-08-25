"""The native renderer maps the plan's dial fields into its own dialect."""

from weir.schema.trace import ToolCallPayload
from weir_tracegen.emitter import emit_scenario, step_source_ref
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.dials import with_clock_skew, without_content


def _plan():
    return instantiate("injection-exfil", seed=1)


def test_content_off_renders_degraded_tool_calls_with_empty_args() -> None:
    trace = emit_scenario(without_content(_plan()))
    tool_calls = [n for n in trace.nodes if isinstance(n.payload, ToolCallPayload)]
    assert tool_calls
    for node in tool_calls:
        assert node.payload.args == {}
        assert node.degraded is True


def test_content_off_blanks_textual_content() -> None:
    trace = emit_scenario(without_content(_plan()))
    for node in trace.nodes:
        content = getattr(node.payload, "content", None)
        if content is not None:
            assert content == ""


def test_clock_skew_shifts_only_that_node() -> None:
    baseline = emit_scenario(_plan())
    skewed = emit_scenario(with_clock_skew(_plan(), step_index=3, offset_ns=2_000_000_000))
    assert skewed.nodes[3].timestamp != baseline.nodes[3].timestamp
    assert skewed.nodes[0].timestamp == baseline.nodes[0].timestamp
    assert skewed.nodes[4].timestamp == baseline.nodes[4].timestamp


def test_undialed_output_is_unchanged() -> None:
    trace = emit_scenario(_plan())
    assert trace.nodes[0].timestamp == "2026-01-01T00:00:00Z"
    assert not any(node.degraded for node in trace.nodes)


def test_step_source_ref_is_the_one_identity_helper() -> None:
    # Both renderers derive step identity from this function, so the two
    # outputs cannot drift into two conventions that happen to agree.
    assert step_source_ref("injection-exfil", 2) == "native-injection-exfil-2"
