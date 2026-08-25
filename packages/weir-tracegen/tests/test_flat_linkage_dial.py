"""The flat-linkage dial: the only corpus that exercises CONTENT_MINED.

Plan transform like its siblings - both renderers render the dialed plan
blind. OTLP: no gen_ai.tool.call.id, no parent link; the id survives only
inside content. Native: JoinRecord at content_mined."""

from weir.schema.trace import JoinConfidence
from weir_tracegen.emitter import emit_scenario
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.dials import with_flat_linkage


def _spans(doc):
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"]


def _attr_keys(span):
    return {a["key"] for a in span["attributes"]}


def test_flat_linkage_native_rendering() -> None:
    plan = with_flat_linkage(instantiate("injection-exfil", seed=1))
    trace = emit_scenario(plan)
    assert trace.joins and all(
        j.join_confidence == JoinConfidence.CONTENT_MINED for j in trace.joins
    )
    # The mined token is in the plan content, so BOTH renderers carry it.
    call_index = trace.joins[0].tool_call_source_ref
    call_node = next(n for n in trace.nodes if n.source_ref == call_index)
    assert "tool_call_id" in call_node.payload.args


def test_flat_linkage_otlp_rendering_is_flat() -> None:
    plan = with_flat_linkage(instantiate("injection-exfil", seed=1))
    doc = render_otlp(plan, preset="full")
    for span in _spans(doc):
        assert "gen_ai.tool.call.id" not in _attr_keys(span)
        assert "parentSpanId" not in span
    # The id token appears only inside content-bearing attributes.
    args_blobs = [
        a["value"]["stringValue"]
        for span in _spans(doc) for a in span["attributes"]
        if a["key"] == "gen_ai.tool.call.arguments"
    ]
    assert any("tool_call_id" in blob for blob in args_blobs)
