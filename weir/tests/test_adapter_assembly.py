"""End-to-end adapter assembly over the M3 corpus renderer."""

import json

from weir.adapters.otel import AdapterResult, adapt_otlp
from weir.adapters.otel._contract import DegradationReason
from weir.schema.trace import JoinConfidence
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset


def _render(preset: str = "full") -> bytes:
    plan = apply_preset(instantiate("injection-exfil", seed=1), preset)
    return json.dumps(render_otlp(plan, preset=preset)).encode()


def test_full_preset_maps_cleanly() -> None:
    result = adapt_otlp(_render())
    assert isinstance(result, AdapterResult)
    trace = result.trace
    assert trace.schema_version == "1.1.0"
    assert trace.metadata.adapter_name == "otel"
    assert trace.metadata.framework_name == "langchain"
    assert trace.metadata.framework_version == "0.3"
    assert all(j.join_confidence == JoinConfidence.EXPLICIT for j in trace.joins)
    assert not any(
        d.reason != DegradationReason.NON_GENAI_SPANS_FILTERED
        for d in result.degradations
    )


def test_partial_preset_joins_are_all_nested() -> None:
    trace = adapt_otlp(_render("partial")).trace
    assert trace.joins and all(
        j.join_confidence == JoinConfidence.NESTED for j in trace.joins
    )


def test_default_realistic_nodes_degraded_with_missing_content() -> None:
    result = adapt_otlp(_render("default-realistic"))
    assert any(n.degraded for n in result.trace.nodes)
    assert any(
        d.reason == DegradationReason.MISSING_CONTENT for d in result.degradations
    )


def test_span_array_order_does_not_matter() -> None:
    doc = json.loads(_render())
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    doc["resourceSpans"][0]["scopeSpans"][0]["spans"] = list(reversed(spans))
    a = adapt_otlp(json.dumps(doc).encode())
    b = adapt_otlp(_render())
    assert a.trace == b.trace
    # Amendment C applies to the commentary too: the ledger is
    # canonically ordered, so reordering may not permute it.
    assert a.degradations == b.degradations


def test_source_ref_is_the_raw_span_id_token() -> None:
    doc = json.loads(_render())
    first_span_id = doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"]
    trace = adapt_otlp(_render()).trace
    assert first_span_id in {n.source_ref for n in trace.nodes}


def test_empty_string_wire_ids_do_not_join() -> None:
    # Semantically absent ids must not create join evidence end to end.
    doc = json.loads(_render("partial"))
    for span in doc["resourceSpans"][0]["scopeSpans"][0]["spans"]:
        span.pop("parentSpanId", None)
        span["attributes"].append(
            {"key": "gen_ai.tool.call.id", "value": {"stringValue": ""}}
        )
    result = adapt_otlp(json.dumps(doc).encode())
    assert result.trace.joins == []
    assert not any(
        d.reason == DegradationReason.AMBIGUOUS_JOIN for d in result.degradations
    )
