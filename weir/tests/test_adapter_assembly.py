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
    assert trace.schema_version == "1.2.0"
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


def test_join_onto_duplicated_span_id_is_ambiguous_not_picked() -> None:
    # Two DIFFERING results share a span id; a call's explicit id matches one
    # of them. No join may form - a pick between digest-suffixed twins is a
    # silent resolution of ambiguous evidence.
    doc = json.loads(_render("partial"))
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    call = next(s for s in spans if any(
        a["key"] == "gen_ai.tool.call.arguments" for a in s["attributes"]))
    result = next(s for s in spans if any(
        a["key"] == "gen_ai.tool.call.result" for a in s["attributes"]))
    call["attributes"].append(
        {"key": "gen_ai.tool.call.id", "value": {"stringValue": "c9"}})
    result["attributes"].append(
        {"key": "gen_ai.tool.call.id", "value": {"stringValue": "c9"}})
    twin = json.loads(json.dumps(result))
    twin["name"] = twin["name"] + " TWIN"
    spans.append(twin)  # differing span sharing the result's spanId
    for s in spans:
        s.pop("parentSpanId", None)  # kill nesting so explicit is the only tier
    out = adapt_otlp(json.dumps(doc).encode())
    assert not any(
        j.tool_call_source_ref == call["spanId"] for j in out.trace.joins
    )
    assert any(d.reason == DegradationReason.AMBIGUOUS_JOIN for d in out.degradations)
    assert any(d.reason == DegradationReason.DUPLICATE_SPAN_ID for d in out.degradations)


def test_parent_pointing_at_duplicated_id_is_ambiguous_not_orphaned() -> None:
    doc = json.loads(_render("partial"))
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    result = next(s for s in spans if "parentSpanId" in s)
    parent_id = result["parentSpanId"]
    parent_span = next(s for s in spans if s["spanId"] == parent_id)
    twin = json.loads(json.dumps(parent_span))
    twin["name"] = twin["name"] + " TWIN"
    spans.append(twin)
    out = adapt_otlp(json.dumps(doc).encode())
    reasons = [d.reason for d in out.degradations]
    assert DegradationReason.AMBIGUOUS_JOIN in reasons
    assert DegradationReason.ORPHANED_PARENT not in reasons


def test_duplicate_id_differing_only_in_parent_is_kept_not_deduped() -> None:
    # Full-span dedup digest (M4 final-review fix): the "byte-identical"
    # tie-break must cover the WHOLE wire span, not a chosen subset of
    # fields - two spans sharing an id that differ ONLY in parentSpanId are
    # DIFFERING, not identical, and silently dropping one is exactly the
    # input-order-dependent bug the fix closes.
    doc = json.loads(_render())
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    idx = next(i for i, s in enumerate(spans) if s.get("parentSpanId"))
    original = spans[idx]
    twin = json.loads(json.dumps(original))
    other_parent = next(
        s["spanId"] for s in spans
        if s["spanId"] not in (original["spanId"], original["parentSpanId"])
    )
    twin["parentSpanId"] = other_parent
    dup_token = original["spanId"]
    base_spans = spans[:idx] + spans[idx + 1 :]

    def _with_order(tail: list[dict[str, object]]) -> bytes:
        d = json.loads(json.dumps(doc))
        d["resourceSpans"][0]["scopeSpans"][0]["spans"] = base_spans + tail
        return json.dumps(d).encode()

    out_a = adapt_otlp(_with_order([original, twin]))
    out_b = adapt_otlp(_with_order([twin, original]))

    # Order-independence: swapping the two duplicate spans' array position
    # must not change the output.
    assert out_a.trace == out_b.trace
    assert out_a.degradations == out_b.degradations

    dup_refs = {
        n.source_ref for n in out_a.trace.nodes
        if n.source_ref.startswith(f"{dup_token}#")
    }
    assert len(dup_refs) == 2  # both kept, digest-suffixed

    dup_degradations = [
        d for d in out_a.degradations
        if d.reason == DegradationReason.DUPLICATE_SPAN_ID and d.subject == dup_token
    ]
    assert len(dup_degradations) == 1
    assert "differing" in dup_degradations[0].note

    assert any(
        d.reason == DegradationReason.AMBIGUOUS_JOIN for d in out_a.degradations
    )
    assert not any(
        j.tool_result_source_ref in dup_refs or j.tool_call_source_ref in dup_refs
        for j in out_a.trace.joins
    )


def test_ledger_sorts_line_subjects_numerically_not_lexicographically() -> None:
    # 11 bad lines after one good line produce line:2 .. line:12 - lexicographic
    # sort would put line:10 before line:2; the ledger must sort numerically.
    good = json.dumps(json.loads(_render()))
    bad_lines = ["{not json" for _ in range(11)]
    data = "\n".join([good, *bad_lines]).encode()
    result = adapt_otlp(data)
    line_subjects = [
        d.subject for d in result.degradations
        if d.reason == DegradationReason.UNDECODABLE_BATCH
    ]
    assert line_subjects == [f"line:{n}" for n in range(2, 13)]
