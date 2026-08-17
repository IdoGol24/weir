"""The OTLP-JSON renderer."""

import json

from weir.schema.dialect import OTEL_GENAI_1_42_0, content_bearing_keys, profile_digest
from weir_tracegen.otlp import BASE_UNIX_NANOS, render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.dials import without_content, without_linkage


def _doc(plan=None, preset="full"):
    return render_otlp(plan or instantiate("injection-exfil", seed=1), preset=preset)


def _spans(doc):
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"]


def _attrs(span):
    return {a["key"]: a["value"] for a in span["attributes"]}


def _all_keys(doc):
    keys = set()
    for span in _spans(doc):
        keys.update(_attrs(span))
    return keys


def test_schema_url_is_in_the_native_field_not_an_attribute() -> None:
    resource_spans = _doc()["resourceSpans"][0]
    assert resource_spans["schemaUrl"] == OTEL_GENAI_1_42_0.schema_url
    assert resource_spans["scopeSpans"][0]["schemaUrl"] == OTEL_GENAI_1_42_0.schema_url


def test_resource_attributes_carry_the_provenance_triplet_and_scenario() -> None:
    resource = _doc()["resourceSpans"][0]["resource"]
    attrs = {a["key"]: a["value"]["stringValue"] for a in resource["attributes"]}
    assert attrs["weir.profile.id"] == "otel-genai/1.42.0"
    assert attrs["weir.profile.digest"] == profile_digest(OTEL_GENAI_1_42_0)
    assert attrs["weir.scenario.id"] == "injection-exfil"
    assert attrs["weir.tracegen.preset"] == "full"


def test_ids_are_lowercase_hex_of_the_right_width() -> None:
    for span in _spans(_doc()):
        assert len(span["traceId"]) == 32
        assert len(span["spanId"]) == 16
        assert span["traceId"] == span["traceId"].lower()
        int(span["traceId"], 16)
        int(span["spanId"], 16)


def test_nanos_serialize_as_decimal_strings() -> None:
    # proto3 JSON encodes 64-bit ints as strings; a number would not round-trip
    # through the official bindings.
    for span in _spans(_doc()):
        assert isinstance(span["startTimeUnixNano"], str)
        assert span["startTimeUnixNano"].isdigit()
    assert _spans(_doc())[0]["startTimeUnixNano"] == str(BASE_UNIX_NANOS)


def test_tool_result_span_parents_to_its_tool_call() -> None:
    spans = _spans(_doc())
    by_id = {s["spanId"]: s for s in spans}
    parented = [s for s in spans if s.get("parentSpanId")]
    assert parented, "the join must be expressible as nesting"
    for span in parented:
        assert span["parentSpanId"] in by_id


def test_closure_no_dangling_parent_reference() -> None:
    spans = _spans(_doc())
    ids = {s["spanId"] for s in spans}
    for span in spans:
        if span.get("parentSpanId"):
            assert span["parentSpanId"] in ids


def test_span_ids_are_unique() -> None:
    spans = _spans(_doc())
    assert len({s["spanId"] for s in spans}) == len(spans)


def test_full_preset_carries_linkage_and_content() -> None:
    keys = _all_keys(_doc())
    assert "gen_ai.tool.call.id" in keys
    assert "gen_ai.tool.call.arguments" in keys


def test_without_linkage_omits_the_call_id_key_but_keeps_content() -> None:
    doc = _doc(without_linkage(instantiate("injection-exfil", seed=1)), preset="partial")
    keys = _all_keys(doc)
    assert "gen_ai.tool.call.id" not in keys
    assert "gen_ai.tool.call.arguments" in keys
    # Nesting must survive so the join is still recoverable.
    assert any(s.get("parentSpanId") for s in _spans(doc))


def test_without_content_omits_every_content_bearing_key() -> None:
    doc = _doc(
        without_content(instantiate("injection-exfil", seed=1)), preset="default-realistic"
    )
    keys = _all_keys(doc)
    assert not (keys & content_bearing_keys(OTEL_GENAI_1_42_0))
    assert "gen_ai.tool.call.id" in keys  # linkage is not content


def test_clock_offset_shifts_the_span() -> None:
    from weir_tracegen.scenarios.dials import with_clock_skew

    plan = with_clock_skew(instantiate("injection-exfil", seed=1), step_index=2, offset_ns=5000)
    shifted = _spans(_doc(plan))[2]["startTimeUnixNano"]
    assert shifted == str(BASE_UNIX_NANOS + 2 * 1_000_000_000 + 5000)


def test_scope_carries_framework_identity_so_it_can_round_trip() -> None:
    # framework_version is on no attribute; the instrumentation scope is its
    # only carrier, and an adapter needs it to satisfy the drift-detection
    # requirement the native metadata exists for.
    from weir_tracegen.emitter import FRAMEWORK_NAME, FRAMEWORK_VERSION

    scope = _doc()["resourceSpans"][0]["scopeSpans"][0]["scope"]
    assert scope["version"] == FRAMEWORK_VERSION
    assert FRAMEWORK_NAME in scope["name"]


def test_attribute_order_is_pinned() -> None:
    # Neither OTLP-JSON nor protobuf gives canonical bytes for free. Unpinned
    # ordering makes the corpus drift test flap.
    for span in _spans(_doc()):
        keys = [a["key"] for a in span["attributes"]]
        assert keys == sorted(keys)
    resource = _doc()["resourceSpans"][0]["resource"]
    resource_keys = [a["key"] for a in resource["attributes"]]
    assert resource_keys == sorted(resource_keys)


def test_render_is_deterministic() -> None:
    assert json.dumps(_doc(), sort_keys=True) == json.dumps(_doc(), sort_keys=True)


def test_span_count_matches_step_count() -> None:
    plan = instantiate("injection-exfil", seed=1)
    assert len(_spans(_doc(plan))) == len(plan.steps)


def test_span_kinds_reflect_whether_the_step_leaves_the_process() -> None:
    # Note: a tool_result span shares its display name with the tool_call it
    # reports (FIX 2), so a name->span lookup collides here and would silently
    # check the wrong span. Index into the fixed injection-exfil step order
    # instead: 6 is the send_email tool_call, 7 is its tool_result.
    spans = _spans(_doc())
    assert spans[6]["name"] == "execute_tool send_email"
    assert spans[6]["kind"] == 3
    assert spans[7]["name"] == "execute_tool send_email"
    assert spans[7]["kind"] == 1
    # index 0 is the user_input step, index 3 is the llm_call step; both are
    # named "chat" but only the model call leaves the process.
    assert spans[0]["kind"] == 1
    assert spans[3]["kind"] == 3
    # user_input and tool_result stay INTERNAL
    assert any(s["kind"] == 1 for s in spans)
    assert any(s["kind"] == 3 for s in spans)


def test_span_names_never_leak_the_internal_step_kind() -> None:
    # `kind` values like "user_input" / "tool_result" are weir-internal
    # identifiers and must not appear on the wire.
    for span in _spans(_doc()):
        assert "user_input" not in span["name"]
        assert "tool_result" not in span["name"]
        assert "llm_call" not in span["name"]


def test_tool_result_span_is_named_for_the_tool_it_reports() -> None:
    spans = _spans(_doc())
    # span 2 is the tool_result joined to span 1's fetch_support_tickets call
    assert spans[2]["name"] == "execute_tool fetch_support_tickets"
    assert spans[1]["name"] == "execute_tool fetch_support_tickets"
