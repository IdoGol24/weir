"""The adapter half: every string the exporter wrote, in span order, with a
location path. Mechanical - it knows nothing about credentials, so there is
nothing here to grade and no catalog in sight."""

import json

from weir.adapters.otel import decode_input, map_wire
from weir.adapters.otel.exposure import scan_surface


def _attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def _surface(spans, resource=None, scope=None):
    doc = {"resourceSpans": [{
        "resource": {"attributes": resource or []},
        "scopeSpans": [{"scope": {"name": "s", "attributes": scope or []},
                        "spans": spans}],
    }]}
    return scan_surface(decode_input(json.dumps(doc).encode()))


def test_span_attributes_are_enumerated_with_a_location_path() -> None:
    surface = _surface([{"spanId": "aa" * 8, "name": "agent",
                         "attributes": [_attr("acme.agent.llm", "value-here")]}])
    assert surface.applicable
    assert surface.spans_scanned == 1
    assert [(s.span_index, s.span_ref, s.span_name, s.location, s.text)
            for s in surface.strings] == [
        (0, "aa" * 8, "agent", "attributes.acme.agent.llm", "value-here")]


def test_events_status_resource_and_scope_are_all_on_the_surface() -> None:
    surface = _surface(
        [{"spanId": "aa" * 8,
          "status": {"message": "boom"},
          "events": [{"name": "exception",
                      "attributes": [_attr("exception.message", "detail")]}]}],
        resource=[_attr("acme.boot", "r")],
        scope=[_attr("acme.cfg", "s")],
    )
    assert [s.location for s in surface.strings] == [
        "events[0].attributes.exception.message",
        "status.message",
        "resource.attributes.acme.boot",
        "scope.attributes.acme.cfg",
    ]


def test_resource_and_scope_are_visited_once_per_batch() -> None:
    surface = _surface(
        [{"spanId": "aa" * 8}, {"spanId": "bb" * 8}],
        resource=[_attr("acme.boot", "r")],
        scope=[_attr("acme.cfg", "s")],
    )
    assert len(surface.strings) == 2
    # Attributed to the FIRST span that arrived under them.
    assert all(s.span_ref == "aa" * 8 for s in surface.strings)


def test_array_and_kvlist_values_recurse_with_a_path() -> None:
    surface = _surface([{"spanId": "aa" * 8, "attributes": [
        {"key": "arr", "value": {"arrayValue": {"values": [{"stringValue": "x"}]}}},
        {"key": "kv", "value": {"kvlistValue": {"values": [
            {"key": "inner", "value": {"stringValue": "y"}}]}}},
    ]}])
    assert [s.location for s in surface.strings] == ["attributes.arr[0]", "attributes.kv.inner"]


def test_non_string_values_are_skipped_never_coerced() -> None:
    surface = _surface([{"spanId": "aa" * 8, "attributes": [
        {"key": "n", "value": {"intValue": "42"}},
        {"key": "b", "value": {"boolValue": True}},
        {"key": "broken", "value": "not-a-dict"},
    ]}])
    assert surface.strings == []


def test_strings_arrive_in_wire_span_order() -> None:
    surface = _surface([
        {"spanId": "bb" * 8, "attributes": [_attr("z", "1"), _attr("a", "2")]},
        {"spanId": "aa" * 8, "attributes": [_attr("m", "3")]},
    ])
    assert [(s.span_index, s.location) for s in surface.strings] == [
        (0, "attributes.z"), (0, "attributes.a"), (1, "attributes.m")]


def test_a_span_the_genai_filter_drops_is_still_on_the_surface() -> None:
    # The whole point: the leak lives on spans carrying no gen_ai.* key.
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"spanId": "aa" * 8, "name": "crew.agent",
         "attributes": [_attr("acme.agent.llm", "material")]}]}]}]}
    wire = decode_input(json.dumps(doc).encode())
    assert map_wire(wire).trace.nodes == []
    assert len(scan_surface(wire).strings) == 1


def _nested_kvlist(depth: int) -> dict:
    value: dict = {"stringValue": "bottom"}
    for _ in range(depth):
        value = {"kvlistValue": {"values": [{"key": "n", "value": value}]}}
    return value


def test_a_hostile_depth_does_not_crash_the_scan() -> None:
    # A 500-level kvlist nest used to blow the recursion limit; the cap must
    # make scan_surface return instead. A shallow canary string in the same
    # span proves the rest of the walk still runs.
    surface = _surface([{"spanId": "aa" * 8, "attributes": [
        {"key": "deep", "value": _nested_kvlist(500)},
        _attr("canary", "shallow-value"),
    ]}])
    assert "shallow-value" in [s.text for s in surface.strings]
