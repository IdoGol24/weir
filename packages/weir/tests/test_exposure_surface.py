"""The adapter half: every string the exporter wrote, in span order, with a
location path: values, and the names and keys they sit under. Mechanical -
it knows nothing about credentials, so there is nothing here to grade and no
catalog in sight."""

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
    assert [(s.record_index, s.span_ref, s.span_name, s.location, s.text)
            for s in surface.strings] == [
        (0, "aa" * 8, "agent", "name", "agent"),
        (0, "aa" * 8, "agent", "attributes.acme.agent.llm (key)", "acme.agent.llm"),
        (0, "aa" * 8, "agent", "attributes.acme.agent.llm", "value-here"),
        (0, "aa" * 8, "agent", "scope.name", "s")]


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
        "events[0].name",
        "events[0].attributes.exception.message (key)",
        "events[0].attributes.exception.message",
        "status.message",
        "resource.attributes.acme.boot (key)",
        "resource.attributes.acme.boot",
        "scope.name",
        "scope.attributes.acme.cfg (key)",
        "scope.attributes.acme.cfg",
    ]


def test_resource_and_scope_are_visited_once_per_batch() -> None:
    surface = _surface(
        [{"spanId": "aa" * 8}, {"spanId": "bb" * 8}],
        resource=[_attr("acme.boot", "r")],
        scope=[_attr("acme.cfg", "s")],
    )
    # Each attribute's key and value, and the scope name, once.
    assert len(surface.strings) == 5
    # Attributed to the FIRST span that arrived under them.
    assert all(s.span_ref == "aa" * 8 for s in surface.strings)


def test_array_and_kvlist_values_recurse_with_a_path() -> None:
    surface = _surface([{"spanId": "aa" * 8, "attributes": [
        {"key": "arr", "value": {"arrayValue": {"values": [{"stringValue": "x"}]}}},
        {"key": "kv", "value": {"kvlistValue": {"values": [
            {"key": "inner", "value": {"stringValue": "y"}}]}}},
    ]}])
    assert [s.location for s in surface.strings] == [
        "attributes.arr (key)", "attributes.arr[0]",
        "attributes.kv (key)", "attributes.kv.inner (key)", "attributes.kv.inner",
        "scope.name"]


def test_non_string_values_are_skipped_never_coerced() -> None:
    surface = _surface([{"spanId": "aa" * 8, "attributes": [
        {"key": "n", "value": {"intValue": "42"}},
        {"key": "b", "value": {"boolValue": True}},
        {"key": "broken", "value": "not-a-dict"},
    ]}])
    # Only the keys and the scope name, which are strings: no value is
    # coerced into one.
    assert [(s.key, s.text) for s in surface.strings] == [
        (True, "n"), (True, "b"), (True, "broken"), (False, "s")]


def test_strings_arrive_in_wire_span_order() -> None:
    surface = _surface([
        {"spanId": "bb" * 8, "attributes": [_attr("z", "1"), _attr("a", "2")]},
        {"spanId": "aa" * 8, "attributes": [_attr("m", "3")]},
    ])
    assert [(s.record_index, s.location) for s in surface.strings if not s.key] == [
        (0, "attributes.z"), (0, "attributes.a"), (0, "scope.name"), (1, "attributes.m")]


def test_a_span_the_genai_filter_drops_is_still_on_the_surface() -> None:
    # The whole point: the leak lives on spans carrying no gen_ai.* key.
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"spanId": "aa" * 8, "name": "crew.agent",
         "attributes": [_attr("acme.agent.llm", "material")]}]}]}]}
    wire = decode_input(json.dumps(doc).encode())
    assert map_wire(wire).trace.nodes == []
    assert [s.location for s in scan_surface(wire).strings] == [
        "name", "attributes.acme.agent.llm (key)", "attributes.acme.agent.llm"]


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
