"""Stage 1: the entire reject side, and nothing but the reject side."""

import json

import pytest

from weir.adapters.otel._contract import DegradationReason
from weir.adapters.otel._wire import OtlpRejectError, decode_input


def _minimal_doc() -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": []},
                "schemaUrl": "https://opentelemetry.io/schemas/1.42.0",
                "scopeSpans": [
                    {
                        "scope": {"name": "s", "version": "1"},
                        "spans": [
                            {
                                "traceId": "ab" * 16,
                                "spanId": "cd" * 8,
                                "name": "chat",
                                "kind": 3,
                                "startTimeUnixNano": "1",
                                "endTimeUnixNano": "2",
                                "attributes": [
                                    {"key": "gen_ai.operation.name",
                                     "value": {"stringValue": "chat"}}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_not_json_rejects() -> None:
    with pytest.raises(OtlpRejectError):
        decode_input(b"this is not telemetry at all")


def test_json_but_not_otlp_shaped_rejects() -> None:
    with pytest.raises(OtlpRejectError):
        decode_input(json.dumps({"hello": "world"}).encode())


def test_minimal_doc_decodes() -> None:
    wire = decode_input(json.dumps(_minimal_doc()).encode())
    assert len(wire.spans) == 1
    assert wire.spans[0].span.span_id == "cd" * 8
    assert wire.degradations == []


def test_utf8_bom_is_stripped() -> None:
    data = b"\xef\xbb\xbf" + json.dumps(_minimal_doc()).encode()
    assert len(decode_input(data).spans) == 1


def test_snake_case_wire_variant_is_accepted() -> None:
    doc = _minimal_doc()
    snake = json.loads(
        json.dumps(doc)
        .replace("resourceSpans", "resource_spans")
        .replace("scopeSpans", "scope_spans")
        .replace("schemaUrl", "schema_url")
        .replace("traceId", "trace_id")
        .replace("spanId", "span_id")
        .replace("startTimeUnixNano", "start_time_unix_nano")
        .replace("endTimeUnixNano", "end_time_unix_nano")
    )
    wire = decode_input(json.dumps(snake).encode())
    assert wire.spans[0].span.span_id == "cd" * 8


def test_numeric_nanos_accepted() -> None:
    doc = _minimal_doc()
    doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["startTimeUnixNano"] = 1
    assert decode_input(json.dumps(doc).encode()).degradations == []


def test_jsonl_batches_merge_and_bad_line_degrades_not_rejects() -> None:
    good = json.dumps(_minimal_doc())
    data = (good + "\n{not json\n" + good + "\n").encode()
    wire = decode_input(data)
    assert len(wire.spans) == 2
    assert [d.reason for d in wire.degradations] == [DegradationReason.UNDECODABLE_BATCH]
    assert wire.degradations[0].subject == "line:2"


def test_undecodable_span_is_quarantined_not_fatal() -> None:
    doc = _minimal_doc()
    doc["resourceSpans"][0]["scopeSpans"][0]["spans"].append({"attributes": "bogus"})
    wire = decode_input(json.dumps(doc).encode())
    assert len(wire.spans) == 1
    assert [d.reason for d in wire.degradations] == [DegradationReason.UNDECODABLE_SPAN]


def test_invalid_utf8_is_named_never_silent() -> None:
    data = json.dumps(_minimal_doc()).encode()
    # Splice an invalid byte into a string value region (inside "chat").
    corrupted = data.replace(b'"chat"', b'"ch\xffat"', 1)
    wire = decode_input(corrupted)
    reasons = [d.reason for d in wire.degradations]
    assert DegradationReason.INVALID_ENCODING in reasons
    assert "byte offset" in next(
        d.note for d in wire.degradations
        if d.reason == DegradationReason.INVALID_ENCODING
    )


def test_top_level_json_array_of_batches_is_accepted() -> None:
    data = json.dumps([_minimal_doc(), _minimal_doc()]).encode()
    assert len(decode_input(data).spans) == 2


def test_mixed_jsonl_counts_non_trace_lines() -> None:
    metrics_line = json.dumps({"resourceMetrics": []})
    data = (json.dumps(_minimal_doc()) + "\n" + metrics_line + "\n").encode()
    wire = decode_input(data)
    assert len(wire.spans) == 1
    entry = next(
        d for d in wire.degradations
        if d.reason == DegradationReason.NON_TRACE_BATCHES_SKIPPED
    )
    assert entry.note == "1"


def test_undecodable_scope_degrades_not_silent() -> None:
    doc = _minimal_doc()
    doc["resourceSpans"][0]["scopeSpans"][0]["scope"] = {"name": ["not", "a", "string"]}
    wire = decode_input(json.dumps(doc).encode())
    assert len(wire.spans) == 1
    assert DegradationReason.UNDECODABLE_SCOPE in [d.reason for d in wire.degradations]


def test_non_trace_batches_skipped_counts_malformed_traces_batch() -> None:
    good = json.dumps(_minimal_doc())
    garbage_line = json.dumps({"resourceSpans": "garbage"})
    data = (good + "\n" + garbage_line + "\n").encode()
    wire = decode_input(data)
    assert len(wire.spans) == 1
    entry = next(
        d for d in wire.degradations
        if d.reason == DegradationReason.NON_TRACE_BATCHES_SKIPPED
    )
    assert entry.note == "1"


def test_scope_level_schema_url_overrides_resource_level() -> None:
    doc = _minimal_doc()
    doc["resourceSpans"][0]["schemaUrl"] = "https://opentelemetry.io/schemas/1.0.0"
    doc["resourceSpans"][0]["scopeSpans"][0]["schemaUrl"] = (
        "https://opentelemetry.io/schemas/1.42.0"
    )
    wire = decode_input(json.dumps(doc).encode())
    assert wire.spans[0].schema_url == "https://opentelemetry.io/schemas/1.42.0"


def test_attribute_values_are_not_key_normalized() -> None:
    # A user kvlist keyed `span_id` inside attribute VALUES must survive
    # untouched - normalization is bounded to the structural depth.
    doc = _minimal_doc()
    doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"].append(
        {"key": "user.blob",
         "value": {"kvlistValue": {"values": [
             {"key": "span_id", "value": {"stringValue": "not-structural"}}
         ]}}}
    )
    wire = decode_input(json.dumps(doc).encode())
    blob = next(
        a for a in wire.spans[0].span.attributes if a.get("key") == "user.blob"
    )
    assert "span_id" in json.dumps(blob)


def test_wire_span_carries_status_and_events() -> None:
    doc = {
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name",
                                         "value": {"stringValue": "svc"}}]},
            "scopeSpans": [{
                "scope": {"name": "s", "attributes": [
                    {"key": "scope.note", "value": {"stringValue": "hi"}}]},
                "spans": [{
                    "spanId": "aa" * 8,
                    "status": {"message": "boom", "code": 2},
                    "events": [{"name": "exception", "attributes": [
                        {"key": "exception.message",
                         "value": {"stringValue": "detail"}}]}],
                }],
            }],
        }]
    }
    wire = decode_input(json.dumps(doc).encode())
    span = wire.spans[0].span
    assert span.status["message"] == "boom"
    assert span.status["code"] == 2
    assert span.events[0]["name"] == "exception"
    assert span.events[0]["attributes"][0]["key"] == "exception.message"
    assert wire.spans[0].scope.attributes[0]["key"] == "scope.note"


def test_a_span_without_status_or_events_still_decodes() -> None:
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"spanId": "bb" * 8}]}]}]}
    span = decode_input(json.dumps(doc).encode()).spans[0].span
    assert span.status is None
    assert span.events is None


def test_a_quarantined_span_subject_carries_no_attribute_values() -> None:
    # G4: the ledger names WHAT failed, never the bytes that failed. A raw
    # JSON slice of the span would put an exported credential in the report.
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"spanId": "cc" * 8},
        {"attributes": "bogus", "name": "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"},
    ]}]}]}
    wire = decode_input(json.dumps(doc).encode())
    quarantined = [d for d in wire.degradations if d.reason == "undecodable_span"]
    assert len(quarantined) == 1
    assert "sk-proj-" not in quarantined[0].subject + quarantined[0].note
    assert "attributes" in quarantined[0].subject  # keys are named, values are not


@pytest.mark.parametrize(
    "overlay",
    [
        {"status": None},
        {"events": None},
        {"events": [None]},
        {"events": ["a string"]},
        {"events": {}},
        {"status": "STATUS_CODE_ERROR"},
        {"status": []},
        {"status": {"message": None}},
        {"events": [{"name": "x", "attributes": "nope"}]},
        {"status": {"code": "STATUS_CODE_ERROR"}},
        {"status": {"code": 2}},
        {"events": [{"name": "x", "timeUnixNano": "1", "droppedAttributesCount": 0,
                     "attributes": []}]},
        {"status": {}},
        {"events": []},
        {"events": [{}]},
    ],
    ids=lambda o: str(o),
)
def test_no_status_or_events_shape_can_quarantine_a_span(overlay) -> None:
    # These fields are parsed for the exposure scan only. Typing them would
    # make the decoder stricter on data it used to ignore, and a quarantined
    # span silently drops its edges out of the flow graph.
    span = {"spanId": "aa" * 8, "name": "s", **overlay}
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}
    wire = decode_input(json.dumps(doc).encode())
    assert len(wire.spans) == 1, wire.degradations
