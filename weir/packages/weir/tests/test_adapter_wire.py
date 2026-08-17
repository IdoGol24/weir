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
