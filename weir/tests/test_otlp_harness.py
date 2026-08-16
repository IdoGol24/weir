"""The OTLP structural validator, and proof its id shim is load-bearing."""

import base64
from typing import Any

import pytest
from _harness.otlp import assert_accept_side, parse_otlp_json
from google.protobuf import json_format
from opentelemetry.proto.trace.v1.trace_pb2 import TracesData

from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset


def _doc(preset: str = "full") -> dict[str, Any]:
    plan = apply_preset(instantiate("injection-exfil", seed=1), preset)
    return render_otlp(plan, preset=preset)


def _spans(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"]


def test_accept_side_passes_on_every_shipped_preset() -> None:
    for preset in ("full", "partial", "default-realistic"):
        assert_accept_side(_doc(preset))


def test_ids_survive_the_round_trip_intact() -> None:
    doc = _doc()
    parsed = parse_otlp_json(doc)
    emitted = [s["spanId"] for s in _spans(doc)]
    round_tripped = [
        span.span_id.hex()
        for rs in parsed.resource_spans
        for ss in rs.scope_spans
        for span in ss.spans
    ]
    assert round_tripped == emitted


def test_without_the_shim_hex_ids_are_silently_mangled() -> None:
    # THE LANDMINE, pinned as a test. OTLP/JSON mandates hex ids; protobuf's
    # json_format treats bytes fields as base64. 32 hex chars are valid base64
    # alphabet, so Parse SUCCEEDS and decodes a 16-byte id into 24 bytes of
    # garbage. Without the shim the round-trip validates nothing about ids and
    # the duplicate-id check runs on mangled values while looking green.
    doc = _doc()
    unshimmed = json_format.ParseDict(doc, TracesData(), ignore_unknown_fields=True)
    emitted_hex = _spans(doc)[0]["spanId"]
    decoded = unshimmed.resource_spans[0].scope_spans[0].spans[0].span_id
    assert decoded == base64.b64decode(emitted_hex + "==")
    assert decoded.hex() != emitted_hex
    assert len(decoded) != 8


def test_duplicate_span_id_is_rejected() -> None:
    doc = _doc()
    spans = _spans(doc)
    spans[1]["spanId"] = spans[0]["spanId"]
    with pytest.raises(AssertionError, match="duplicate span id"):
        assert_accept_side(doc)


def test_dangling_parent_reference_is_rejected() -> None:
    doc = _doc()
    for span in _spans(doc):
        if span.get("parentSpanId"):
            span["parentSpanId"] = "ffffffffffffffff"
            break
    with pytest.raises(AssertionError, match="closure"):
        assert_accept_side(doc)


def test_validator_does_not_mutate_the_document() -> None:
    doc = _doc()
    before = _spans(doc)[0]["spanId"]
    assert_accept_side(doc)
    assert _spans(doc)[0]["spanId"] == before
