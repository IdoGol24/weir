"""The corrupt corpus (spec section 7.2): authored AGAINST the section-2
contract, never before it. Each item is a deterministic transform of the
full-preset injection-exfil rendering, named for the contract row that
judges it. Expected verdicts live in tests/test_adapter_corrupt.py and are
derived from the DegradationReason enum - the third law, satisfied by
construction."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset

_SEED = 1


def _doc() -> dict[str, Any]:
    plan = apply_preset(instantiate("injection-exfil", seed=_SEED), "full")
    return render_otlp(plan, preset="full")


def _spans(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"]


def _dumps(doc: object) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


def render_corrupt_corpus() -> dict[str, bytes]:
    items: dict[str, bytes] = {}

    items["reject-not-json.txt"] = b"this file is not telemetry at all\n"

    items["reject-not-otlp.json"] = _dumps({"spans": "wrong shape entirely"})

    doc = _doc()
    spans = _spans(doc)
    spans.append(dict(spans[0]))  # byte-identical duplicate
    items["duplicate-span-id-identical.json"] = _dumps(doc)

    doc = _doc()
    spans = _spans(doc)
    clone = dict(spans[0])
    clone["name"] = clone["name"] + " CLONE"
    spans.append(clone)  # differing duplicate
    items["duplicate-span-id-differing.json"] = _dumps(doc)

    doc = _doc()
    for span in _spans(doc):
        if "parentSpanId" in span:
            span["parentSpanId"] = "ee" * 8  # absent parent
    items["orphaned-parent.json"] = _dumps(doc)

    doc = _doc()
    for span in _spans(doc):
        for field in ("traceId", "spanId", "parentSpanId"):
            if field in span:
                span[field] = base64.b64encode(
                    bytes.fromhex(span[field])
                ).decode()
    items["base64-ids.json"] = _dumps(doc)

    doc = _doc()
    _spans(doc)[0]["spanId"] = ""
    items["missing-span-id.json"] = _dumps(doc)

    doc = _doc()
    _spans(doc)[0]["startTimeUnixNano"] = "not-a-number"
    items["garbage-timestamp.json"] = _dumps(doc)

    doc = _doc()
    _spans(doc).append({"attributes": "bogus"})
    items["undecodable-span.json"] = _dumps(doc)

    doc = _doc()
    for span in _spans(doc):
        span["attributes"] = [
            a for a in span["attributes"] if a["key"] != "gen_ai.operation.name"
        ]
    items["missing-operation-name.json"] = _dumps(doc)

    doc = _doc()
    for span in _spans(doc):
        for a in span["attributes"]:
            if a["key"] == "gen_ai.tool.call.arguments":
                blob = a["value"]["stringValue"]
                a["value"]["stringValue"] = blob[: max(1, len(blob) // 2)]
    items["truncated-args.json"] = _dumps(doc)

    doc = _doc()
    doc["resourceSpans"][0]["schemaUrl"] = "https://example.com/not-a-dialect"
    for ss in doc["resourceSpans"][0]["scopeSpans"]:
        ss["schemaUrl"] = "https://example.com/not-a-dialect"
    for span in _spans(doc):
        span["attributes"] = [
            {"key": "llm.vendor", "value": {"stringValue": "mystery"}}
        ]
    items["unknown-dialect.json"] = _dumps(doc)

    good_line = json.dumps(_doc())
    items["jsonl-with-bad-line.jsonl"] = (
        good_line + "\n{truncated mid-write\n"
    ).encode()

    doc = _doc()
    _spans(doc).append({
        "traceId": "ab" * 16, "spanId": "77" * 8, "name": "GET /health",
        "kind": 3, "startTimeUnixNano": "1", "endTimeUnixNano": "2",
        "attributes": [
            {"key": "http.request.method", "value": {"stringValue": "GET"}}
        ],
    })
    items["non-genai-span.json"] = _dumps(doc)

    doc = _doc()
    for span in _spans(doc):
        for a in span["attributes"]:
            if a["key"] == "gen_ai.tool.call.arguments":
                # Mid-string decode error: UNPARSEABLE, never the
                # truncation fingerprint (which is error-at-end-of-string).
                a["value"]["stringValue"] = '{"query": nope, "x": 1}'
    items["unparseable-args.json"] = _dumps(doc)

    # Two results claim the same explicit call id: ambiguity, never a pick.
    doc = _doc()
    spans = _spans(doc)
    result_span = next(
        s for s in spans
        if any(a["key"] == "gen_ai.tool.call.id" for a in s["attributes"])
        and s["kind"] == 1
    )
    clone = json.loads(json.dumps(result_span))
    clone["spanId"] = "99" * 8
    clone.pop("parentSpanId", None)
    spans.append(clone)
    items["ambiguous-explicit-id.json"] = _dumps(doc)

    # Envelope join exists AND a mined id points at a different result:
    # resolved per precedence, conflict named (linkage-forgery fingerprint).
    doc = _doc()
    spans = _spans(doc)
    call_span = next(
        s for s in spans
        if any(a["key"] == "gen_ai.tool.call.arguments" for a in s["attributes"])
    )
    for a in call_span["attributes"]:
        if a["key"] == "gen_ai.tool.call.arguments":
            args = json.loads(a["value"]["stringValue"])
            args["tool_call_id"] = "forged-target"
            a["value"]["stringValue"] = json.dumps(
                args, sort_keys=True, separators=(",", ":"))
    spans.append({
        "traceId": "ab" * 16, "spanId": "88" * 8, "name": "execute_tool decoy",
        "kind": 1, "startTimeUnixNano": "1", "endTimeUnixNano": "2",
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.provider.name", "value": {"stringValue": "langchain"}},
            {"key": "gen_ai.tool.call.result",
             "value": {"stringValue": '{"content":"decoy","tool_call_id":"forged-target"}'}},
        ],
    })
    items["conflicting-join-evidence.json"] = _dumps(doc)

    # Invalid UTF-8 spliced into a string-value region: named, never silent.
    items["invalid-utf8.json"] = _dumps(_doc()).replace(
        b'"execute_tool', b'"exec\xffute_tool', 1
    )

    # Mixed JSONL: one traces line, one metrics line (decodes, isn't traces).
    items["mixed-signals.jsonl"] = (
        json.dumps(_doc()) + "\n" + json.dumps({"resourceMetrics": []}) + "\n"
    ).encode()

    # An instrumentation scope that fails structural decode: dropped, named.
    doc = _doc()
    doc["resourceSpans"][0]["scopeSpans"][0]["scope"] = {"name": ["not", "a", "string"]}
    items["undecodable-scope.json"] = _dumps(doc)

    # Top-level array wrapper: accepted shape, zero degradations expected.
    items["array-wrapped.json"] = (
        json.dumps([_doc()], indent=2, sort_keys=True) + "\n"
    ).encode()

    return items


def write_corrupt_corpus(fixtures_dir: Path) -> None:
    for rel, content in render_corrupt_corpus().items():
        path = fixtures_dir / "otlp-corrupt" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
