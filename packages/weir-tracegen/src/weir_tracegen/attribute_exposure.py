"""The `attribute_exposure` capture (spec 2026-09-06 section 5): synthetic,
vendor-free, and hand-built.

It is not a ScenarioSpec. A ScenarioSpec is a plan that two renderers turn into
GenAI spans; this capture needs vendor-namespaced attributes, an exception
event, a status message, and one span carrying no `gen_ai.*` key at all - none
of which a plan can express. `corrupt.py` is the sibling to compare it to, not
`scenarios/`.

The planted key is a locally generated random string of OpenAI shape. It is not
a real credential, and it deliberately clears the bundled reject list and the
distinct-character floor, because a fixture that could not be verdict-grade
would prove nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"
_TRACE_ID = "b1946ac92492d2347c6235b4d2611184"
_SCHEMA_URL = "https://opentelemetry.io/schemas/1.42.0"
_BASE_NANOS = 1767225600000000000
_STEP_NANOS = 1_000_000_000


def _attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def _sorted_attrs(pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(pairs, key=lambda a: a["key"])


def _agent_span(index: int, *, span_id: str, genai: bool) -> dict[str, Any]:
    """An agent span whose vendor attributes carry the serialized repr of the
    agent object - the shape that leaked the key. One of these carries no
    gen_ai.* key, so the mapper's GenAI filter drops it; its hits must still be
    reported, which is what proves the scan runs before the filter."""
    start = _BASE_NANOS + index * _STEP_NANOS
    attributes = [
        _attr("acme.agent.llm", f"LLM(model='m-1', temperature=0.0, api_key='{_KEY}')"),
        _attr("acme.agent.executor", f"AgentExecutor(llm=LLM(api_key='{_KEY}'), tools=[])"),
    ]
    if genai:
        attributes.append(_attr("gen_ai.operation.name", "chat"))
        attributes.append(_attr("gen_ai.provider.name", "acme"))
    return {
        "traceId": _TRACE_ID,
        "spanId": span_id,
        "name": "acme.agent",
        "kind": 1,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(start + _STEP_NANOS),
        "attributes": _sorted_attrs(attributes),
    }


def render_document() -> dict[str, Any]:
    spans: list[dict[str, Any]] = [
        _agent_span(0, span_id="1111111111111111", genai=True),
        _agent_span(1, span_id="2222222222222222", genai=True),
        _agent_span(2, span_id="3333333333333333", genai=False),
    ]

    # The same key inside the JSON STRING of a chat span's input messages,
    # proving the scan reads raw strings and never parses them, and again in a
    # status message, proving the surface list. The event attributes carry the
    # false-positive companions.
    chat_start = _BASE_NANOS + 3 * _STEP_NANOS
    spans.append({
        "traceId": _TRACE_ID,
        "spanId": "4444444444444444",
        "name": "chat m-1",
        "kind": 3,
        "startTimeUnixNano": str(chat_start),
        "endTimeUnixNano": str(chat_start + _STEP_NANOS),
        "status": {"code": 2, "message": f"upstream rejected key {_KEY}"},
        "attributes": _sorted_attrs([
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.provider.name", "acme"),
            _attr("gen_ai.input.messages", json.dumps(
                [{"role": "user", "content": f"here is my key {_KEY}, use it"}],
                sort_keys=True, separators=(",", ":"))),
        ]),
        "events": [{
            "name": "exception",
            "attributes": _sorted_attrs([
                _attr("exception.message",
                      "auth failed for sk-proj-****************************0000; "
                      "response {'code': 'invalid_api_key'}"),
                _attr("exception.type", "AuthError"),
            ]),
        }],
    })

    misc_start = _BASE_NANOS + 4 * _STEP_NANOS
    spans.append({
        "traceId": _TRACE_ID,
        "spanId": "5555555555555555",
        "name": "acme.config",
        "kind": 1,
        "startTimeUnixNano": str(misc_start),
        "endTimeUnixNano": str(misc_start + _STEP_NANOS),
        "status": {"code": 0, "message": "loaded with api_key='***'"},
        "attributes": _sorted_attrs([
            _attr("acme.flags", "token=1 secret=true max_tokens: 1024"),
            # A key-name match with no floor to clear: credential_field has no
            # pattern/structure_class/min_length, so it is never eligible by
            # construction - triage route 1.
            _attr("acme.secrets.password", "password=correcthorsebattery"),
            # A content match that clears google_api_key's loose content_pattern
            # (AIza + 16-256 chars) but fails its eligibility.pattern (AIza +
            # exactly 35) - wrong length, not a masked/rejected value. Proves
            # triage is not only key-name matches - triage route 2.
            _attr("acme.secrets.google_key", "AIzaSyBqT7Rk2Ls9Vn4Xb6Zt1Wc8Mp3"),
        ]),
    })

    return {
        "resourceSpans": [{
            "resource": {"attributes": [_attr("service.name", "acme-crew")]},
            "schemaUrl": _SCHEMA_URL,
            "scopeSpans": [{
                "scope": {"name": "acme.instrumentation.crew", "version": "0.1.0"},
                "schemaUrl": _SCHEMA_URL,
                "spans": spans,
            }],
        }]
    }


def render_all() -> dict[str, str]:
    return {
        "exposure/attribute-exposure.json":
            json.dumps(render_document(), indent=2, sort_keys=True) + "\n"
    }


def write_all(fixtures_dir: Path) -> None:
    """LF newlines so the committed bytes do not depend on the platform."""
    for rel, content in render_all().items():
        path = fixtures_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
