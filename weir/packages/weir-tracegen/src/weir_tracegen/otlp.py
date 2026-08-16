"""OTLP-JSON renderer: the SECOND renderer over the same scenario plan.

Architectural law: this module renders the same `ScenarioSpec` the native
emitter renders. It is never a parallel generator, and it knows nothing about
dials - it reads the plan's declarative fields and maps them into the pinned
dialect. That is what makes the adapter milestone's acceptance test
by-construction: adapter(render_otlp(plan)) must equal emit_scenario(plan)
after normalizing declared provenance fields.

Span model: one span per step. A tool_result span is a CHILD of its joined
tool_call span, so dropping `gen_ai.tool.call.id` leaves parent/child nesting
as the join fallback. No synthetic session span: an extra span is one more
thing the adapter would have to drop.

Wire-format notes that are easy to get wrong:
- Trace and span ids are LOWERCASE HEX in OTLP/JSON, not base64.
- 64-bit nanosecond fields serialize as DECIMAL STRINGS per proto3 JSON.
- The schema URL belongs in the native `schemaUrl` field on ResourceSpans and
  ScopeSpans, the slot real collectors read, not in an attribute.
"""

from __future__ import annotations

import hashlib
import json

from weir.schema.dialect import OTEL_GENAI_1_42_0, DialectProfile, profile_digest
from weir_tracegen.emitter import step_source_ref
from weir_tracegen.scenarios._types import ScenarioSpec, StepSpec

# 2026-01-01T00:00:00Z, matching the native seeded clock's base instant.
BASE_UNIX_NANOS = 1767225600000000000
_STEP_NANOS = 1_000_000_000

SCOPE_NAME = "weir-tracegen"
SCOPE_VERSION = "0.1.0"
PROVIDER_NAME = "langchain"

_OPERATION_BY_KIND = {
    "llm_call": "chat",
    "tool_call": "execute_tool",
    "tool_result": "execute_tool",
    "user_input": "chat",
}


def _hex_id(seed_text: str, width: int) -> str:
    """Derive a stable id from the ONE step-identity helper, so OTLP span ids
    and native source_refs cannot drift apart."""
    return hashlib.sha256(seed_text.encode("utf-8")).hexdigest()[:width]


def _attributes(pairs: dict[str, str]) -> list[dict[str, object]]:
    """Attribute ordering is pinned by sorting on key. Unpinned ordering makes
    the corpus drift test flap."""
    return [{"key": key, "value": {"stringValue": pairs[key]}} for key in sorted(pairs)]


def _span_attributes(step: StepSpec, *, call_id: str | None) -> dict[str, str]:
    pairs: dict[str, str] = {
        "gen_ai.operation.name": _OPERATION_BY_KIND[step.kind],
        "gen_ai.provider.name": PROVIDER_NAME,
    }
    if step.tool_name is not None:
        pairs["gen_ai.tool.name"] = step.tool_name
    if call_id is not None:
        pairs["gen_ai.tool.call.id"] = call_id
    if not step.content_captured:
        return pairs
    if step.kind == "tool_call":
        pairs["gen_ai.tool.call.arguments"] = json.dumps(
            step.args or {}, sort_keys=True, separators=(",", ":")
        )
    elif step.kind == "tool_result":
        pairs["gen_ai.tool.call.result"] = step.content or ""
    elif step.kind == "user_input":
        pairs["gen_ai.input.messages"] = step.content or ""
    elif step.kind == "llm_call":
        pairs["gen_ai.output.messages"] = step.content or ""
    return pairs


def render_otlp(
    plan: ScenarioSpec,
    *,
    preset: str,
    profile: DialectProfile = OTEL_GENAI_1_42_0,
) -> dict[str, object]:
    trace_id = _hex_id(f"trace-{plan.name}", 32)
    span_ids = [_hex_id(step_source_ref(plan.name, i), 16) for i in range(len(plan.steps))]

    # A tool_result span parents to its tool_call span; explicit linkage adds
    # the call id on both ends. `nested` confidence means linkage is dropped
    # but the nesting remains, which is the fallback a consumer must use.
    parent_of: dict[int, int] = {}
    call_id_of: dict[int, str] = {}
    for join in plan.joins:
        parent_of[join.result_index] = join.call_index
        if join.join_confidence == "explicit":
            call_id = _hex_id(f"call-{plan.name}-{join.call_index}", 16)
            call_id_of[join.call_index] = call_id
            call_id_of[join.result_index] = call_id

    spans: list[dict[str, object]] = []
    for i, step in enumerate(plan.steps):
        start = BASE_UNIX_NANOS + i * _STEP_NANOS + step.clock_offset_ns
        span: dict[str, object] = {
            "traceId": trace_id,
            "spanId": span_ids[i],
            "name": f"{_OPERATION_BY_KIND[step.kind]} {step.tool_name or step.kind}",
            "kind": 1,
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(start + _STEP_NANOS),
            "attributes": _attributes(_span_attributes(step, call_id=call_id_of.get(i))),
        }
        if i in parent_of:
            span["parentSpanId"] = span_ids[parent_of[i]]
        spans.append(span)

    resource_attributes = _attributes(
        {
            "weir.profile.id": profile.profile_id,
            "weir.profile.digest": profile_digest(profile),
            "weir.scenario.id": plan.name,
            "weir.tracegen.preset": preset,
        }
    )

    return {
        "resourceSpans": [
            {
                "resource": {"attributes": resource_attributes},
                "schemaUrl": profile.schema_url,
                "scopeSpans": [
                    {
                        "scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION},
                        "schemaUrl": profile.schema_url,
                        "spans": spans,
                    }
                ],
            }
        ]
    }
