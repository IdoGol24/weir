"""Native Seam-1 emitter (L8, R1.1 path): ScenarioSpec -> validated CanonicalTrace.

The only place scenario steps become schema-valid trace nodes — ids,
source_refs, and timestamps are assigned here, deterministically, from the L6
seeded core. Skips the OTLP path entirely (execution-plan L25-27, out of
scope for this demo slice).
"""

from __future__ import annotations

import msgspec.structs

from weir.schema.trace import (
    SCHEMA_VERSION,
    CanonicalTrace,
    JoinConfidence,
    JoinRecord,
    LlmCallPayload,
    NodeKind,
    Payload,
    ToolCallPayload,
    ToolResultPayload,
    TraceMetadata,
    TraceNode,
    UserInputPayload,
)
from weir_tracegen._clock import SeededClock
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios._types import ScenarioSpec, StepSpec

ADAPTER_NAME = "native"
ADAPTER_VERSION = "0.1.0"
# R1.6: detected framework/version, so the L13 gauge demo has a real
# framework to key its R3.4 remediation line off of. Matches the catalog's
# bundled "langchain" remediation entry (weir.catalog.default).
FRAMEWORK_NAME = "langchain"
FRAMEWORK_VERSION = "0.3"

_KIND_MAP = {
    "user_input": NodeKind.USER_INPUT,
    "tool_call": NodeKind.TOOL_CALL,
    "tool_result": NodeKind.TOOL_RESULT,
    "llm_call": NodeKind.LLM_CALL,
}


def _build_payload(step: StepSpec) -> Payload:
    if step.kind == "tool_call":
        if step.tool_name is None:
            raise ValueError("tool_call step requires tool_name")
        return ToolCallPayload(tool_name=step.tool_name, args=dict(step.args or {}))
    if step.kind == "tool_result":
        return ToolResultPayload(content=step.content or "")
    if step.kind == "llm_call":
        return LlmCallPayload(content=step.content or "")
    if step.kind == "user_input":
        return UserInputPayload(content=step.content or "")
    raise ValueError(f"unknown step kind {step.kind!r}")


def emit_scenario(spec: ScenarioSpec) -> CanonicalTrace:
    clock = SeededClock()
    nodes: list[TraceNode] = []
    source_refs: list[str] = []
    for i, step in enumerate(spec.steps):
        source_ref = f"native-{spec.name}-{i}"
        source_refs.append(source_ref)
        nodes.append(
            TraceNode(
                id=f"n{i}",
                kind=_KIND_MAP[step.kind],
                timestamp=clock.tick(),
                actor=step.actor,
                source_ref=source_ref,
                payload=_build_payload(step),
            )
        )
    joins = [
        JoinRecord(
            tool_call_source_ref=source_refs[j.call_index],
            tool_result_source_ref=source_refs[j.result_index],
            join_confidence=JoinConfidence(j.join_confidence),
        )
        for j in spec.joins
    ]
    return CanonicalTrace(
        schema_version=SCHEMA_VERSION,
        nodes=nodes,
        joins=joins,
        metadata=TraceMetadata(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            framework_name=FRAMEWORK_NAME,
            framework_version=FRAMEWORK_VERSION,
        ),
    )


def emit(name: str, *, seed: int) -> CanonicalTrace:
    return emit_scenario(instantiate(name, seed=seed))


def emit_degraded(name: str, *, seed: int, degrade_tool_call_index: int) -> CanonicalTrace:
    """A generation-parameter variation of `emit`, not a new emitter (per the
    demo-slice doc's L8 notes): strips one tool_call node's args and marks it
    `degraded:true`, simulating a real-world payload-capture gap. Feeds the
    L13 gauge demo's partial-coverage beat."""
    trace = emit(name, seed=seed)
    target = trace.nodes[degrade_tool_call_index]
    if not isinstance(target.payload, ToolCallPayload):
        raise ValueError(
            f"node at index {degrade_tool_call_index} is not a tool_call "
            f"(kind={target.kind!r})"
        )
    degraded_payload = msgspec.structs.replace(target.payload, args={})
    degraded_node = msgspec.structs.replace(target, payload=degraded_payload, degraded=True)
    nodes = list(trace.nodes)
    nodes[degrade_tool_call_index] = degraded_node
    return msgspec.structs.replace(trace, nodes=nodes)
