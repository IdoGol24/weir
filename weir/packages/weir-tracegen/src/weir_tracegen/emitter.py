"""Native Seam-1 emitter (L8, R1.1 path): ScenarioSpec -> validated CanonicalTrace.

The only place scenario steps become schema-valid trace nodes - ids,
source_refs, and timestamps are assigned here, deterministically, from the L6
seeded core. Skips the OTLP path entirely (execution-plan L25-27, out of
scope for this demo slice).
"""

from __future__ import annotations

import datetime

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
from weir_tracegen.scenarios import instantiate, instantiate_varied
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


def step_source_ref(scenario_name: str, index: int) -> str:
    """The ONE step-identity function. Both renderers derive their ids from it
    (the OTLP renderer hashes it into a span id), so native `source_ref`s and
    OTLP span ids cannot drift into two conventions that happen to agree."""
    return f"native-{scenario_name}-{index}"


def _build_payload(step: StepSpec) -> Payload:
    captured = step.content_captured
    if step.kind == "tool_call":
        if step.tool_name is None:
            raise ValueError("tool_call step requires tool_name")
        args = dict(step.args or {}) if captured else {}
        return ToolCallPayload(tool_name=step.tool_name, args=args)
    content = (step.content or "") if captured else ""
    if step.kind == "tool_result":
        return ToolResultPayload(content=content)
    if step.kind == "llm_call":
        return LlmCallPayload(content=content)
    if step.kind == "user_input":
        return UserInputPayload(content=content)
    raise ValueError(f"unknown step kind {step.kind!r}")


def _offset_iso(timestamp: str, offset_ns: int) -> str:
    """Apply a plan-declared clock offset to a seeded timestamp. Pure
    arithmetic on the parsed instant; never reads a wall clock.

    `offset_ns` is guaranteed a whole number of microseconds by
    `dials.with_clock_skew`, so this division is exact rather than lossy.
    """
    if offset_ns == 0:
        return timestamp
    if offset_ns % 1000 != 0:
        raise ValueError(f"clock offset {offset_ns} ns is not a whole microsecond")
    instant = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    shifted = instant + datetime.timedelta(microseconds=offset_ns // 1000)
    return shifted.isoformat().replace("+00:00", "Z")


def emit_scenario(spec: ScenarioSpec) -> CanonicalTrace:
    clock = SeededClock()
    nodes: list[TraceNode] = []
    source_refs: list[str] = []
    for i, step in enumerate(spec.steps):
        source_ref = step_source_ref(spec.name, i)
        source_refs.append(source_ref)
        nodes.append(
            TraceNode(
                id=f"n{i}",
                kind=_KIND_MAP[step.kind],
                timestamp=_offset_iso(clock.tick(), step.clock_offset_ns),
                actor=step.actor,
                source_ref=source_ref,
                payload=_build_payload(step),
                degraded=not step.content_captured,
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


def emit_run(name: str, *, seed: int, run: int) -> CanonicalTrace:
    """One run of the multi-run variance dial: the same scenario with seeded
    benign variance in wording and step count. Feeds baseline capture
    (N runs) and the too-strict fixture family (spec sections 3 and 6)."""
    return emit_scenario(instantiate_varied(name, seed=seed, run=run))


def _degrade_node(trace: CanonicalTrace, index: int) -> CanonicalTrace:
    target = trace.nodes[index]
    if not isinstance(target.payload, ToolCallPayload):
        raise ValueError(f"node at index {index} is not a tool_call (kind={target.kind!r})")
    degraded_payload = msgspec.structs.replace(target.payload, args={})
    degraded_node = msgspec.structs.replace(target, payload=degraded_payload, degraded=True)
    nodes = list(trace.nodes)
    nodes[index] = degraded_node
    return msgspec.structs.replace(trace, nodes=nodes)


def emit_degraded(
    name: str, *, seed: int, degrade_tool_call_indices: list[int]
) -> CanonicalTrace:
    """A generation-parameter variation of `emit`, not a new emitter (per the
    demo-slice doc's L8 notes): strips the given tool_call nodes' args and
    marks them `degraded:true`, simulating a real-world payload-capture gap.
    Feeds the L13 gauge demo's partial-coverage beat - kept as its own
    dedicated fixture, never the red/green scan pair, so the coverage
    number and the finding/no-finding contrast don't collide (see
    injection_exfil.py's module docstring)."""
    trace = emit(name, seed=seed)
    for index in degrade_tool_call_indices:
        trace = _degrade_node(trace, index)
    return trace
