"""Degradation dials: pure functions from plan to dialed plan.

A dial NEVER touches a renderer. Both renderers render the dialed plan blind,
so a dial cannot express anything the plan cannot carry - which is the
accept-side razor enforced structurally rather than by taste. If content-off
were implemented as "the OTLP renderer skips attributes" and separately on the
native side, the architecture would have rebuilt two-conventions-that-happen-
to-agree one level up, where it is hardest to see.

Every dial here is accept-side: its output must remain well-formed under the
target format. `drop_step` therefore refuses to orphan a join target, because
the OTLP rendering parents a tool_result span to its tool_call span and an
absent parent is reject-adjacent. That case belongs to the corrupt corpus.
"""

from __future__ import annotations

import msgspec.structs

from weir_tracegen.scenarios._types import JoinSpec, ScenarioSpec, StepSpec


def _replace_steps(plan: ScenarioSpec, steps: list[StepSpec]) -> ScenarioSpec:
    return msgspec.structs.replace(plan, steps=steps)


def without_content(plan: ScenarioSpec) -> ScenarioSpec:
    """The wild's privacy default: instrumentation captures no payloads."""
    return _replace_steps(
        plan,
        [msgspec.structs.replace(step, content_captured=False) for step in plan.steps],
    )


def without_linkage(plan: ScenarioSpec) -> ScenarioSpec:
    """Drop explicit call/result linkage, forcing a consumer to fall back to
    parent/child nesting. Renders as `gen_ai.tool.call.id` omitted in OTLP and
    as `join_confidence: nested` natively."""
    return msgspec.structs.replace(
        plan,
        joins=[
            msgspec.structs.replace(join, join_confidence="nested") for join in plan.joins
        ],
    )


def with_truncated_content(plan: ScenarioSpec, *, limit: int) -> ScenarioSpec:
    """Payload truncation. A truncated string is still a valid string, so this
    is accept-side."""
    return _replace_steps(
        plan,
        [
            step
            if step.content is None
            else msgspec.structs.replace(step, content=step.content[:limit])
            for step in plan.steps
        ],
    )


def with_clock_skew(plan: ScenarioSpec, *, step_index: int, offset_ns: int) -> ScenarioSpec:
    """Clock skew on one step. Out-of-order timestamps are legal and real.

    The offset must be a whole number of MICROSECONDS. Native timestamps are
    ISO-8601, which carries no finer precision, so a sub-microsecond offset
    would be exact in OTLP and invisible natively - the two renderers would
    then disagree about what the same dialed plan means, which is precisely
    what the one-plan-two-renderers law exists to prevent. A dial neither
    renderer can express identically is not a legal dial.
    """
    if offset_ns % 1000 != 0:
        raise ValueError(
            f"clock offset must be a whole number of microseconds; {offset_ns} ns "
            "is not representable identically by both renderers"
        )
    steps = list(plan.steps)
    steps[step_index] = msgspec.structs.replace(steps[step_index], clock_offset_ns=offset_ns)
    return _replace_steps(plan, steps)


def drop_step(plan: ScenarioSpec, *, index: int) -> ScenarioSpec:
    """Drop one step, modelling a partial export.

    Refuses to drop a step another step is joined FROM, because the OTLP
    rendering parents a tool_result span to its tool_call span: dropping the
    call would leave the result referencing an absent parent, which the
    accept-side invariant forbids.
    """
    for join in plan.joins:
        if join.call_index == index and join.result_index != index:
            raise ValueError(
                f"dropping step {index} would orphan its joined result at "
                f"{join.result_index}; orphaning is a corrupt-corpus item"
            )
    steps = [step for i, step in enumerate(plan.steps) if i != index]

    def _shift(position: int) -> int:
        return position - 1 if position > index else position

    joins = [
        JoinSpec(
            call_index=_shift(join.call_index),
            result_index=_shift(join.result_index),
            join_confidence=join.join_confidence,
        )
        for join in plan.joins
        if index not in (join.call_index, join.result_index)
    ]
    return msgspec.structs.replace(plan, steps=steps, joins=joins)
