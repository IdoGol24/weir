"""M4's acceptance mechanism (spec section 7.1, M3 design section 8):

    adapt_otlp(render_otlp(plan)) == emit_scenario(plan)

after normalizing EXACTLY {adapter_name, adapter_version, source_ref,
join_source, weir.* resource attrs}. Nothing else may be normalized - the
point of the test is that everything outside that set matches, byte for
byte, per scenario per dial."""

import hashlib
import json
from collections.abc import Iterator

import msgspec.structs
import pytest

from weir.adapters.otel import adapt_otlp
from weir.schema.trace import CanonicalTrace, encode_canonical_trace
from weir_tracegen.emitter import emit_scenario, step_source_ref
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import ScenarioSpec, instantiate
from weir_tracegen.scenarios.dials import (
    drop_step,
    with_clock_skew,
    with_flat_linkage,
    with_truncated_content,
)
from weir_tracegen.scenarios.presets import apply_preset

_SCENARIOS = ("injection-exfil", "injection-exfil-benign")
_PRESETS = ("full", "partial", "default-realistic")

_NORM = "\x00norm"


def _otlp_span_id(scenario: str, index: int) -> str:
    return hashlib.sha256(
        step_source_ref(scenario, index).encode("utf-8")
    ).hexdigest()[:16]


def _normalized(trace: CanonicalTrace, *, scenario: str) -> bytes:
    """Map native source_refs to the ids the OTLP renderer derives from the
    SAME identity helper, blank the adapter provenance, drop join_source."""
    ref_map = {
        step_source_ref(scenario, i): _otlp_span_id(scenario, i)
        for i in range(64)
    }
    nodes = [
        msgspec.structs.replace(n, source_ref=ref_map.get(n.source_ref, n.source_ref))
        for n in trace.nodes
    ]
    joins = [
        msgspec.structs.replace(
            j,
            tool_call_source_ref=ref_map.get(
                j.tool_call_source_ref, j.tool_call_source_ref),
            tool_result_source_ref=ref_map.get(
                j.tool_result_source_ref, j.tool_result_source_ref),
            join_source=None,
        )
        for j in trace.joins
    ]
    metadata = msgspec.structs.replace(
        trace.metadata, adapter_name=_NORM, adapter_version=_NORM
    )
    return encode_canonical_trace(
        msgspec.structs.replace(trace, nodes=nodes, joins=joins, metadata=metadata)
    )


def _case_id(scenario: str, preset: str, dial_name: str) -> str:
    return f"{scenario}/{preset}/{dial_name}"


def _dials(plan: ScenarioSpec) -> Iterator[tuple[str, ScenarioSpec]]:
    yield "none", plan
    yield "truncated", with_truncated_content(plan, limit=24)
    # Non-reordering skew: +500 microseconds keeps the temporal order, so
    # byte equality holds. Reordering skew is covered by the adapter's
    # order-independence test (tests/test_adapter_assembly.py), where the
    # comparison target is itself, not the native emitter.
    yield "skew", with_clock_skew(plan, step_index=1, offset_ns=500_000)


_CASES = [
    (s, p, d)
    for s in _SCENARIOS
    for p in _PRESETS
    for d in ("none", "truncated", "skew")
]


@pytest.mark.parametrize(
    "scenario,preset,dial_name", _CASES,
    ids=[_case_id(*c) for c in _CASES],
)
def test_equivalence_per_scenario_per_preset_per_dial(
    scenario: str, preset: str, dial_name: str
) -> None:
    plan = apply_preset(instantiate(scenario, seed=1), preset)
    dialed = dict(_dials(plan))[dial_name]
    native = emit_scenario(dialed)
    adapted = adapt_otlp(
        json.dumps(render_otlp(dialed, preset=preset)).encode()
    ).trace
    assert _normalized(adapted, scenario=scenario) == _normalized(
        native, scenario=scenario
    )


def test_equivalence_flat_linkage_dial() -> None:
    for scenario in _SCENARIOS:
        dialed = with_flat_linkage(instantiate(scenario, seed=1))
        native = emit_scenario(dialed)
        adapted = adapt_otlp(
            json.dumps(render_otlp(dialed, preset="full")).encode()
        ).trace
        assert _normalized(adapted, scenario=scenario) == _normalized(
            native, scenario=scenario
        )


def test_equivalence_drop_step_dial() -> None:
    # Drop a step no join depends on (a non-joined step; find one by
    # inspecting the plan rather than hardcoding an index).
    plan = instantiate("injection-exfil", seed=1)
    joined = {j.call_index for j in plan.joins} | {j.result_index for j in plan.joins}
    index = next(i for i in range(len(plan.steps)) if i not in joined)
    dialed = drop_step(plan, index=index)
    native = emit_scenario(dialed)
    adapted = adapt_otlp(
        json.dumps(render_otlp(dialed, preset="full")).encode()
    ).trace
    assert _normalized(adapted, scenario="injection-exfil") == _normalized(
        native, scenario="injection-exfil"
    )
