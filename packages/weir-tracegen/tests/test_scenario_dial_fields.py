"""The declarative dial fields on the plan.

A dial is a pure plan-to-plan function; the plan must be able to CARRY a
dial's effect or the dial would have to live inside a renderer.
"""

from weir_tracegen.emitter import emit
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios._types import StepSpec


def test_defaults_preserve_existing_behavior() -> None:
    step = StepSpec(kind="llm_call", actor="agent", content="hi")
    assert step.content_captured is True
    assert step.clock_offset_ns == 0


def test_every_step_of_every_shipped_scenario_defaults_to_undialed() -> None:
    # These defaults are what keep the committed native fixtures byte-identical.
    for name in ("injection-exfil", "injection-exfil-benign"):
        for step in instantiate(name, seed=1).steps:
            assert step.content_captured is True
            assert step.clock_offset_ns == 0


def test_committed_native_fixture_is_unaffected() -> None:
    # Deliberately redundant with the drift test: this fails loudly right here
    # if adding fields changed rendering, rather than in a distant test file.
    trace = emit("injection-exfil", seed=1)
    assert trace.nodes[0].timestamp == "2026-01-01T00:00:00Z"
    assert not any(node.degraded for node in trace.nodes)
