"""The actor-from-kind invariant, pinned because the OTel adapter depends on it.

`actor` appears on no OTLP attribute. That is deliberate: stamping a
`weir.actor` attribute would put a weir-internal identifier into a corpus whose
purpose is to imitate third-party telemetry, and a real LangChain trace carries
no such field. Instead the adapter reconstructs `actor` from node kind.

That makes the mapping load-bearing. If a future scenario ever gives a
`tool_result` an `agent` actor, the corpus silently stops being
reconstructible - so this test fails instead.
"""

from weir_tracegen.scenarios import SCENARIOS, VARIED_SCENARIOS, instantiate, instantiate_varied
from weir_tracegen.scenarios._types import ScenarioSpec

# The mapping the adapter is entitled to rely on.
ACTOR_BY_KIND = {
    "llm_call": "agent",
    "tool_call": "agent",
    "tool_result": "tool",
    "user_input": "user",
}


def _all_plans() -> list[ScenarioSpec]:
    plans = [instantiate(name, seed=1) for name in SCENARIOS]
    # The variance dial can add steps, so its output must obey the rule too.
    plans += [
        instantiate_varied(name, seed=1, run=run)
        for name in VARIED_SCENARIOS
        for run in range(5)
    ]
    return plans


def test_actor_is_a_function_of_kind_in_every_scenario() -> None:
    for plan in _all_plans():
        for index, step in enumerate(plan.steps):
            expected = ACTOR_BY_KIND[step.kind]
            assert step.actor == expected, (
                f"{plan.name} step {index}: kind {step.kind!r} carries actor "
                f"{step.actor!r}, breaking the mapping the OTel adapter relies on "
                f"to reconstruct actor (expected {expected!r})"
            )


def test_the_mapping_covers_every_kind_the_scenarios_use() -> None:
    # A kind with no mapping entry would make the adapter's derivation
    # incomplete, which this test would otherwise not notice.
    used = {step.kind for plan in _all_plans() for step in plan.steps}
    assert used <= set(ACTOR_BY_KIND)
    assert used, "no scenarios were instantiated, the test is vacuous"


def test_every_mapped_kind_is_actually_exercised() -> None:
    # Guards the opposite drift: a mapping entry no scenario produces is an
    # untested claim the adapter would still rely on.
    used = {step.kind for plan in _all_plans() for step in plan.steps}
    assert set(ACTOR_BY_KIND) <= used
