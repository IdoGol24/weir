"""The sorted-args invariant: the M4 equivalence requires native payload key
order to equal the order the adapter recovers from the sort_keys=True OTLP
rendering. Plans must therefore author args pre-sorted; the normalization
set stays closed."""

from weir_tracegen.scenarios import SCENARIOS, instantiate


def test_every_scenario_declares_args_with_sorted_keys() -> None:
    for name in SCENARIOS:
        plan = instantiate(name, seed=1)
        for index, step in enumerate(plan.steps):
            if step.args is None:
                continue
            keys = list(step.args)
            assert keys == sorted(keys), (name, index, keys)
