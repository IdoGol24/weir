from collections.abc import Callable

from weir_tracegen._rng import SeededRng
from weir_tracegen.scenarios import injection_exfil
from weir_tracegen.scenarios._types import JoinSpec, ScenarioSpec, StepSpec

SCENARIOS: dict[str, Callable[[SeededRng], ScenarioSpec]] = {
    "injection-exfil": injection_exfil.build_red,
    "injection-exfil-benign": injection_exfil.build_benign,
}


def instantiate(name: str, seed: int) -> ScenarioSpec:
    rng = SeededRng(seed)
    return SCENARIOS[name](rng)


__all__ = ["SCENARIOS", "JoinSpec", "ScenarioSpec", "StepSpec", "instantiate"]
