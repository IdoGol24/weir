from collections.abc import Callable

from weir_tracegen._rng import SeededRng
from weir_tracegen.scenarios import injection_exfil
from weir_tracegen.scenarios._types import JoinSpec, ScenarioSpec, StepSpec

SCENARIOS: dict[str, Callable[[SeededRng], ScenarioSpec]] = {
    "injection-exfil": injection_exfil.build_red,
    "injection-exfil-benign": injection_exfil.build_benign,
}

# Varied counterparts for the multi-run variance dial (spec section 6).
VARIED_SCENARIOS: dict[str, Callable[[SeededRng], ScenarioSpec]] = {
    "injection-exfil": injection_exfil.build_red_varied,
    "injection-exfil-benign": injection_exfil.build_benign_varied,
}

# Per-run seed derivation. Plain arithmetic, never hashing: hash() depends on
# PYTHONHASHSEED and would break G1 byte-identity across runs.
_RUN_SEED_STRIDE = 10_000


def instantiate(name: str, seed: int) -> ScenarioSpec:
    rng = SeededRng(seed)
    return SCENARIOS[name](rng)


def instantiate_varied(name: str, *, seed: int, run: int) -> ScenarioSpec:
    rng = SeededRng(seed * _RUN_SEED_STRIDE + run)
    return VARIED_SCENARIOS[name](rng)


__all__ = [
    "SCENARIOS",
    "VARIED_SCENARIOS",
    "JoinSpec",
    "ScenarioSpec",
    "StepSpec",
    "instantiate",
    "instantiate_varied",
]
