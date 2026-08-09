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

# Varied runs live in a disjoint seed space so a varied run can never share an
# RNG stream with an unvaried emission and silently reproduce a gold fixture.
_VARIED_SEED_BASE = 1_000_000_000


def instantiate(name: str, seed: int) -> ScenarioSpec:
    rng = SeededRng(seed)
    return SCENARIOS[name](rng)


def instantiate_varied(name: str, *, seed: int, run: int) -> ScenarioSpec:
    if not 0 <= run < _RUN_SEED_STRIDE:
        raise ValueError(f"run must be in [0, {_RUN_SEED_STRIDE}); got {run}")
    rng = SeededRng(_VARIED_SEED_BASE + seed * _RUN_SEED_STRIDE + run)
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
