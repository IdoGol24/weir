"""G1 determinism harness.

Runs a snippet of code twice, once per PYTHONHASHSEED value, and asserts the
captured stdout is byte-identical. This is the repo's one reusable check for
"identical inputs -> byte-identical output" (spec constitution #1, G1) —
later layers (tracegen's --seed emitters, the engine's repeat-run fixture
comparisons) call into this rather than reimplementing subprocess plumbing.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence

DEFAULT_HASH_SEEDS: tuple[str, ...] = ("0", "1")


def run_under_hash_seed(code: str, seed: str) -> bytes:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        check=True,
    )
    return result.stdout


def assert_byte_identical_across_hash_seeds(
    code: str, seeds: Sequence[str] = DEFAULT_HASH_SEEDS
) -> None:
    outputs = {seed: run_under_hash_seed(code, seed) for seed in seeds}
    first_seed, first_output = next(iter(outputs.items()))
    for seed, output in outputs.items():
        if output != first_output:
            raise AssertionError(
                f"G1 violation: output differs across PYTHONHASHSEED values "
                f"({first_seed!r} vs {seed!r}): {first_output!r} != {output!r}"
            )
