"""Seeded deterministic PRNG (L6).

This is the one file in the repo where importing stdlib `random` is allowed
(see the ruff per-file-ignore for this exact path) - everything here is
driven by an explicit `seed`, never OS entropy or a global unseeded instance.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


class SeededRng:
    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed)

    def randint(self, a: int, b: int) -> int:
        return self._random.randint(a, b)

    def choice(self, seq: Sequence[T]) -> T:
        return self._random.choice(seq)

    def random(self) -> float:
        return self._random.random()
