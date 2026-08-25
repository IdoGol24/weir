"""Seeded deterministic clock (L6).

Never reads the wall clock - `datetime.datetime.now`/`time.time` are
ruff-banned repo-wide, including here. Timestamps are pure arithmetic from a
fixed base instant plus an explicit step, so two clocks constructed the same
way always produce the same tick sequence.
"""

from __future__ import annotations

import datetime

_BASE_INSTANT = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


class SeededClock:
    def __init__(self, step: datetime.timedelta = datetime.timedelta(seconds=1)) -> None:
        self._step = step
        self._current = _BASE_INSTANT

    def tick(self) -> str:
        timestamp = self._current
        self._current = self._current + self._step
        return timestamp.isoformat().replace("+00:00", "Z")
