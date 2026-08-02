"""G3 no-network harness.

Blocks socket construction for the duration of a test. weir's constitution
(#6) bans network I/O in scan|gauge|test|validate; since `pytest` itself is
`weir test`'s underlying mechanism, the whole suite runs under this block by
default (wired as an autouse fixture in conftest.py), not just a subset of
tests.
"""

from __future__ import annotations

import socket
from collections.abc import Generator
from contextlib import contextmanager

import pytest


class NetworkAccessBlocked(RuntimeError):
    pass


def _blocked(*_args: object, **_kwargs: object) -> None:
    raise NetworkAccessBlocked(
        "G3 violation: network access is never permitted in weir's "
        "scan|gauge|test|validate code paths"
    )


@contextmanager
def block_network(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    yield
