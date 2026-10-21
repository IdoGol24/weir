"""What the runner tests' loopback-only socket guard refused (conftest.py)."""

from __future__ import annotations


class LoopbackOnly(RuntimeError):
    """A runner test tried to reach a host other than 127.0.0.1."""


class NetworkLog:
    def __init__(self) -> None:
        self.refused: list[str] = []
