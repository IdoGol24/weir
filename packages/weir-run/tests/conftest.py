"""Test harness for the canary runner.

The repository's autouse `_g3_no_network` fixture blocks every socket,
because weir-scan's analysis path may open none. The runner's mock has to
open one, so for these tests the same fixture name is overridden with a
stricter-than-it-looks guard: sockets may bind and connect to 127.0.0.1
only, and name resolution answers only for 127.0.0.1 and localhost. Any
other destination raises, and every attempt is recorded so a test can
assert the mock never tried to reach anything else.

Flows run as subprocesses, outside this guard; the ones in these tests are
synthetic scripts that talk only to the mock.
"""

from __future__ import annotations

import socket
from collections.abc import Generator
from typing import Any

import pytest
from _network import LoopbackOnly, NetworkLog

from weir_run.judge import resolve

LOOPBACK = {"127.0.0.1", "localhost"}


def _host(address: object) -> str:
    if isinstance(address, tuple):
        items: tuple[object, ...] = address  # pyright: ignore[reportUnknownVariableType]
        return str(items[0]) if items else ""
    return str(address)


@pytest.fixture(autouse=True)
def _g3_no_network(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, network_log: NetworkLog
) -> Generator[None]:
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_bind = socket.socket.bind
    real_getaddrinfo = socket.getaddrinfo

    def guard(address: object) -> None:
        host = _host(address)
        if host not in LOOPBACK:
            network_log.refused.append(host)
            raise LoopbackOnly(f"loopback only in runner tests, not {host!r}")

    def connect(self: socket.socket, address: Any) -> None:
        guard(address)
        real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        guard(address)
        return real_connect_ex(self, address)

    def bind(self: socket.socket, address: Any) -> None:
        guard(address)
        real_bind(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        guard((host,))
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "bind", bind)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    yield


@pytest.fixture
def network_log() -> NetworkLog:
    return NetworkLog()


@pytest.fixture
def judge() -> list[str]:
    """The real judge, `weir canary judge` from the workspace's weir-scan,
    found the way the runner finds it: beside this interpreter."""
    return resolve()
