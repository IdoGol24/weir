import socket

import pytest
from _harness.g3 import NetworkAccessBlocked


def test_socket_construction_is_blocked() -> None:
    with pytest.raises(NetworkAccessBlocked, match="G3 violation"):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_create_connection_is_blocked() -> None:
    with pytest.raises(NetworkAccessBlocked, match="G3 violation"):
        socket.create_connection(("example.invalid", 80))
