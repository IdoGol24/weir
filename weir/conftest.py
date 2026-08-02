import pytest
from _harness.g3 import block_network


@pytest.fixture(autouse=True)
def _g3_no_network(monkeypatch: pytest.MonkeyPatch):
    with block_network(monkeypatch):
        yield
