"""Drift check: hatchling needs README.md inside the project dir (packages/weir),
so we keep a copy there. This test pins that copy byte-for-byte to the real
weir-root README.md, the one source of truth."""

from __future__ import annotations

from pathlib import Path

_PACKAGED = Path(__file__).parents[1] / "README.md"
_ROOT = Path(__file__).parents[3] / "README.md"


def test_packaged_readme_matches_root_readme() -> None:
    assert _PACKAGED.read_bytes() == _ROOT.read_bytes()
