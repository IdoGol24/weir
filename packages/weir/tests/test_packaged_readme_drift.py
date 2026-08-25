"""Drift check: hatchling needs README.md inside the project dir (packages/weir),
so we keep a copy there. This test pins that copy byte-for-byte to the real
weir-root README.md, the one source of truth."""

from __future__ import annotations

from pathlib import Path

_PACKAGED = Path(__file__).parents[1] / "README.md"
_ROOT = Path(__file__).parents[3] / "README.md"


def test_packaged_readme_matches_root_readme() -> None:
    # The failure this guards against is always the same one: someone edits
    # README.md and not its packaged twin. A bare byte-index mismatch costs a
    # CI round trip to diagnose, so say the fix instead of only the symptom.
    assert _PACKAGED.read_bytes() == _ROOT.read_bytes(), (
        "packages/weir/README.md is out of sync with README.md.\n"
        "The packaged copy is the PyPI long description and hatchling needs it\n"
        "inside the project directory, so the two are kept byte-identical.\n"
        "Edit README.md, never the copy, then run:\n"
        "    cp README.md packages/weir/README.md"
    )
