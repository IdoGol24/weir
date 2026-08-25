"""A rule quoted in a public doc is the rule that ships.

`test_readme_truth.py` pins CLI-output blocks. This pins FILE-content blocks:
a `<!-- verify-file: path -->` marker means the fenced block below it must be
the exact contents of that file. Without it, a quoted rule could drift from
the shipped rule and only a human diff would notice.

Applies to every public markdown doc that carries a marker, not just the
README: CONTRIBUTING.md quotes a rule too, and a contributor guide showing a
rule that no longer exists is worse than one showing none.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[3]
_MARKED_DOCS = ("README.md", "CONTRIBUTING.md")
_BLOCK = re.compile(
    r"<!--\s*verify-file:\s*(?P<path>.+?)\s*-->\s*\n+```(?:[^\n]*)\n(?P<body>.*?)```",
    re.DOTALL,
)


@pytest.mark.parametrize("doc", _MARKED_DOCS)
def test_every_verify_file_block_matches_the_shipped_file(doc: str) -> None:
    text = (_REPO_ROOT / doc).read_text(encoding="utf-8")
    blocks = list(_BLOCK.finditer(text))
    assert blocks, f"expected at least one '<!-- verify-file: ... -->' block in {doc}"
    for block in blocks:
        target = _REPO_ROOT / block.group("path")
        shipped = target.read_text(encoding="utf-8")
        assert block.group("body").strip() == shipped.strip(), (
            f"{doc} block for '{block.group('path')}' is stale.\n"
            f"Shipped file:\n{shipped}"
        )
