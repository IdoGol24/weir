"""The rule shown in the README is the rule that ships.

`test_readme_truth.py` pins CLI-output blocks. This pins FILE-content blocks:
a `<!-- verify-file: path -->` marker means the fenced block below it must be
the exact contents of that file. Without it, the README's rule could drift
from the shipped rule and only a human diff would notice.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[3]
_BLOCK = re.compile(
    r"<!--\s*verify-file:\s*(?P<path>.+?)\s*-->\s*\n+```(?:[^\n]*)\n(?P<body>.*?)```",
    re.DOTALL,
)


def test_every_verify_file_block_matches_the_shipped_file() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    blocks = list(_BLOCK.finditer(readme))
    assert blocks, "expected at least one '<!-- verify-file: ... -->' block in README.md"
    for block in blocks:
        target = _REPO_ROOT / block.group("path")
        shipped = target.read_text(encoding="utf-8")
        assert block.group("body").strip() == shipped.strip(), (
            f"README.md block for '{block.group('path')}' is stale.\n"
            f"Shipped file:\n{shipped}"
        )
