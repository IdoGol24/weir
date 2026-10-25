"""README-truth: every ``<!-- verify: ... -->`` block is pinned to real CLI output.

Each marker holds the CLI args (everything after ``weir ``); the fenced block right
after it must equal that command's real stdout, byte for byte. This is not a copy of
the docs' prose - it re-invokes the CLI and diffs against what actually comes out,
so a stale block fails here instead of lying to readers. The README carries no
output block today; the sample's report is in docs/canary.md, which must keep one.
"""

import re
import shlex
from pathlib import Path

import pytest
from click.testing import CliRunner

from weir.cli.main import main

_ROOT = Path(__file__).parents[3]
_DOCS = ("README.md", "docs/canary.md")
_MUST_VERIFY = "docs/canary.md"

_PAIR_RE = re.compile(
    r"<!--\s*verify:\s*(?P<marker>.+?)\s*-->\s*\n+```(?:[^\n]*)\n(?P<body>.*?)```",
    re.DOTALL,
)


def _find_pairs(doc: str) -> list[tuple[str, str]]:
    text = (_ROOT / doc).read_text(encoding="utf-8")
    return [(m.group("marker"), m.group("body")) for m in _PAIR_RE.finditer(text)]


@pytest.mark.parametrize("doc", _DOCS)
def test_every_verified_block_matches_real_cli_output(doc: str) -> None:
    pairs = _find_pairs(doc)
    if doc == _MUST_VERIFY:
        assert len(pairs) >= 1, (
            f"expected >= 1 '<!-- verify: ... -->' block in {doc}, found "
            f"{len(pairs)} - the marker convention may have silently died"
        )

    runner = CliRunner()
    for marker, fence_body in pairs:
        args = shlex.split(marker)
        resolved_args = []
        for arg in args:
            if not arg.startswith("-") and (_ROOT / arg).exists():
                resolved_args.append(str(_ROOT / arg))
            else:
                resolved_args.append(arg)

        result = runner.invoke(main, resolved_args)
        expected = fence_body.rstrip("\n")
        actual = result.output.rstrip("\n")
        assert actual == expected, (
            f"{doc} block for '<!-- verify: {marker} -->' is stale.\n"
            f"--- expected (README fence) ---\n{expected}\n"
            f"--- actual (live CLI output) ---\n{actual}"
        )
