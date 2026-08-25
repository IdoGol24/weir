"""The README's hero image is real CLI output, and cannot go stale.

A screenshot is the usual way to show a tool working, and it starts lying the
first time the output changes - silently, because nothing checks a PNG. The
hero here is generated from a live `weir scan` run, so this test regenerates
it and compares bytes. Change the finding block's wording and this fails,
exactly like the README's verified output blocks do.
"""

from __future__ import annotations

from pathlib import Path

from _harness.demo_svg import render_demo_svg

_ASSET = Path(__file__).parents[3] / "docs" / "assets" / "demo.svg"


def test_hero_svg_matches_live_cli_output() -> None:
    assert _ASSET.read_text(encoding="utf-8") == render_demo_svg(), (
        "docs/assets/demo.svg is stale - regenerate it with:\n"
        "  python -c \"from _harness.demo_svg import render_demo_svg; "
        "from pathlib import Path; "
        "Path('docs/assets/demo.svg').write_text(render_demo_svg(), "
        'encoding=\'utf-8\', newline=\'\\n\')"'
    )


def test_the_hero_actually_shows_a_finding() -> None:
    # Guards the failure mode a byte-comparison alone cannot catch: if the
    # renderer silently produced an empty terminal, the test above would
    # still pass as long as the committed asset were equally empty.
    svg = _ASSET.read_text(encoding="utf-8")
    assert "verdict-grade finding" in svg
    assert "witness path" in svg
    assert "weir scan" in svg
