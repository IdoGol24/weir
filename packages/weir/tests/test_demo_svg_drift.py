"""The README's hero image is real CLI output, and cannot go stale.

A screenshot is the usual way to show a tool working, and it starts lying the
first time the output changes - silently, because nothing checks a PNG. The
hero here is generated from a live `weir canary judge --sample` run, so this
test regenerates it and compares bytes. Change the report's wording and this
fails, exactly like the README's verified output blocks do.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import unescape

from _harness.demo_svg import render_demo_svg
from click.testing import CliRunner

from weir.cli.main import main

_ASSET = Path(__file__).parents[3] / "docs" / "assets" / "demo.svg"


def test_hero_svg_matches_live_cli_output() -> None:
    assert _ASSET.read_text(encoding="utf-8") == render_demo_svg(), (
        "docs/assets/demo.svg is stale - regenerate it with:\n"
        "  python -c \"from _harness.demo_svg import render_demo_svg; "
        "from pathlib import Path; "
        "Path('docs/assets/demo.svg').write_text(render_demo_svg(), "
        'encoding=\'utf-8\', newline=\'\\n\')"'
    )


def _rows(svg: str) -> list[tuple[str, str | None]]:
    """Each terminal row's text and fill, in order. A prompt "$" is its own
    <text> element; it is folded into the command it precedes."""
    rows: list[tuple[str, str | None]] = []
    prompt = False
    for attrs, text in re.findall(r"<text ([^>]*)>([^<]*)</text>", svg):
        text = unescape(text)
        if text == "$" and 'class="r r' in attrs and " c" in attrs:
            prompt = True
            continue
        fill = re.search(r'fill="([^"]+)"', attrs)
        rows.append((f"$ {text}" if prompt else text, fill.group(1) if fill else None))
        prompt = False
    return rows


def test_the_hero_actually_shows_the_leak() -> None:
    # Guards the failure mode a byte-comparison alone cannot catch: if the
    # renderer silently produced an empty or truncated terminal, the test
    # above would still pass as long as the committed asset were equally
    # wrong. The expectation comes from a fresh CLI run, not from literals.
    result = CliRunner().invoke(main, ["canary", "judge", "--sample"])
    expected = result.output.rstrip("\n").splitlines()
    assert any(line.startswith("LEAK ") for line in expected)
    assert expected[-1] == "result: leak"
    assert result.exit_code == 1

    rows = _rows(_ASSET.read_text(encoding="utf-8"))
    texts = [text for text, _ in rows]
    assert texts[0] == "$ weir canary judge --sample"
    assert texts[-2:] == ["$ echo $?", str(result.exit_code)]

    # Wrapped rows rejoin into exactly the CLI's lines: a continuation row
    # carries the two-space indent the renderer adds.
    output: list[str] = []
    for text in texts[1:-2]:
        if text.startswith("  ") and output:
            output[-1] += " " + text[2:]
        else:
            output.append(text)
    assert output == expected

    fills = dict(rows)
    leak_fill = fills[next(t for t in texts if t.startswith("LEAK "))]
    assert fills["result: leak"] == leak_fill == fills[str(result.exit_code)]
    assert fills[next(t for t in texts if t.startswith("coverage: "))] != leak_fill


def _top_level_rules(css: str) -> list[tuple[str, str]]:
    """The stylesheet's top-level rules in source order, as (prelude, block)."""
    rules: list[tuple[str, str]] = []
    depth = start = 0
    open_at = -1
    for i, ch in enumerate(css):
        if ch == "{":
            if depth == 0:
                open_at = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                rules.append((css[start:open_at].strip(), css[open_at + 1 : i]))
                start = i + 1
    return rules


def _declarations(block: str) -> dict[str, dict[str, str]]:
    """Each selector's declarations inside an at-rule's block."""
    out: dict[str, dict[str, str]] = {}
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", block):
        decls = out.setdefault(selector.strip(), {})
        for decl in filter(str.strip, body.split(";")):
            prop, value = decl.split(":", 1)
            decls[prop.strip()] = value.strip()
    return out


def test_the_hero_is_animated_and_respects_reduced_motion() -> None:
    svg = _ASSET.read_text(encoding="utf-8")
    assert "@keyframes" in svg, "the hero silently became a still image"

    # An animation that loops forever needs a reduced-motion opt-out, and the
    # opt-out has to win the cascade: its .r and .t tie on specificity with
    # every row's .rN and .tN, so it only takes effect if it comes after them.
    (style,) = re.findall(r"<style>(.*?)</style>", svg, flags=re.S)
    rules = _top_level_rules(style)
    reduced = [i for i, (prelude, _) in enumerate(rules) if "prefers-reduced-motion" in prelude]
    assert len(reduced) == 1, "an animation that loops forever needs a reduced-motion opt-out"
    opt_out = _declarations(rules[reduced[0]][1])
    assert opt_out[".r"]["animation"] == opt_out[".t"]["animation"] == "none"
    assert opt_out[".r"]["opacity"] == "1"
    animated = [
        i
        for i, (prelude, block) in enumerate(rules)
        if re.fullmatch(r"\.[rt]\d+", prelude) and "animation:" in block
    ]
    assert animated, "no row carries an animation"
    assert reduced[0] > max(animated), (
        "the reduced-motion rule is overridden by a later per-row animation rule"
    )
    # Every row must land before the frame starts fading out, or the loop
    # restarts before the exit code is ever on screen.
    shows = re.findall(r"@keyframes a\d+\{0%,([\d.]+)%\{opacity:0\}[\d.]+%,([\d.]+)%", svg)
    assert len(shows) == len(_rows(svg))
    assert all(float(at) < float(hold) for at, hold in shows)


def test_the_hero_is_self_contained_and_scriptless() -> None:
    # This file is served to every visitor. Scripts never run in an <img>
    # context anyway, so one appearing here would mean something went wrong,
    # and an external reference would make the hero fail offline or leak a
    # request to a third party.
    svg = _ASSET.read_text(encoding="utf-8")
    assert "<script" not in svg.lower()
    external = [
        url
        for url in re.findall(r"https?://[^\"' >]+", svg)
        if "w3.org/2000/svg" not in url
    ]
    assert not external, f"hero must be self-contained, found: {external}"
