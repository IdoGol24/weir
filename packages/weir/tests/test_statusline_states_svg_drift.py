"""The README's two status lines are real CLI output, and cannot go stale.

docs/assets/statusline-states.svg shows the segment in its two states
beside a stand-in for an existing status line: nothing exposed, and
exposed with counts. Each line is a live `weir statusline --inner` run over
a fake session (statusline_demo.py), so this test regenerates the image and
compares bytes, and checks it shows exactly what those runs print, in the
colours they print it in.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import canary_fixtures as cfx
import pytest
import statusline_demo as demo
import statusline_fixtures as sx

_SVG = "{http://www.w3.org/2000/svg}"


def test_statusline_states_svg_matches_live_cli_output() -> None:
    assert demo.STATES_ASSET.read_text(encoding="utf-8") == demo.render_states(), (
        "docs/assets/statusline-states.svg is stale - regenerate it with:\n"
        "  PYTHONPATH=tests uv run python packages/weir/tests/statusline_demo.py"
    )


@pytest.fixture(scope="module")
def live() -> list[demo.State]:
    """Fresh runs of the real command over the fake sessions."""
    return demo.states()


def _root() -> ET.Element:
    return ET.fromstring(demo.STATES_ASSET.read_bytes())


def test_the_two_states_are_nothing_exposed_and_exposed(live: list[demo.State]) -> None:
    # What each line should say comes from `weir audit` of its session,
    # through the counting rule, never from the segment's own output.
    clean, exposed = live
    assert clean.counts == (0, 0, False)
    assert exposed.counts[0] and exposed.counts[1] and not exposed.counts[2]
    for state in live:
        stand_in = state.line.split("\x1b[0m | ")[0]
        assert "weir" not in stand_in and "\x1b" not in stand_in
        assert state.line == f"{stand_in}\x1b[0m | {sx.segment_for(state.counts, colour=True)}"


def test_the_image_shows_each_line_in_its_colours(live: list[demo.State]) -> None:
    root = _root()
    rows = list(root.iter(f"{_SVG}text"))
    assert len(rows) == len(live) == 2
    for el, state in zip(rows, live, strict=True):
        sx.assert_painted(el, state.line)
    label = root.get("aria-label", "")
    assert all(sx.plain(state.line) in label for state in live)


def test_the_image_holds_no_credential_value(live: list[demo.State]) -> None:
    text = demo.STATES_ASSET.read_text(encoding="utf-8")
    for state in live:
        cfx.assert_value_free(text, state.values)


def test_the_states_image_is_self_contained_and_scriptless() -> None:
    root = _root()
    for el in root.iter():
        assert el.tag.startswith(_SVG), el.tag
        assert el.tag not in (f"{_SVG}script", f"{_SVG}foreignObject", f"{_SVG}style"), el.tag
        for name, value in el.attrib.items():
            assert not name.startswith("on"), name
            assert "href" not in name, (name, value)
            assert not re.search(r"url\(", value), (name, value)
