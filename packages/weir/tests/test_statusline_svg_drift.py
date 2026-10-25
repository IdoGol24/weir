"""The README's status line image is real CLI output, and cannot go stale.

docs/assets/statusline.svg is generated from live `weir statusline` runs
over a fake session and the live report `/weir` runs (statusline_demo.py),
so this test regenerates it and compares bytes, and checks the animation
actually shows what those commands print. Change the segment's or the
report's wording and this fails.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import canary_fixtures as cfx
import pytest
import statusline_demo as demo

from weir.statusline.segment import SCANNING


def test_statusline_svg_matches_live_cli_output() -> None:
    assert demo.ASSET.read_text(encoding="utf-8") == demo.render(), (
        "docs/assets/statusline.svg is stale - regenerate it with:\n"
        "  PYTHONPATH=tests uv run python packages/weir/tests/statusline_demo.py"
    )


_SVG = "{http://www.w3.org/2000/svg}"


def _root() -> ET.Element:
    return ET.fromstring(demo.ASSET.read_bytes())


def _classes(el: ET.Element) -> list[str]:
    return el.get("class", "").split()


def _texts(root: ET.Element, cls: str) -> list[ET.Element]:
    """Each <text>, in document order, with a class matching `cls`."""
    return [
        el for el in root.iter(f"{_SVG}text") if any(re.fullmatch(cls, c) for c in _classes(el))
    ]


def _blocks(css: str) -> list[tuple[str, str]]:
    """The top-level `prelude{body}` blocks of `css`, in source order."""
    out: list[tuple[str, str]] = []
    depth = start = open_at = 0
    for i, ch in enumerate(css):
        if ch == "{":
            if depth == 0:
                open_at = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append((css[start:open_at].strip(), css[open_at + 1 : i]))
                start = i + 1
    assert depth == 0 and not css[start:].strip(), "unbalanced or trailing CSS"
    return out


def _declarations(body: str) -> dict[str, str]:
    return dict(
        (prop.strip(), value.strip())
        for prop, value in (d.split(":", 1) for d in body.split(";") if d.strip())
    )


@dataclass(frozen=True)
class _Style:
    # Single-class rules in source order; True marks one inside the
    # reduced-motion block. They all tie on specificity, so order decides.
    rules: list[tuple[bool, str, dict[str, str]]]
    # Each keyframes' stops: the percentages and the declarations at them.
    keyframes: dict[str, list[tuple[list[float], dict[str, str]]]]

    def computed(self, el: ET.Element, *, reduced: bool) -> dict[str, str]:
        classes = _classes(el)
        out: dict[str, str] = {}
        for in_reduced, selector, decls in self.rules:
            if (reduced or not in_reduced) and selector[1:] in classes:
                out.update(decls)
        return out

    def shown(self, el: ET.Element) -> tuple[float, float]:
        """The one window, in percent of the loop, in which the element's
        animation has it visible."""
        name = self.computed(el, reduced=False)["animation"].split()[0]
        timeline = sorted(
            (at, decls.get("opacity")) for stops, decls in self.keyframes[name] for at in stops
        )
        visible = [at for at, opacity in timeline if opacity == "1"]
        on, off = visible[0], visible[-1]
        assert all(opacity == "1" for at, opacity in timeline if on <= at <= off), (
            f"{name} shows more than once a loop"
        )
        return on, off


def _style(root: ET.Element) -> _Style:
    (style,) = (el.text or "" for el in root.iter(f"{_SVG}style"))
    rules: list[tuple[bool, str, dict[str, str]]] = []
    keyframes: dict[str, list[tuple[list[float], dict[str, str]]]] = {}
    media = 0
    for prelude, body in _blocks(style):
        if prelude.startswith("@keyframes "):
            keyframes[prelude.removeprefix("@keyframes ")] = [
                ([float(at.strip().rstrip("%")) for at in stops.split(",")], _declarations(b))
                for stops, b in _blocks(body)
            ]
        elif prelude == "@media (prefers-reduced-motion:reduce)":
            media += 1
            for selector, b in _blocks(body):
                assert re.fullmatch(r"\.[a-z]\w*", selector), selector
                rules.append((True, selector, _declarations(b)))
        else:
            assert re.fullmatch(r"\.[a-z]\w*", prelude), prelude
            rules.append((False, prelude, _declarations(body)))
    assert media == 1, "an animation that loops forever needs one reduced-motion opt-out"
    return _Style(rules, keyframes)


@pytest.fixture(scope="module")
def live() -> demo.Outputs:
    """A fresh run of the real commands over the fake session."""
    return demo.outputs()


def test_the_status_line_scans_then_settles_on_the_counts(live: demo.Outputs) -> None:
    # The expectation comes from a fresh run of the real commands, never
    # from literals: if the renderer dropped a refresh or the asset were
    # truncated, the byte comparison alone would not say which.
    out = live
    assert len(out.frames) >= 2
    assert all(SCANNING in f for f in out.frames[:-1])
    assert SCANNING not in out.frames[-1]
    # The status line and the report's first line are two runs over the
    # same session; they agree.
    assert out.frames[-1] == out.report[0]

    segments = _texts(_root(), r"s\d+")
    assert [el.text for el in segments] == out.frames


def test_the_report_is_shown_whole_and_in_order(live: demo.Outputs) -> None:
    out = live
    rows = _texts(_root(), r"r\d+")
    assert rows[0].text == ">"  # the prompt the command was typed at
    # Wrapped rows hold exactly the report's words, in its order: nothing
    # dropped, nothing added.
    shown = " ".join(el.text or "" for el in rows[1:]).split()
    assert shown == " ".join([demo.COMMAND, *out.report]).split()
    assert any(line.startswith("  sent in a tool call: ") for line in out.report)
    assert any(line.startswith("  entered the context: ") for line in out.report)


def test_the_image_holds_no_credential_value(live: demo.Outputs) -> None:
    cfx.assert_value_free(demo.ASSET.read_text(encoding="utf-8"), live.values)


def test_the_finished_frame_survives_reduced_motion(live: demo.Outputs) -> None:
    root = _root()
    style = _style(root)
    texts = list(root.iter(f"{_SVG}text"))

    # Nothing moves: every animated element has its animation turned off.
    for el in root.iter():
        if "animation" in style.computed(el, reduced=False):
            assert style.computed(el, reduced=True)["animation"] == "none", _classes(el)
    # What stays on screen is the finished frame: the finished counts, the
    # prompt and the whole transcript; the passing segments and the
    # typed-but-not-yet-submitted command are hidden.
    opacity = [style.computed(el, reduced=True).get("opacity") for el in texts]
    assert set(opacity) == {"0", "1"}
    still = [el.text for el, o in zip(texts, opacity, strict=True) if o == "1"]
    hidden = [el.text for el, o in zip(texts, opacity, strict=True) if o == "0"]
    transcript = [el.text for el in _texts(root, r"r\d+")]
    assert still == [live.frames[-1], ">", *transcript]
    assert hidden == [*live.frames[:-1], demo.COMMAND]

    # And the animation reaches that same frame: every element shows
    # before it fades, and the finished frame is on screen all at once.
    shown = {id(el): style.shown(el) for el in texts}
    assert all(on < off for on, off in shown.values())
    finished = [shown[id(el)] for el, o in zip(texts, opacity, strict=True) if o == "1"]
    assert max(on for on, _ in finished) < min(off for _, off in finished)
    # The command is typed out in full before it is submitted.
    (clip,) = (el for el in root.iter(f"{_SVG}rect") if "t" in _classes(el))
    typing = style.keyframes[style.computed(clip, reduced=False)["animation"].split()[0]]
    typed = min(at for stops, d in typing if d.get("transform") == "scaleX(1)" for at in stops)
    (command,) = (el for el in texts if el.text == demo.COMMAND and "x" in _classes(el))
    on, off = shown[id(command)]
    assert on < typed < off


def _local(value: str) -> bool:
    return all(ref.startswith("#") for ref in re.findall(r"url\(([^)]*)\)", value))


def test_the_image_is_self_contained_and_scriptless() -> None:
    # This file is served to every visitor: a script, an event handler or a
    # foreign element would mean something went wrong, and a reference
    # outside the file would make it fail offline or call a third party.
    root = _root()
    for el in root.iter():
        assert el.tag.startswith(_SVG), el.tag
        assert el.tag not in (f"{_SVG}script", f"{_SVG}foreignObject"), el.tag
        for name, value in el.attrib.items():
            assert not name.startswith("on"), name
            assert not name.endswith("href") or value.startswith("#"), (name, value)
            assert _local(value), (name, value)
    for _, _, decls in _style(root).rules:
        assert all(map(_local, decls.values())), decls
