"""Render the README's status line animation from real CLI output.

Like demo_svg.py, this is generated, never recorded. The caller runs the
real `weir statusline` over a fake session, once per status line refresh,
and the real `weir statusline report` that `/weir` runs, and hands their
output here. This lays it out as an animated SVG terminal: the bottom line
is the status line, moving through each refresh's segment (the scanning
ones first) to the finished counts; then `/weir` types at the prompt above
it and the report lands in the transcript. Each segment is drawn in the
colours its ANSI SGR codes name. render_states_svg draws the segment's two
states as two status lines, for the top of the README.
test_statusline_svg_drift.py and test_statusline_states_svg_drift.py
regenerate both and compare bytes, so they cannot go stale silently.

The status line is drawn as a plain terminal bottom line, not as any
product's chrome. Animation is declarative CSS only, which runs in an <img>
tag; every element's timing lives in its own @keyframes for the reason
demo_svg.py gives. No wall clock and no randomness (G1).
"""

from __future__ import annotations

import re
import textwrap
from collections.abc import Sequence
from xml.sax.saxutils import escape

_COLUMNS = 106

_CHAR_W = 8.4
_LINE_H = 21.0
_FONT = 14
_PAD_X = 22.0
_BAR_H = 34.0
_STATUS_H = 32.0
_PAD_BOTTOM = 10.0

_BG = "#0d1117"
_BAR = "#161b22"
_RULE = "#30363d"
_PROMPT = "#7ee787"
_CMD = "#e6edf3"
_ALERT = "#ff7b72"
_DIM = "#8b949e"
# The fill of each SGR code the segment prints (docs/statusline.md,
# "Colours"), and of a part it leaves in the terminal's own colour.
SGR_FILLS = {32: "#3fb950", 33: "#d29922", 31: _ALERT, 2: _DIM}
TEXT_FILL = _CMD
_PAINTED = re.compile(r"\x1b\[0m|\x1b\[(\d+)m([^\x1b]*)\x1b\[0m|([^\x1b]+)")

# One loop, in seconds: the status line refreshes and settles, /weir types
# and its report bursts in, then the whole frame holds long enough to be read.
_CYCLE = 9.0
_FIRST_FRAME = 0.3
_FRAME_GAP = 0.7
_AFTER_COUNTS = 0.6
_TYPE_RATE = 0.06  # seconds per character
_AFTER_CMD = 0.35
_LINE_GAP = 0.07
_HOLD_END = 8.4


def _pct(seconds: float) -> str:
    return f"{seconds / _CYCLE * 100:.2f}".rstrip("0").rstrip(".")


def _shown(at: float, until: float) -> str:
    """A keyframes body: hidden, then visible from `at` to `until`, then hidden."""
    return (
        f"0%,{_pct(at)}%{{opacity:0}}{_pct(at + 0.01)}%,{_pct(until)}%{{opacity:1}}"
        f"{_pct(until + 0.01)}%,100%{{opacity:0}}"
    )


def _parts(line: str) -> list[tuple[str, str]]:
    """A segment's parts: each one's text and fill."""
    parts = [
        (m[2], SGR_FILLS[int(m[1])]) if m[1] else (m[3], TEXT_FILL)
        for m in _PAINTED.finditer(line) if m[1] or m[3]
    ]
    assert "\x1b" not in "".join(text for text, _ in parts), f"an SGR code not drawn: {line!r}"
    return parts


def _plain(line: str) -> str:
    return "".join(text for text, _ in _parts(line))


def _painted(x: float, y: float, line: str, cls: str = "") -> str:
    """A <text> of `line`, one <tspan> per part in its colour."""
    spans = "".join(f'<tspan fill="{fill}">{escape(text)}</tspan>' for text, fill in _parts(line))
    attr = f'class="{cls}" ' if cls else ""
    return f'<text {attr}x="{x:.0f}" y="{y:.0f}" xml:space="preserve">{spans}</text>'


def _wrap(line: str) -> list[str]:
    """A long line wraps at word boundaries, continuing two spaces deeper
    than it starts."""
    if not line:
        return [""]
    indent = line[: len(line) - len(line.lstrip(" "))]
    return textwrap.wrap(
        line,
        width=_COLUMNS,
        subsequent_indent=indent + "  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def _colours(report: Sequence[str]) -> list[str]:
    """The segment line stands out, a credential's heading (an unindented
    line its indented details follow) is bright, the rest is dim."""
    out: list[str] = []
    for i, line in enumerate(report):
        following = report[i + 1] if i + 1 < len(report) else ""
        if i == 0:
            out.append(_ALERT)
        elif line and not line.startswith(" ") and following.startswith("  "):
            out.append(_CMD)
        else:
            out.append(_DIM)
    return out


def render_statusline_svg(frames: Sequence[str], command: str, report: Sequence[str]) -> str:
    """`frames` are the status line's successive segments, the last one the
    finished counts; `command` is what is typed at the prompt; `report` is
    the lines it prints."""
    # The transcript: the submitted command, then the report.
    rows: list[tuple[str, str, str]] = [("> ", command, _CMD)]
    for line, fill in zip(report, _colours(report), strict=True):
        rows.extend(("", part, fill) for part in _wrap(line))

    widest = max(len(p) + len(t) for p, t, _ in rows)
    widest = max([widest, *(len(_plain(f)) for f in frames)])
    width = round(_PAD_X * 2 + widest * _CHAR_W)
    first_y = _BAR_H + 26
    # The prompt sits in its own band between a rule and the status line.
    rule_y = first_y + (len(rows) - 1) * _LINE_H + 14
    prompt_y = rule_y + 24
    status_y = rule_y + 38
    height = round(status_y + _STATUS_H + _PAD_BOTTOM)

    css: list[str] = [".r{opacity:0}", f".c{{fill:{_PROMPT}}}"]
    body: list[str] = []

    def text(cls: str, x: float, y: float, fill: str, content: str) -> None:
        body.append(
            f'<text class="{cls}" x="{x:.0f}" y="{y:.0f}" fill="{fill}" '
            f'xml:space="preserve">{escape(content)}</text>'
        )

    # The status line: each refresh's segment in the same place, one at a
    # time; the finished counts stay until the frame fades.
    frame_y = status_y + _STATUS_H / 2 + 5
    for i, segment in enumerate(frames):
        at = _FIRST_FRAME + i * _FRAME_GAP
        last = i == len(frames) - 1
        until = _HOLD_END if last else at + _FRAME_GAP - 0.01
        css.append(f"@keyframes s{i}{{{_shown(at, until)}}}")
        css.append(f".s{i}{{animation:s{i} {_CYCLE}s infinite}}")
        body.append(_painted(_PAD_X, frame_y, segment, f"r s{i}" + ("" if last else " x")))

    # The prompt, and the command typing into it: a clip rect scaled
    # left-to-right in character steps, as in demo_svg.py. On submit the
    # command leaves the prompt for the transcript.
    typed_at = _FIRST_FRAME + (len(frames) - 1) * _FRAME_GAP + _AFTER_COUNTS
    typed_end = typed_at + len(command) * _TYPE_RATE
    submit = typed_end + _AFTER_CMD
    cmd_x = _PAD_X + 2 * _CHAR_W
    css.append(f"@keyframes p{{{_shown(0, _HOLD_END)}}}")
    css.append(f".p{{animation:p {_CYCLE}s infinite}}")
    css.append(f"@keyframes q{{{_shown(typed_at, submit)}}}")
    css.append(f".q{{animation:q {_CYCLE}s infinite}}")
    body.append(f'<text class="r p c" x="{_PAD_X:.0f}" y="{prompt_y:.0f}">&gt;</text>')
    clip = (
        f'<clipPath id="k"><rect class="t" x="{cmd_x:.0f}" y="{prompt_y - _FONT:.0f}" '
        f'width="{len(command) * _CHAR_W:.0f}" height="{_LINE_H:.0f}"/></clipPath>'
    )
    css.append(
        f".t{{transform-box:view-box;transform-origin:{cmd_x:.0f}px 0;"
        f"animation:k {_CYCLE}s steps({len(command)}) infinite}}"
    )
    css.append(
        f"@keyframes k{{0%,{_pct(typed_at)}%{{transform:scaleX(0)}}"
        f"{_pct(typed_end)}%,100%{{transform:scaleX(1)}}}}"
    )
    body.append(
        f'<text class="r q x" x="{cmd_x:.0f}" y="{prompt_y:.0f}" fill="{_CMD}" '
        f'clip-path="url(#k)" xml:space="preserve">{escape(command)}</text>'
    )

    # The transcript, a burst of lines from the submit on.
    clock = submit
    for idx, (prefix, content, fill) in enumerate(rows):
        y = first_y + idx * _LINE_H
        x = _PAD_X
        css.append(f"@keyframes a{idx}{{{_shown(clock, _HOLD_END)}}}")
        css.append(f".r{idx}{{animation:a{idx} {_CYCLE}s infinite}}")
        if prefix:
            body.append(
                f'<text class="r r{idx} c" x="{x:.0f}" y="{y:.0f}">{escape(prefix.strip())}</text>'
            )
            x += len(prefix) * _CHAR_W
        text(f"r r{idx}", x, y, fill, content)
        clock += _LINE_GAP

    # Reduced motion shows the finished frame: the whole transcript and the
    # finished counts, with the passing segments and the typed-but-not-yet-
    # submitted command hidden. This must come last so it wins the
    # specificity ties with each element's own rule, and .x after .r.
    css.append(
        "@media (prefers-reduced-motion:reduce)"
        "{.r{opacity:1;animation:none}.x{opacity:0}.t{animation:none}}"
    )

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Terminal recording: the status line scans a fake session and settles '
        f"on {escape(_plain(frames[-1]))}, then {escape(command)} lists each credential, where it "
        f'came from, the turn and tool call that moved it, where it sits now and what to do">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{_BG}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{_BAR_H - 8:.0f}H0Z" '
        f'fill="{_BAR}"/>',
    ]
    for i, dot in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        parts.append(f'<circle cx="{20 + i * 18}" cy="17" r="6" fill="{dot}"/>')
    parts.append(f'<path d="M0 {rule_y:.0f}H{width}" stroke="{_RULE}"/>')
    parts.append(
        f'<rect y="{status_y:.0f}" width="{width}" height="{_STATUS_H:.0f}" fill="{_BAR}"/>'
    )
    parts.append("<defs>" + clip + "</defs>")
    parts.append("<style>" + "".join(css) + "</style>")
    parts.append(
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{_FONT}">'
    )
    parts.extend(body)
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"


def render_states_svg(lines: Sequence[str]) -> str:
    """`lines` are status lines, each the real output of the segment beside
    an existing status line; one bar each, as a terminal's bottom line."""
    gap = 10.0
    widest = max(len(_plain(line)) for line in lines)
    width = round(_PAD_X * 2 + widest * _CHAR_W)
    height = round(gap * 2 + len(lines) * _STATUS_H + (len(lines) - 1) * gap)
    label = "Status lines, the weir segment beside an existing one: " + "; and ".join(
        _plain(line) for line in lines
    )
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{escape(label)}">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{_BG}"/>',
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{_FONT}">',
    ]
    for i, line in enumerate(lines):
        top = gap + i * (_STATUS_H + gap)
        parts.append(
            f'<rect x="{gap:.0f}" y="{top:.0f}" width="{width - 2 * gap:.0f}" '
            f'height="{_STATUS_H:.0f}" rx="4" fill="{_BAR}"/>'
        )
        parts.append(_painted(_PAD_X, top + _STATUS_H / 2 + 5, line))
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"
