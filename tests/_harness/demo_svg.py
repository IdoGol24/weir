"""Render the README's hero animation from real CLI output.

The hero is generated, never recorded. It runs `weir canary judge --sample`
(the bundled fake ledger and capture) and lays the actual stdout out as an
animated SVG terminal: the command types, the LEAK, coverage and result lines
appear, the exit code lands. A GIF or a screenshot starts lying the first time the CLI changes
wording, silently, because nothing checks a binary; this cannot, because
test_demo_svg_drift.py regenerates it and compares bytes.

Animation is pure declarative CSS, which runs when an SVG is loaded through
an <img> tag (scripts do not, which is why none are used). Every line's
timing lives in its own @keyframes rather than in animation-delay, because
delay applies only to the first iteration and the loop would otherwise
collapse into everything appearing at once on the second pass.

Output lines wider than the terminal wrap at word boundaries, with a
two-space continuation indent, so the image stays readable at the README's
width instead of shrinking to fit one very long line.

No wall clock and no randomness (G1): the same sample renders the same
bytes forever.
"""

from __future__ import annotations

import textwrap
from xml.sax.saxutils import escape

from click.testing import CliRunner

from weir.cli.main import main

_ARGS = ("canary", "judge", "--sample")
_COLUMNS = 92

_CHAR_W = 8.4
_LINE_H = 21.0
_FONT = 14
_PAD_X = 22.0
_BAR_H = 34.0
_PAD_BOTTOM = 18.0

_BG = "#0d1117"
_BAR = "#161b22"
_PROMPT = "#7ee787"
_CMD = "#e6edf3"
_ALERT = "#ff7b72"
_DIM = "#8b949e"

# One loop, in seconds. Output lines land fast enough to read as a burst,
# then the whole frame holds long enough to actually be read before repeating.
_CYCLE = 6.0
_TYPE_START = 0.4
_TYPE_RATE = 0.028  # seconds per character
_LINE_GAP = 0.16
_AFTER_CMD = 0.35
_HOLD_END = 5.6


def _judge_output() -> tuple[list[str], int]:
    """The real stdout and exit code of `weir canary judge --sample`."""
    result = CliRunner().invoke(main, list(_ARGS))
    return result.output.rstrip("\n").splitlines(), result.exit_code


def _colour(line: str) -> str:
    if line.startswith("LEAK ") or line == "result: leak":
        return _ALERT
    return _DIM


def _wrap(line: str) -> list[str]:
    return textwrap.wrap(
        line,
        width=_COLUMNS,
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def _pct(seconds: float) -> str:
    return f"{seconds / _CYCLE * 100:.2f}".rstrip("0").rstrip(".")


def render_demo_svg() -> str:
    output, exit_code = _judge_output()
    command = "weir " + " ".join(_ARGS)

    # (prefix, text, colour, is_typed_command)
    rows: list[tuple[str, str, str, bool]] = [("$ ", command, _CMD, True)]
    rows.extend(("", part, _colour(line), False) for line in output for part in _wrap(line))
    rows.append(("$ ", "echo $?", _CMD, True))
    rows.append(("", str(exit_code), _ALERT if exit_code else _DIM, False))

    widest = max(len(p) + len(t) for p, t, _, _ in rows)
    width = round(_PAD_X * 2 + widest * _CHAR_W)
    height = round(_BAR_H + len(rows) * _LINE_H + _PAD_BOTTOM)

    # Walk the timeline once, assigning each row the moment it appears.
    appears: list[float] = []
    clock = _TYPE_START
    for _prefix, text, _fill, typed in rows:
        appears.append(clock)
        clock += len(text) * _TYPE_RATE + _AFTER_CMD if typed else _LINE_GAP

    css: list[str] = [".r{opacity:0}", f".c{{fill:{_PROMPT}}}"]
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Terminal recording: weir canary judge --sample reports a planted '
        f'fake key leaked into a trace span, prints its coverage, and exits {exit_code}">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{_BG}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{_BAR_H - 8:.0f}H0Z" '
        f'fill="{_BAR}"/>',
    ]
    for i, dot in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        parts.append(f'<circle cx="{20 + i * 18}" cy="17" r="6" fill="{dot}"/>')

    clips: list[str] = []
    body: list[str] = []
    for idx, ((prefix, text, fill, typed), at) in enumerate(zip(rows, appears, strict=True)):
        y = _BAR_H + 16 + idx * _LINE_H
        x = _PAD_X
        css.append(
            f"@keyframes a{idx}{{0%,{_pct(at)}%{{opacity:0}}"
            f"{_pct(at + 0.01)}%,{_pct(_HOLD_END)}%{{opacity:1}}100%{{opacity:0}}}}"
        )
        css.append(f".r{idx}{{animation:a{idx} {_CYCLE}s infinite}}")

        if prefix:
            body.append(
                f'<text class="r r{idx} c" x="{x:.0f}" y="{y:.0f}">'
                f"{escape(prefix.strip())}</text>"
            )
            x += len(prefix) * _CHAR_W

        if typed:
            # A clip rect scaled left-to-right in character steps is the
            # typing; the text itself never moves.
            span = len(text) * _CHAR_W
            clips.append(
                f'<clipPath id="k{idx}"><rect class="t t{idx}" x="{x:.0f}" '
                f'y="{y - _FONT:.0f}" width="{span:.0f}" height="{_LINE_H:.0f}"/></clipPath>'
            )
            css.append(
                f".t{idx}{{transform-box:view-box;transform-origin:{x:.0f}px 0;"
                f"animation:k{idx} {_CYCLE}s steps({len(text)}) infinite}}"
            )
            css.append(
                f"@keyframes k{idx}{{0%,{_pct(at)}%{{transform:scaleX(0)}}"
                f"{_pct(at + len(text) * _TYPE_RATE)}%,100%{{transform:scaleX(1)}}}}"
            )
            body.append(
                f'<text class="r r{idx}" x="{x:.0f}" y="{y:.0f}" fill="{fill}" '
                f'clip-path="url(#k{idx})" xml:space="preserve">{escape(text)}</text>'
            )
        else:
            body.append(
                f'<text class="r r{idx}" x="{x:.0f}" y="{y:.0f}" fill="{fill}" '
                f'xml:space="preserve">{escape(text)}</text>'
            )

    # Stopping the animations is enough to show the finished frame: every
    # line's base state is the visible one, and an unanimated clip rect sits
    # at full width rather than scaled to zero. This must come last: .r and
    # .t tie on specificity with each row's .rN and .tN, so the later rule
    # wins, and placed first it would be silently overridden by every row.
    css.append(
        "@media (prefers-reduced-motion:reduce){.r{opacity:1;animation:none}.t{animation:none}}"
    )

    parts.append("<defs>" + "".join(clips) + "</defs>")
    parts.append("<style>" + "".join(css) + "</style>")
    parts.append(
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{_FONT}">'
    )
    parts.extend(body)
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"
