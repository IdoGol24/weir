"""Render the README's hero animation from real CLI output.

The hero is generated, never recorded. It runs `weir scan` against the
committed demo fixture and lays the actual stdout out as an animated SVG
terminal: the command types, the finding appears line by line, the exit code
lands. A GIF or a screenshot starts lying the first time the CLI changes
wording, silently, because nothing checks a binary; this cannot, because
test_demo_svg_drift.py regenerates it and compares bytes.

Animation is pure declarative CSS, which runs when an SVG is loaded through
an <img> tag (scripts do not, which is why none are used). Every line's
timing lives in its own @keyframes rather than in animation-delay, because
delay applies only to the first iteration and the loop would otherwise
collapse into everything appearing at once on the second pass.

No wall clock and no randomness (G1): the same fixture renders the same
bytes forever.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from click.testing import CliRunner

from weir.cli.main import main

_ROOT = Path(__file__).parents[2]
_FIXTURE = "fixtures/injection-exfil.json"

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
_RULE = "#d2a8ff"
_DIM = "#8b949e"
_PATH = "#79c0ff"

# One loop, in seconds. Output lines land fast enough to read as a burst,
# then the whole frame holds long enough to actually be read before repeating.
_CYCLE = 9.0
_TYPE_START = 0.4
_TYPE_RATE = 0.028  # seconds per character
_LINE_GAP = 0.16
_AFTER_CMD = 0.35
_HOLD_END = 8.6


def _scan_output() -> list[str]:
    """The real stdout of `weir scan` on the demo fixture."""
    result = CliRunner().invoke(main, ["scan", str(_ROOT / _FIXTURE)])
    return result.output.rstrip("\n").splitlines()


def _colour(line: str) -> str:
    if "verdict-grade finding" in line:
        return _ALERT
    if line.startswith("finding:"):
        return _RULE
    if "witness path:" in line:
        return _PATH
    return _DIM


def _pct(seconds: float) -> str:
    return f"{seconds / _CYCLE * 100:.2f}".rstrip("0").rstrip(".")


def render_demo_svg() -> str:
    output = _scan_output()
    command = f"weir scan {_FIXTURE}"

    # (prefix, text, colour, is_typed_command)
    rows: list[tuple[str, str, str, bool]] = [("$ ", command, _CMD, True)]
    rows.extend(("", line, _colour(line), False) for line in output)
    rows.append(("$ ", "echo $?", _CMD, True))
    rows.append(("", "1", _ALERT, False))

    widest = max(len(p) + len(t) for p, t, _, _ in rows)
    width = round(_PAD_X * 2 + widest * _CHAR_W)
    height = round(_BAR_H + len(rows) * _LINE_H + _PAD_BOTTOM)

    # Walk the timeline once, assigning each row the moment it appears.
    appears: list[float] = []
    clock = _TYPE_START
    for _prefix, text, _fill, typed in rows:
        appears.append(clock)
        clock += len(text) * _TYPE_RATE + _AFTER_CMD if typed else _LINE_GAP

    css: list[str] = [
        ".r{opacity:0}",
        f".c{{fill:{_PROMPT}}}",
        # Stopping the animations is enough to show the finished frame: every
        # line's base state is the visible one, and an unanimated clip rect
        # sits at full width rather than scaled to zero.
        "@media (prefers-reduced-motion:reduce){"
        ".r{opacity:1;animation:none}.t{animation:none}}",
    ]
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Terminal recording: weir scan reports a verdict-grade finding '
        f'with a witness path, and exits 1">',
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

    parts.append("<defs>" + "".join(clips) + "</defs>")
    parts.append("<style>" + "".join(css) + "</style>")
    parts.append(
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{_FONT}">'
    )
    parts.extend(body)
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"
