"""Render the README's hero image from real CLI output.

The hero is generated, never drawn. It runs `weir scan` against the committed
demo fixture and lays the actual stdout out as an SVG terminal, so the image
a visitor sees is the output they will get. A screenshot drifts silently the
moment the CLI changes wording; this cannot, because test_demo_svg_drift.py
regenerates it and compares bytes.

No wall clock and no randomness here (G1): the same fixture renders the same
bytes forever.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from click.testing import CliRunner

from weir.cli.main import main

_ROOT = Path(__file__).parents[2]
_FIXTURE = "fixtures/injection-exfil.json"

# Monospace advance width at font-size 14 is ~8.4px; the rest is chosen to
# leave the longest real output line comfortably inside the frame.
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


def render_demo_svg() -> str:
    output = _scan_output()
    command = f"weir scan {_FIXTURE}"

    rows: list[tuple[str, str, str]] = [("$ ", command, _CMD)]
    rows.extend(("", line, _colour(line)) for line in output)
    rows.append(("$ ", "echo $?", _CMD))
    rows.append(("", "1", _ALERT))

    widest = max(len(prefix) + len(text) for prefix, text, _ in rows)
    width = round(_PAD_X * 2 + widest * _CHAR_W)
    height = round(_BAR_H + len(rows) * _LINE_H + _PAD_BOTTOM)

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Terminal showing weir scan reporting a verdict-grade finding '
        f'and exiting 1">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{_BG}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{_BAR_H - 8:.0f}H0Z" '
        f'fill="{_BAR}"/>',
    ]
    for i, dot in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        parts.append(f'<circle cx="{20 + i * 18}" cy="17" r="6" fill="{dot}"/>')

    parts.append(
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{_FONT}">'
    )
    for row, (prefix, text, fill) in enumerate(rows):
        y = _BAR_H + 16 + row * _LINE_H
        x = _PAD_X
        if prefix:
            parts.append(
                f'<text x="{x:.0f}" y="{y:.0f}" fill="{_PROMPT}">{escape(prefix.strip())}</text>'
            )
            x += len(prefix) * _CHAR_W
        # xml:space keeps the leading indentation of the CLI's detail lines.
        parts.append(
            f'<text x="{x:.0f}" y="{y:.0f}" fill="{fill}" '
            f'xml:space="preserve">{escape(text)}</text>'
        )
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"
