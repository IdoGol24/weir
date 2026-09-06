"""Flatten untrusted text before it reaches a rendered line.

Span names, attribute keys and matched key names come off the wire or out of
a contributed catalog, and every renderer here is line-oriented: one embedded
newline forges a line that reads like weir's own output. `str.isprintable()`
is False for every separator that moves a cursor - \\n \\r \\t \\x0b \\x0c
\\x85 \\u2028 \\u2029 - which is a wider net than any strip set.

At the package root, not under `report/` or `gauge/`: `weir.report.renderer`
already imports `weir.gauge`, so a helper living in either package would make
the other's import circular. This module imports nothing, so both can use it.
"""

from __future__ import annotations


def flatten_untrusted(value: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in value)


def plural(count: int, word: str) -> str:
    """`1 location` / `2 locations`. Inline ternaries got two of six wrong."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"
