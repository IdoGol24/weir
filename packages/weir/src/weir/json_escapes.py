"""Text with its JSON escapes undone (docs/canary.md, "The decoded view").

JSON lets a writer escape any character, not only the ones a standard
serializer escapes, so a value can sit in JSON text with any of its
characters written `\\uXXXX`. No set of encoded needles covers every such
spelling; matching the text unescaped does.

*Unescaping* replaces each JSON escape (`\\"` `\\\\` `\\/` `\\b` `\\f` `\\n`
`\\r` `\\t`, and `\\uXXXX` in either letter case, a surrogate pair as one
character) by its character and leaves any other backslash as it is: the
rule of the audit's `json` form (docs/audit.md). For a string holding a
JSON document one unescaping gives each of its string leaves and keys
decoded; which text is read this way is the caller's. Text that still holds an
escape is unescaped again, up to a bound; text escaped deeper than the
bound cannot be read in full, and the view says so.

Bytes in, bytes out, so any capture bytes can be read: an escape becomes
its character's UTF-8, a lone surrogate written the way the judge writes
strings (`surrogatepass`), and bytes that are not an escape are kept as
they are.

At the package root, importing only `re` and `dataclasses`: the canary
judge reads its capture through it, and any other part of weir can read
text the same way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# docs/canary.md, "The decoded view": how many times text is unescaped.
LEVELS = 16

_ESCAPE = re.compile(
    rb"\\(?:"
    rb"u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})"  # a surrogate pair
    rb"|u([0-9a-fA-F]{4})"
    rb'|(["\\/bfnrt])'
    rb")"
)
_SHORT = {
    b'"': b'"',
    b"\\": b"\\",
    b"/": b"/",
    b"b": b"\b",
    b"f": b"\f",
    b"n": b"\n",
    b"r": b"\r",
    b"t": b"\t",
}


def _character(found: re.Match[bytes]) -> bytes:
    high, low, code, short = found.groups()
    if high is not None:
        point = 0x10000 + ((int(high, 16) - 0xD800) << 10) + (int(low, 16) - 0xDC00)
        return chr(point).encode("utf-8")
    if code is not None:
        return chr(int(code, 16)).encode("utf-8", errors="surrogatepass")
    return _SHORT[short]


def unescape(data: bytes) -> bytes:
    """`data` with each JSON escape replaced by its character, once.
    Escapes are read left to right in one pass, so `\\\\` is one escaped
    backslash and never starts another escape."""
    return _ESCAPE.sub(_character, data)


@dataclass(frozen=True)
class View:
    """The texts of `data` unescaped once, twice and so on, while one still
    holds an escape. `complete` is False when the last text still holds one
    after the bound: the view stops there and does not hold the rest."""

    texts: tuple[bytes, ...]
    complete: bool


_EMPTY = View((), True)


def decoded_view(data: bytes, levels: int = LEVELS) -> View:
    """`data` unescaped up to `levels` times. Each unescaping makes the text
    shorter, so the view costs at most `levels` times the text's length."""
    texts: list[bytes] = []
    while b"\\" in data:
        decoded = unescape(data)
        # Every escape is at least two bytes and becomes fewer: text that
        # kept its length held none.
        if len(decoded) == len(data):
            break
        if len(texts) == levels:
            return View(tuple(texts), complete=False)
        texts.append(decoded)
        data = decoded
    return View(tuple(texts), complete=True) if texts else _EMPTY
