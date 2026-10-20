"""The encoded forms the judge matches (docs/canary.md, "The encoded forms").

For each value the judge builds needles: byte strings, each one a form of
the value's UTF-8 bytes. Identical needles from different forms are kept
once, under the first form in the contract's table order.
"""

from __future__ import annotations

import base64
import itertools
from collections.abc import Callable

from weir.canary._types import Form

_SHORT_ESCAPES = {"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _u_escape(code: int, upper: bool) -> str:
    return f"\\u{code:04X}" if upper else f"\\u{code:04x}"


def json_escape(
    value: str, *, escape_slash: bool = False, escape_non_ascii: bool = False, upper: bool = False
) -> str:
    """The value as JSON string content.

    The base rule (all flags off) escapes `"` and `\\`, and control
    characters as `\\b \\f \\n \\r \\t` or `\\u00XX`. The flags are the
    contract's variants: `/` written `\\/`, non-ASCII written `\\uXXXX`
    (surrogate pairs above U+FFFF), and uppercase hex in every `\\u` escape.
    """
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == '"' or ch == "\\":
            out.append("\\" + ch)
        elif ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif code < 0x20:
            out.append(_u_escape(code, upper))
        elif ch == "/" and escape_slash:
            out.append("\\/")
        elif code > 0x7F and escape_non_ascii:
            if code > 0xFFFF:
                high = 0xD800 + ((code - 0x10000) >> 10)
                low = 0xDC00 + ((code - 0x10000) & 0x3FF)
                out.append(_u_escape(high, upper) + _u_escape(low, upper))
            else:
                out.append(_u_escape(code, upper))
        else:
            out.append(ch)
    return "".join(out)


def _utf8(text: str) -> bytes:
    # A value is a JSON string, which may hold a lone surrogate.
    return text.encode("utf-8", errors="surrogatepass")


def _json_needles(value: str) -> list[bytes]:
    return [
        _utf8(json_escape(value, escape_slash=s, escape_non_ascii=n, upper=u))
        for s, n, u in itertools.product((False, True), repeat=3)
    ]


def _json2_needles(value: str) -> list[bytes]:
    return [
        _utf8(json_escape(needle.decode("utf-8", errors="surrogatepass")))
        for needle in _json_needles(value)
    ]


def url_encode(
    data: bytes, *, upper: bool = True, keep_slash: bool = False, plus: bool = False
) -> bytes:
    """Percent-encoding of every byte outside `A-Za-z0-9-._~`, with the
    contract's variants: hex case, `/` kept, space as `+`."""
    out = bytearray()
    for byte in data:
        if byte in _UNRESERVED or (keep_slash and byte == 0x2F):
            out.append(byte)
        elif plus and byte == 0x20:
            out.append(0x2B)
        else:
            out += (f"%{byte:02X}" if upper else f"%{byte:02x}").encode("ascii")
    return bytes(out)


def _url_needles(value: str) -> list[bytes]:
    data = _utf8(value)
    return [
        url_encode(data, upper=u, keep_slash=k, plus=p)
        for u, k, p in itertools.product((True, False), repeat=3)
    ]


def base64_cores(data: bytes, encode: Callable[[bytes], bytes]) -> list[bytes]:
    """The base64 cores of `data` at byte offsets 0, 1 and 2.

    For `k` filler bytes followed by the value's `n` bytes, character `i` of
    the encoding is kept when `6i >= 8k` and `6i + 6 <= 8(k + n)`: its 6
    bits all come from the value, so it is the same whatever surrounds it.
    """
    n = len(data)
    cores: list[bytes] = []
    for k in range(3):
        encoded = encode(b"\x00" * k + data)
        first = -(-8 * k // 6)  # ceil(8k / 6)
        last = (8 * (k + n)) // 6  # exclusive: 6i + 6 <= 8(k + n)
        cores.append(encoded[first:last])
    return cores


def _base64_needles(value: str) -> list[bytes]:
    return base64_cores(_utf8(value), base64.b64encode)


def _base64url_needles(value: str) -> list[bytes]:
    return base64_cores(_utf8(value), base64.urlsafe_b64encode)


def _hex_needles(value: str) -> list[bytes]:
    lower = _utf8(value).hex().encode("ascii")
    return [lower, lower.upper()]


_BUILDERS: dict[Form, Callable[[str], list[bytes]]] = {
    Form.RAW: lambda value: [_utf8(value)],
    Form.JSON: _json_needles,
    Form.JSON2: _json2_needles,
    Form.URL: _url_needles,
    Form.BASE64: _base64_needles,
    Form.BASE64URL: _base64url_needles,
    Form.HEX: _hex_needles,
}


def needles(value: str) -> list[tuple[bytes, Form]]:
    """Every needle of `value`, each under the first form that produces it."""
    seen: set[bytes] = set()
    out: list[tuple[bytes, Form]] = []
    for form in Form:
        for needle in _BUILDERS[form](value):
            if needle and needle not in seen:
                seen.add(needle)
                out.append((needle, form))
    return out
