"""The encoded forms of a value (docs/canary.md, "The encoded forms").

The runner needs the judge's needles twice: the mock decides whether a
credential field it received holds a ledger value, and relayed flow output
is redacted before anyone sees it. The judge lives in weir-scan and the
runner never imports weir, so the forms are built here from the contract
text. Where the contract lists variants, every variant is a needle.
"""

from __future__ import annotations

import base64
import itertools

FORMS = ("raw", "json", "json2", "url", "base64", "base64url", "hex")

_SHORT_ESCAPES = {0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}
_URL_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _u_escape(code: int, upper: bool) -> str:
    return f"\\u{code:04X}" if upper else f"\\u{code:04x}"


def json_escape(
    value: str,
    *,
    escape_slash: bool = False,
    escape_non_ascii: bool = False,
    upper_hex: bool = False,
    short_controls: bool = True,
) -> str:
    """The value as JSON string content, under one variant of the contract."""
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "/" and escape_slash:
            out.append("\\/")
        elif code < 0x20:
            if short_controls and code in _SHORT_ESCAPES:
                out.append(_SHORT_ESCAPES[code])
            else:
                out.append(_u_escape(code, upper_hex))
        elif code > 0x7F and escape_non_ascii:
            if code > 0xFFFF:
                code -= 0x10000
                out.append(_u_escape(0xD800 + (code >> 10), upper_hex))
                out.append(_u_escape(0xDC00 + (code & 0x3FF), upper_hex))
            else:
                out.append(_u_escape(code, upper_hex))
        else:
            out.append(ch)
    return "".join(out)


def _json_variants(value: str) -> list[str]:
    return [
        json_escape(
            value,
            escape_slash=slash,
            escape_non_ascii=non_ascii,
            upper_hex=upper,
            short_controls=short,
        )
        for slash, non_ascii, upper, short in itertools.product((False, True), repeat=4)
    ]


def url_encode(data: bytes, *, upper_hex: bool, encode_slash: bool, plus_space: bool) -> str:
    out: list[str] = []
    for b in data:
        if b in _URL_UNRESERVED or (b == 0x2F and not encode_slash):
            out.append(chr(b))
        elif b == 0x20 and plus_space:
            out.append("+")
        else:
            out.append(f"%{b:02X}" if upper_hex else f"%{b:02x}")
    return "".join(out)


def base64_cores(data: bytes, *, urlsafe: bool) -> list[bytes]:
    """The value's base64 characters that do not depend on its neighbours,
    at byte offsets 0, 1 and 2 (the contract's "base64 core")."""
    n = len(data)
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    cores: list[bytes] = []
    for k in (0, 1, 2):
        encoded = encode(b"\x00" * k + data)
        kept = bytes(
            encoded[i] for i in range(len(encoded)) if 6 * i >= 8 * k and 6 * i + 6 <= 8 * (k + n)
        )
        cores.append(kept)
    return cores


def needles(value: str) -> list[tuple[str, bytes]]:
    """Every (form, needle) of value, first form wins on duplicates."""
    data = value.encode("utf-8")
    json_needles = [v.encode("utf-8") for v in _json_variants(value)]
    candidates: list[tuple[str, bytes]] = [("raw", data)]
    candidates += [("json", n) for n in json_needles]
    candidates += [("json2", json_escape(n.decode("utf-8")).encode("utf-8")) for n in json_needles]
    candidates += [
        ("url", url_encode(data, upper_hex=u, encode_slash=s, plus_space=p).encode("ascii"))
        for u, s, p in itertools.product((True, False), repeat=3)
    ]
    candidates += [("base64", c) for c in base64_cores(data, urlsafe=False)]
    candidates += [("base64url", c) for c in base64_cores(data, urlsafe=True)]
    candidates += [("hex", data.hex().encode("ascii")), ("hex", data.hex().upper().encode("ascii"))]
    seen: set[bytes] = set()
    out: list[tuple[str, bytes]] = []
    for form, needle in candidates:
        if needle and needle not in seen:
            seen.add(needle)
            out.append((form, needle))
    return out
