"""The parts of one recorded request (docs/canary.md, "The request capture").

A request capture line is one request the mock received. `parse_request`
reads it into a `Request` record, or None when the line is not one, and
`request_parts` breaks the record into `Part`s: the bytes to match and the
printed, value-free location within the request. The judge decides what a
match means; this module only says where in the request the bytes are.

Every part of the request is searched: the method, the host, the path as
received and percent-decoded, each query parameter, each header, and the
body, string by string when it is JSON, field by field when it is a form,
and always as a whole. The whole query and the whole body are fallbacks:
the judge reports them only where no finer part of the same request found
the same placement.

A name in a location (a header, parameter, field or JSON member name) is
program text, so it is printed under the printing rule. A name the judge
prints in another form than it was received (a header name in lower case,
a parameter name percent-decoded) is withheld when any of its forms holds
a value, so no transformation can print a value the original would have
withheld.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass

import msgspec

from weir.canary._types import Request
from weir.canary.text import WITHHELD
from weir.canary.walk import Json

_FORM = "application/x-www-form-urlencoded"
_HEX = frozenset(b"0123456789abcdefABCDEF")

type Display = Callable[[str], str]


@dataclass(frozen=True)
class Part:
    data: bytes
    location: str
    # Set for the parts of the query and the body: their whole is a
    # fallback, reported only where no finer part of the same group in the
    # same request found the same placement.
    group: str | None = None
    whole: bool = False


def parse_request(line: bytes) -> Request | None:
    """The record on one line, or None when the line is not a request
    record. A body that is not valid base64 is not a record either: its
    bytes could not be searched."""
    try:
        record = msgspec.json.decode(line, type=Request)
    except (msgspec.DecodeError, msgspec.ValidationError, RecursionError):
        return None
    if record.body is not None and _body_bytes(record.body) is None:
        return None
    return record


def _body_bytes(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogatepass")


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def shown(display: Display, printed: str, *received: str) -> str:
    """`printed` under the printing rule, withheld when it or any form it
    was `received` in holds a value."""
    if any(display(form) == WITHHELD for form in (printed, *received)):
        return WITHHELD
    return display(printed)


def _unquote(data: bytes, *, plus: bool) -> bytes:
    """Percent-decoding, byte for byte; `+` is a space when `plus`. An escape
    that is not two hex digits is kept as it is."""
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == 0x25 and i + 2 < len(data) and data[i + 1] in _HEX and data[i + 2] in _HEX:
            out.append(int(data[i + 1 : i + 3], 16))
            i += 3
            continue
        out.append(0x20 if plus and byte == 0x2B else byte)
        i += 1
    return bytes(out)


def _pairs(data: bytes, root: str, display: Display) -> list[Part]:
    """A query string or form body, parameter by parameter."""
    parts: list[Part] = []
    for item in data.split(b"&"):
        if not item:
            continue
        raw_name, _, raw_value = item.partition(b"=")
        name = _unquote(raw_name, plus=True)
        location = f"{root}.{shown(display, _text(name), _text(raw_name))}"
        parts.append(Part(name, location, root))
        parts.append(Part(_unquote(raw_value, plus=True), location, root))
    return parts


def _json_parts(node: Json, location: str, display: Display, parts: list[Part]) -> None:
    if isinstance(node, str):
        parts.append(Part(_utf8(node), location, "body"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _json_parts(item, f"{location}[{index}]", display, parts)
    elif isinstance(node, dict):
        for key, value in node.items():
            member = f"{location}.{display(key)}"
            parts.append(Part(_utf8(key), member, "body"))
            _json_parts(value, member, display, parts)


def _is_form(record: Request) -> bool:
    for name, value in record.headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower() == _FORM
    return False


def _body_parts(record: Request, body: bytes, display: Display) -> list[Part]:
    parts: list[Part] = []
    try:
        doc: Json = msgspec.json.decode(body)
    except (msgspec.DecodeError, RecursionError):
        if _is_form(record):
            parts = _pairs(body, "body", display)
    else:
        _json_parts(doc, "body", display, parts)
    parts.append(Part(body, "body", "body", whole=True))
    return parts


def request_parts(record: Request, display: Display) -> list[Part]:
    """Every part of the request, each with its printed location."""
    parts = [Part(_utf8(record.method), "method"), Part(_utf8(record.host), "host")]
    if record.path is not None:
        path = _utf8(record.path)
        parts.append(Part(path, "path"))
        parts.append(Part(_unquote(path, plus=False), "path"))
    if record.query is not None:
        query = _utf8(record.query)
        parts += _pairs(query, "query", display)
        parts.append(Part(query, "query", "query", whole=True))
    for name, value in record.headers:
        location = f"headers.{shown(display, name.lower(), name)}"
        parts.append(Part(_utf8(name), location))
        parts.append(Part(_utf8(value), location))
    if record.body is not None:
        body = _body_bytes(record.body)
        assert body is not None  # parse_request refuses a body that does not decode
        parts += _body_parts(record, body, display)
    return parts
