"""The runner's needles against docs/canary.md "The encoded forms".

Every expectation is built by an independent encoder (the standard
library's json, urllib and base64), never by restating a needle: plant the
value in a real encoding, then require that some needle of the right form
is in it. The value holds every character class the contract names - a
quote, a backslash, a slash, a space, control characters, non-ASCII and a
character above U+FFFF - so each variant has something to change.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from collections.abc import Callable

import pytest

from weir_run.needles import FORMS, needles

VALUE = 'k3y"q\\/ a\tb\x01cé\U0001f600Z9'
PLAIN = "Q7mZp2Lx9TbW4nRk8VhC"


def _of(value: str, form: str) -> list[bytes]:
    return [n for f, n in needles(value) if f == form]


def _found(value: str, form: str, haystack: bytes) -> bool:
    return any(n in haystack for n in _of(value, form))


def test_raw_is_the_utf8_bytes() -> None:
    assert _found(VALUE, "raw", b"<" + VALUE.encode() + b">")


@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_json_matches_a_json_document(ensure_ascii: bool) -> None:
    document = json.dumps({"k": VALUE}, ensure_ascii=ensure_ascii).encode()
    assert _found(VALUE, "json", document)


def test_json_matches_uppercase_hex_and_escaped_slash() -> None:
    lower = json.dumps(VALUE)
    upper = lower.replace("\\u00e9", "\\u00E9").replace("\\ud83d\\ude00", "\\uD83D\\uDE00")
    variant = upper.replace("/", "\\/").encode()
    assert variant != lower.encode()
    assert _found(VALUE, "json", variant)


def test_json_matches_controls_written_as_unicode_escapes() -> None:
    # \t written \u0009 instead of its short escape, as some encoders do.
    variant = json.dumps(VALUE).replace("\\t", "\\u0009").encode()
    assert _found(VALUE, "json", variant)


def test_json2_matches_json_inside_a_string_inside_json() -> None:
    inner = json.dumps({"headers": {"authorization": VALUE}})
    outer = json.dumps({"attributes": inner}).encode()
    assert not _found(VALUE, "json", outer)
    assert _found(VALUE, "json2", outer)


def _lower_hex(text: str) -> str:
    return re.sub("%[0-9A-F]{2}", lambda m: m.group(0).lower(), text)


URL_ENCODERS: list[Callable[[str], str]] = [
    lambda v: urllib.parse.quote(v, safe=""),
    lambda v: urllib.parse.quote(v, safe="/"),
    lambda v: urllib.parse.quote_plus(v, safe=""),
    # Lowercase hex digits, as some encoders write them.
    lambda v: _lower_hex(urllib.parse.quote(v, safe="")),
]


@pytest.mark.parametrize("encode", URL_ENCODERS)
def test_url_matches_percent_encodings(encode: Callable[[str], str]) -> None:
    text = encode(VALUE)
    assert _found(VALUE, "url", f"q={text}&x=1".encode())


@pytest.mark.parametrize("value", [VALUE, PLAIN])
@pytest.mark.parametrize("offset", range(6))
@pytest.mark.parametrize(
    ("form", "encode"), [("base64", base64.b64encode), ("base64url", base64.urlsafe_b64encode)]
)
def test_base64_core_matches_at_any_offset(
    value: str, offset: int, form: str, encode: Callable[[bytes], bytes]
) -> None:
    # A Basic credential and a JWT segment: the value sits at some byte
    # offset of a larger plaintext, followed by more bytes.
    plaintext = b"u" * offset + value.encode() + b":tail"
    blob = encode(plaintext)
    # A URL-safe core with no `-` or `_` is identical to the standard one,
    # and identical needles are kept once, under the first form.
    forms = {form, "base64"}
    assert any(n in blob for f, n in needles(value) if f in forms)
    if form == "base64":
        assert _found(value, form, blob)


def test_base64_core_holds_only_the_values_bits() -> None:
    # The same value under different neighbours gives the same core.
    a = base64.b64encode(b"AAAA" + PLAIN.encode() + b"BBBB")
    b = base64.b64encode(b"zzzz" + PLAIN.encode() + b"yyyy")
    shared = [n for n in _of(PLAIN, "base64") if n in a and n in b]
    assert shared


@pytest.mark.parametrize("upper", [False, True])
def test_hex_matches_both_cases(upper: bool) -> None:
    text = VALUE.encode().hex()
    assert _found(VALUE, "hex", (text.upper() if upper else text).encode())


def test_every_form_is_produced_and_duplicates_are_dropped() -> None:
    produced = needles(VALUE)
    assert {f for f, _ in produced} == set(FORMS)
    assert len({n for _, n in produced}) == len(produced)
    # For a plain value escaping changes nothing: json and url collapse into raw.
    plain_forms = {f for f, _ in needles(PLAIN)}
    assert "json" not in plain_forms and "url" not in plain_forms
