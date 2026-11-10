"""weir.json_escapes against the standard library's JSON decoder and the
contract's rule (docs/canary.md, "The decoded view").

What a JSON string's escapes mean is the standard's, so the expectation is
stdlib `json.loads` of the same string: any text, escaped any way json and
the u-escape fixture write it, unescapes to the text itself.
"""

from __future__ import annotations

import json

import canary_fixtures as fx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from weir.json_escapes import decoded_view, unescape


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogatepass")


@given(st.text())
def test_a_json_string_unescapes_to_what_json_decodes(text: str) -> None:
    for written in (json.dumps(text), json.dumps(text, ensure_ascii=False)):
        assert unescape(_utf8(written[1:-1])) == _utf8(json.loads(written))


@given(st.text(), st.integers(min_value=1, max_value=7), st.booleans())
def test_any_character_written_as_a_u_escape_unescapes_to_itself(
    text: str, every: int, upper: bool
) -> None:
    written = fx.u_escaped(text, lambda i: i % every == 0, upper=upper)
    assert unescape(_utf8(written)) == _utf8(json.loads('"' + written + '"'))


# Bytes rich in what the rule turns on: backslashes, escape letters, hex,
# surrogate halves, and bytes that are not UTF-8.
_PIECES = st.sampled_from(
    [b"\\", b"\\\\", b"u", b"\\u", b"00", b"73", b"d8", b"3d", b"dc", b"DE", b"0f", b"n", b"t"]
    + [b'"', b"/", b"b", b"x", b"a", b"\n", b"\xff", b"\xc3\xa9", b"q"]
)


@given(st.lists(_PIECES, max_size=40).map(b"".join))
def test_any_bytes_unescape_as_one_left_to_right_pass(data: bytes) -> None:
    """Malformed escapes included: the oracle is the contract's rule read
    byte by byte (canary_fixtures)."""
    assert unescape(data) == fx.json_unescape_once(data)


@pytest.mark.parametrize("high", [0xD7FF, 0xD800, 0xDBFF, 0xDC00])
@pytest.mark.parametrize("low", [0xDBFF, 0xDC00, 0xDFFF, 0xE000])
@pytest.mark.parametrize("spell", ["{:04x}", "{:04X}"])
def test_two_u_escapes_at_the_surrogate_edges_unescape_as_the_rule_reads_them(
    high: int, low: int, spell: str
) -> None:
    """A pair is joined only for a high then a low surrogate, the edges of
    each range included (the oracle: canary_fixtures' byte-by-byte rule)."""
    data = f"\\u{spell}\\u{spell}".format(high, low).encode()
    assert unescape(data) == fx.json_unescape_once(data)


@pytest.mark.parametrize("upper", [False, True])
def test_a_surrogate_pair_is_one_character(upper: bool) -> None:
    """A pair is joined as json joins it, beside bytes that are not UTF-8."""
    text = "a\U0001f511b"
    written = fx.u_escaped(text, lambda i: True, upper=upper)
    expected = b"\xff" + _utf8(json.loads('"' + written + '"'))
    assert unescape(b"\xff" + _utf8(written)) == expected


def test_an_unpaired_backslash_or_unknown_escape_is_kept() -> None:
    for kept in (b"C:\\Users\\x", b"\\q", b"\\u12", b"\\u12G4", b"end\\"):
        assert unescape(kept) == kept
        assert decoded_view(kept).texts == ()


# Text with no backslash of its own: it would be one more escape to undo.
@given(
    st.text(st.characters(exclude_characters="\\"), min_size=1, max_size=12),
    # Each quoting doubles the backslashes: past a few levels only size grows.
    st.integers(min_value=1, max_value=8),
)
def test_the_view_unescapes_as_many_times_as_json_quoted_it(text: str, times: int) -> None:
    written = fx.u_escaped(text, lambda i: i == 0)
    for _ in range(times - 1):
        written = json.dumps(written)[1:-1]
    view = decoded_view(_utf8(written), levels=times)
    assert view.complete
    assert view.texts[-1] == _utf8(text)
    assert len(view.texts) == times
    deeper = decoded_view(_utf8(written), levels=times - 1)
    assert not deeper.complete
    assert deeper.texts == view.texts[:-1]
