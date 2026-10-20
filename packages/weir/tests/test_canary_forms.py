"""Each encoded form of docs/canary.md is found, and named, in both roles.

The placed encodings are built with the standard library from the
contract's definitions (canary_fixtures), never with weir.canary.forms. A
form's test fails when that form's needles are removed: the value is then
either missed or reported under another form.
"""

from __future__ import annotations

import base64
import json
import re
import typing
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import canary_fixtures as fx
import pytest

# A mock-oauth value may hold characters outside [A-Za-z0-9] (docs/canary.md,
# "Canary values"); these make every escaping form differ from raw. The
# tildes put `+` and `/` into the base64 core, so base64url differs too.
_SPECIAL = ' "/\\\té€~~~~~~'


def _value(seed: str) -> str:
    return fx.fake_value(seed, 20) + _SPECIAL + fx.fake_value(seed + "tail", 8)


def _json2(value: str) -> str:
    return fx.json_content(fx.json_content(value))


def _url_lower_hex(value: str) -> str:
    # Lowercase only the percent-escapes' hex digits, not the value's letters.
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), urllib.parse.quote(value, safe=""))


_FORMS: dict[str, list[Callable[[str], str]]] = {
    "raw": [lambda v: v],
    "json": [
        fx.json_content,  # non-ASCII as lowercase \uXXXX, `/` kept
        lambda v: fx.json_content(v, ensure_ascii=False),  # non-ASCII kept
        lambda v: fx.json_content(v).replace("/", "\\/"),
        lambda v: fx.json_content(v).replace("\\u20ac", "\\u20AC").replace("\\u00e9", "\\u00E9"),
    ],
    "json2": [_json2],
    "url": [
        lambda v: urllib.parse.quote(v, safe=""),
        lambda v: urllib.parse.quote(v, safe="/"),
        lambda v: urllib.parse.quote_plus(v, safe=""),
        _url_lower_hex,
    ],
    "base64": [lambda v, k=k: fx.base64_embedded(v, k) for k in range(3)],
    "base64url": [lambda v, k=k: fx.base64_embedded(v, k, urlsafe=True) for k in range(3)],
    "hex": [lambda v: v.encode().hex(), lambda v: v.encode().hex().upper()],
}


def _cases() -> list[tuple[str, int]]:
    return [(form, i) for form, encoders in _FORMS.items() for i in range(len(encoders))]


@pytest.mark.parametrize(("form", "index"), _cases())
def test_a_form_in_a_telemetry_string_is_reported_under_its_name(
    tmp_path: Path, form: str, index: int
) -> None:
    value = _value(f"{form}{index}")
    text = _FORMS[form][index](value)
    assert value.encode() not in text.encode() or form == "raw"
    span = fx.span("op", attributes=[fx.kv("carrier", f"<{text}>")])
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(span) + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert fx.leak_lines(run) == [
        f'LEAK p.one file={tmp_path / "otlp.jsonl"}:1 signal=traces span="op"'
        f" at=attributes.carrier form={form}"
    ]
    assert run.exit_code == 1
    fx.assert_value_free(run.stdout, [value])


@pytest.mark.parametrize(("form", "index"), _cases())
def test_a_form_in_a_swept_file_is_reported_under_its_name(
    tmp_path: Path, form: str, index: int
) -> None:
    value = _value(f"swept{form}{index}")
    text = _FORMS[form][index](value)
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    (tmp_path / "flow.stdout").write_bytes(b"start\n\x00binary " + text.encode() + b" end\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], [tmp_path / "flow.stdout"])
    assert fx.leak_lines(run) == [
        f"LEAK p.one file={tmp_path / 'flow.stdout'}:2 signal=raw form={form}"
    ]
    fx.assert_value_free(run.stdout, [value])


def test_identical_needles_are_kept_once_under_the_first_form(tmp_path: Path) -> None:
    """An alphanumeric value's json and url forms equal its raw bytes: one
    hit, under raw, not three."""
    value = fx.fake_value("alnum")
    assert fx.json_content(value) == value == urllib.parse.quote(value, safe="")
    fx.write(
        (tmp_path / "otlp.jsonl"), fx.traces(fx.span("op", attributes=[fx.kv("k", value)])) + "\n"
    )
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], as_json=True)
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    assert [h["form"] for h in hits] == ["raw"]


def test_a_fragment_of_a_value_is_not_a_hit(tmp_path: Path) -> None:
    """docs/canary.md "What the judge does not claim": truncated or split."""
    value = fx.fake_value("fragment")
    fragments = [value[:-1], value[1:], value[:12] + " " + value[12:]]
    span = fx.span("op", attributes=[fx.kv(f"k{i}", f) for i, f in enumerate(fragments)])
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(span) + "\n")
    ledger = fx.write_ledger(
        tmp_path / "ledger.jsonl",
        [
            fx.placement("p.one", value),
            {"type": "exercised", "placement": "p.one", "evidence": "request"},
        ],
    )
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert fx.leak_lines(run) == []
    assert run.exit_code == 0
    assert run.lines[-1] == "result: clean"


def test_base64_core_matches_inside_any_blob_padded_or_not(tmp_path: Path) -> None:
    """The core is the same whatever bytes surround the value: at each
    alignment, blobs with different neighbours, padded or not, all hit."""
    value = fx.fake_value("core")
    blobs: list[str] = []
    for k in range(3):
        for before, after in ((b"q", b""), (b"ZZZ", b"?"), (b"\xff\xfe\xfd" * 2, b"\x00\x01")):
            plain = before * 3 + b"." * k + value.encode() + after
            blobs.append(base64.b64encode(plain).decode())
    assert any(b.endswith("=") for b in blobs) and any(not b.endswith("=") for b in blobs)
    spans = [fx.span(f"s{i}", attributes=[fx.kv("blob", b)]) for i, b in enumerate(blobs)]
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(*spans) + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], as_json=True)
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    assert sorted(str(h["span"]) for h in hits) == sorted(f"s{i}" for i in range(len(blobs)))
    assert {h["form"] for h in hits} == {"base64"}


def test_bytes_values_are_matched_after_base64_decoding(tmp_path: Path) -> None:
    value = fx.fake_value("bytes")
    encoded = base64.b64encode(b"\x00\x01" + value.encode() + b"\x02").decode()
    attribute = {"key": "payload", "value": {"bytesValue": encoded}}
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op", attributes=[attribute])) + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], as_json=True)
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    # Decoded, the value is there as it is; the raw sweep's base64 hit on
    # the same line is not reported twice.
    assert [(h["location"], h["form"], h["signal"]) for h in hits] == [
        ("attributes.payload", "raw", "traces")
    ]
    fx.assert_value_free(json.dumps(run.report), [value])
