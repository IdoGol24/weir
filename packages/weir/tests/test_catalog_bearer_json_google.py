"""Bearer headers, JSON-quoted credential fields and Google OAuth shapes.

Every expectation is derived from the planted value: a hit's length and
fingerprint come from the value itself, so a detector that captures one byte
too many (a closing `\\"`) or too few fails here. The values are made up and
written in fragments, so no committed literal has a credential's shape.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG
from weir.cli.main import main
from weir.exposure import ExposureHit, classify_exposure
from weir.inventory.fingerprint import fingerprint, load_or_create_key


def _v(fragments: str) -> str:
    return fragments.replace(" ", "")


TOKEN = _v("Kq7vR2 mLx9Tz 4Wb8Nc 3Hd6Jf 1Ps5Yg 0Ua")
FIELD = _v("Rk2Ls9 Vn4Xb6 Zt1Wc8 Mp")
PASSPHRASE = "violet quarry ferry lantern"
ACCESS = _v("ya 29.a0Kq 7vR2mL x9Tz4W b8Nc3H d6Jf1P s5Yg0U a-Rk2L s9Vn4X b6.Zt1Wc8")
REFRESH = _v("1/ /0gKq7v R2mLx9 Tz4Wb8 Nc3Hd6 Jf1Ps5 Yg0Ua- Rk2Ls9 Vn4Xb6")
CLIENT = _v("GOC SPX- Kq7vR2 mLx9Tz 4Wb8Nc 3Hd6Jf 1Ps5")
REFRESH_7 = _v("1/ /7gKq7v R2mLx9 Tz4Wb8 Nc3Hd6 Jf1Ps5 Yg0Ua- Rk2Ls9 Vn4Xb6")
REFRESH_HYPHEN = _v("1/ /03-gKq 7vR2mL x9Tz4W b8Nc3H d6Jf1P s5Yg0U a-Rk2L s9Vn4X b6")
GOOGLE = {
    "access": ACCESS,
    "refresh": REFRESH,
    "refresh-nonzero-digit": REFRESH_7,
    "refresh-hyphen-after-digits": REFRESH_HYPHEN,
    "client-secret": CLIENT,
}
THRESHOLD = 6  # the printing rule: no run of 6 or more characters of a value


def _hits(text: str, key: str = "probe") -> list[ExposureHit]:
    """The real exposure scan over one span attribute holding `text`."""
    return _attribute_hits(key, {"stringValue": text})


def _attribute_hits(key: str, value: dict[str, object]) -> list[ExposureHit]:
    """The real exposure scan over one span attribute `key` set to the OTLP
    AnyValue `value`."""
    doc = {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "spanId": "ab" * 8,
                                "attributes": [{"key": key, "value": value}],
                            }
                        ]
                    }
                ]
            }
        ]
    }
    surface = scan_surface(decode_input(json.dumps(doc).encode()))
    return classify_exposure(surface, DEFAULT_CATALOG).hits


def _claim(value: str, source_class: str, *, eligible: bool) -> tuple[object, ...]:
    fp = hashlib.sha256(value.encode()).hexdigest()[:12] if eligible else None
    return (source_class, eligible, len(value), fp)


def _claims(hits: list[ExposureHit]) -> list[tuple[object, ...]]:
    return [(h.source_class, h.eligible, h.value_len, h.fingerprint) for h in hits]


def _header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _header_list(token: str) -> dict[str, list[str]]:
    # Go's json.Marshal(http.Header) writes every header value as an array.
    return {"Authorization": [f"Bearer {token}"], "Accept": ["application/json"]}


def _asgi(token: str) -> str:
    return repr([(b"authorization", f"Bearer {token}".encode()), (b"accept", b"*/*")])


_BEARER_FORMS = {
    "header": lambda t: f"GET /v1/models HTTP/1.1\r\nAuthorization: Bearer {t}\r\n",
    "lower-case": lambda t: f"authorization: bearer {t}",
    "json": lambda t: json.dumps({"headers": _header(t)}),
    "json-escaped": lambda t: json.dumps({"request": json.dumps({"headers": _header(t)})}),
    "python-repr": lambda t: repr(_header(t)),
    "curl": lambda t: f"curl -H 'Authorization: Bearer {t}' https://api.example.com",
    "json-array": lambda t: json.dumps({"headers": _header_list(t)}),
    "json-array-escaped": lambda t: json.dumps({"request": json.dumps(_header_list(t))}),
    "json-array-indented": lambda t: json.dumps({"headers": _header_list(t)}, indent=2),
    "json-array-indented-escaped": lambda t: json.dumps(
        {"request": json.dumps(_header_list(t), indent=2)}
    ),
    "python-tuple-list": lambda t: repr([("authorization", f"Bearer {t}"), ("accept", "*/*")]),
    "python-tuple-list-wrapped": lambda t: f"[('authorization',\n  'Bearer {t}')]",
    "asgi-bytes": _asgi,
    "asgi-bytes-escaped": lambda t: json.dumps({"scope": _asgi(t)}),
}


@pytest.mark.parametrize("form", sorted(_BEARER_FORMS))
def test_a_bearer_token_is_a_verdict_grade_credential(form: str) -> None:
    hits = _hits(_BEARER_FORMS[form](TOKEN))
    assert _claims(hits) == [_claim(TOKEN, "bearer_token", eligible=True)]
    # The display prefix is the header, never a byte of the token.
    assert hits[0].prefix.lower() == "authorization: bearer"


JWT = f"{TOKEN}.{FIELD}.{TOKEN[::-1]}"


@pytest.mark.parametrize("end", [".", ". Then retry.", ".\n"])
def test_a_sentence_period_after_a_bearer_token_is_not_part_of_it(end: str) -> None:
    hits = _hits(f"Send Authorization: Bearer {JWT}{end}")
    assert _claims(hits) == [_claim(JWT, "bearer_token", eligible=True)]


SLASH_TOKEN = _v("Kq7/vR 2mLx9T z4Wb8N c3Hd6J f1Ps5Y")


def _slashes(text: str) -> str:
    """JSON as encoders that escape `/` write it (PHP, some Java and C#)."""
    return text.replace("/", "\\/")


def _slash_json(obj: object) -> str:
    return _slashes(json.dumps(obj))


_SLASH_FORMS = {
    "bearer": (lambda: _slash_json(_header(SLASH_TOKEN)), SLASH_TOKEN, 1),
    "bearer-escaped": (
        lambda: _slash_json({"body": _slash_json(_header(SLASH_TOKEN))}),
        SLASH_TOKEN,
        2,
    ),
    "refresh-bare": (lambda: _slash_json({"content": f"token {REFRESH}"}), REFRESH, 1),
    "refresh-keyed": (lambda: _slash_json({"refresh_token": REFRESH}), REFRESH, 1),
}


@pytest.mark.parametrize("form", sorted(_SLASH_FORMS))
def test_an_escaped_slash_does_not_hide_a_token(form: str) -> None:
    build, value, layers = _SLASH_FORMS[form]
    written = value
    for _ in range(layers):
        written = _slashes(json.dumps(written)[1:-1])
    # The hit is the value's bytes as the span holds them, at any depth.
    hits = _hits(build())
    source_class = "bearer_token" if value == SLASH_TOKEN else "google_oauth_credential"
    assert _claims(hits) == [_claim(written, source_class, eligible=True)]
    assert len(hits[0].prefix) < THRESHOLD or hits[0].prefix == "Authorization: Bearer"


_HEADER_ATTRIBUTES = {
    "string": lambda t: {"stringValue": f"Bearer {t}"},
    "array": lambda t: {"arrayValue": {"values": [{"stringValue": f"Bearer {t}"}]}},
}


@pytest.mark.parametrize(
    "key",
    [
        "http.request.header.authorization",
        "HTTP.Request.Header.Authorization",
        "http.request.header.proxy-authorization",
    ],
)
@pytest.mark.parametrize("form", sorted(_HEADER_ATTRIBUTES))
def test_an_authorization_header_attribute_holds_a_bearer_token(form: str, key: str) -> None:
    # The OpenTelemetry HTTP semantic conventions record a request header as
    # `http.request.header.<name>`, so the header name is the attribute key
    # and the value is only `Bearer <token>`.
    hits = _attribute_hits(key, _HEADER_ATTRIBUTES[form](JWT))
    assert _claims(hits) == [_claim(JWT, "bearer_token", eligible=True)]
    assert hits[0].prefix.lower() == "authorization: bearer"


@pytest.mark.parametrize(
    "key", ["probe", "http.request.header.accept", "app.request.authorization"]
)
@pytest.mark.parametrize("form", sorted(_HEADER_ATTRIBUTES))
def test_bearer_under_an_unrelated_attribute_name_is_not_a_hit(form: str, key: str) -> None:
    assert _attribute_hits(key, _HEADER_ATTRIBUTES[form](JWT)) == []


@pytest.mark.parametrize(
    "header", ["x-csrf-token", "x-request-token", "x-api-key", "cookie", "accept"]
)
def test_another_request_header_attribute_is_scanned_as_a_plain_string(header: str) -> None:
    # Only the authorization headers are read as a header line: any other
    # header attribute classifies exactly as the same string under a
    # non-header key does.
    value: dict[str, object] = {"stringValue": FIELD}
    assert _attribute_hits(f"http.request.header.{header}", value) == _attribute_hits(
        "probe", value
    )


_FIELD_FORMS = {
    "json": lambda k: json.dumps({k: FIELD, "model": "m-1"}),
    "compact": lambda k: json.dumps({k: FIELD, "model": "m-1"}, separators=(",", ":")),
    "json-escaped": lambda k: json.dumps({"body": json.dumps({k: FIELD, "model": "m-1"})}),
    "escaped-twice": lambda k: json.dumps(
        {"log": json.dumps({"body": json.dumps({k: FIELD, "model": "m-1"})})}
    ),
    "python-repr": lambda k: repr({k: FIELD, "model": "m-1"}),
}


@pytest.mark.parametrize(
    "key", ["api_key", "access_token", "client_secret", "password", "token", "Token"]
)
@pytest.mark.parametrize("form", sorted(_FIELD_FORMS))
def test_a_json_quoted_credential_field_is_found(form: str, key: str) -> None:
    hits = _hits(_FIELD_FORMS[form](key))
    # Floorless, so the review queue, at exactly the value's length.
    assert _claims(hits) == [_claim(FIELD, "json_credential_field", eligible=False)]
    assert hits[0].prefix == key


_PASSPHRASE_FORMS = {
    "json": lambda v: json.dumps({"password": v}),
    "json-escaped": lambda v: json.dumps({"body": json.dumps({"password": v})}),
    "python-repr": lambda v: repr({"password": v}),
    "python-repr-apostrophe": lambda v: repr({"password": f"don't {v}"}),
}


@pytest.mark.parametrize("form", sorted(_PASSPHRASE_FORMS))
def test_a_json_quoted_value_runs_to_its_closing_quote(form: str) -> None:
    text = _PASSPHRASE_FORMS[form](PASSPHRASE)
    # The whole value, spaces and an apostrophe inside double quotes included.
    value = PASSPHRASE if "apostrophe" not in form else f"don't {PASSPHRASE}"
    assert _claims(_hits(text)) == [_claim(value, "json_credential_field", eligible=False)]


@pytest.mark.parametrize(
    "value", ["abc\\u00e9123456", "123456\\u00e9abc", "abc\\U0001f600123"]
)
def test_a_token_value_with_escapes_counts_its_literal_letters_and_digits(value: str) -> None:
    # The only digits, or the only letters, come after the escape.
    assert _claims(_hits(f'{{"token": "{value}"}}')) == [
        _claim(value, "json_credential_field", eligible=False)
    ]


def test_an_unquoted_key_value_still_ends_at_the_first_space() -> None:
    first, rest = "lanternfish", " quarry ferry"
    hits = _hits(f'password = "{first}{rest}"')
    assert _claims(hits) == [_claim(first, "credential_field", eligible=False)]


def test_a_placeholder_sentence_in_a_json_quoted_field_is_only_reviewed() -> None:
    # The placeholder rules judge the whole value: a masked or null value is
    # dropped, and a sentence matches neither, so it is reviewed, never a
    # verdict.
    sentence = "your password goes here"
    assert _claims(_hits(json.dumps({"password": sentence}))) == [
        _claim(sentence, "json_credential_field", eligible=False)
    ]
    for masked in ("*" * 12, "REDACTED", "null"):
        assert _hits(json.dumps({"password": masked})) == []


def _encoded(value: str, layers: int) -> str:
    for _ in range(layers):
        value = json.dumps(value)[1:-1]
    return value


_BACKSLASH_VALUE = "abc\\defghijk"
_BACKSLASH_FORMS = {
    "env-line": (
        lambda v: json.dumps({"content": f"DB_PASSWORD={v}\n"}), 1, "credential_field"
    ),
    "json-quoted": (
        lambda v: json.dumps({"content": json.dumps({"password": v})}), 2,
        "json_credential_field",
    ),
}


@pytest.mark.parametrize("form", sorted(_BACKSLASH_FORMS))
def test_an_escaped_backslash_stays_inside_a_credential_field_value(form: str) -> None:
    build, layers, source_class = _BACKSLASH_FORMS[form]
    hits = _hits(build(_BACKSLASH_VALUE))
    # A Write tool argument carries the value JSON-encoded, so the span holds
    # its escaped bytes; an escaped backslash is part of the value, not its end.
    expected = _encoded(_BACKSLASH_VALUE, layers)
    assert _claims(hits) == [_claim(expected, source_class, eligible=False)]


_GOOGLE_FORMS = {
    "prose": lambda v: f"refreshed with {v}.",
    "json": lambda v: json.dumps({"credential": v}),
    "json-escaped": lambda v: json.dumps({"body": json.dumps({"token": v})}),
    "after-escaped-line-break": lambda v: json.dumps({"content": f"# creds\n{v}\n"}),
    "bearer-header": lambda v: f"Authorization: Bearer {v}",
}


@pytest.mark.parametrize("form", sorted(_GOOGLE_FORMS))
@pytest.mark.parametrize("kind", sorted(GOOGLE))
def test_a_google_oauth_shape_is_a_verdict_grade_credential(kind: str, form: str) -> None:
    value = GOOGLE[kind]
    hits = _hits(_GOOGLE_FORMS[form](value))
    # One hit: a key-name or header match around it is subsumed by the
    # stronger claim about the same bytes.
    assert _claims(hits) == [_claim(value, "google_oauth_credential", eligible=True)]
    head = re.match(r"ya29\.|1//[0-9]|GOCSPX-", value)
    assert head is not None
    # The display prefix stops inside the class head and prints fewer than
    # THRESHOLD characters of the value.
    assert head.group(0).startswith(hits[0].prefix)
    assert 0 < len(hits[0].prefix) < THRESHOLD


_NEAR_MISSES = {
    "bearer-in-prose": "Bearer authentication sends the token in a header; the bearer pays.",
    "bearer-placeholder-angle": "Authorization: Bearer <token>",
    "bearer-placeholder-shell": "Authorization: Bearer ${TOKEN}",
    "bearer-placeholder-format": json.dumps({"Authorization": "Bearer {token}"}),
    "bearer-concatenated": 'headers = {"Authorization": "Bearer " + token}',
    "bearer-empty": json.dumps({"Authorization": "Bearer "}),
    "bearer-short": "Authorization: Bearer abc123",
    "bearer-glued-key": f"xAuthorization: Bearer {TOKEN}",
    "bearer-comma-prose": f"Authorization, Bearer {TOKEN} style schemes are in RFC 6750",
    "bearer-array-placeholder": json.dumps({"Authorization": ["Bearer <token>"]}),
    "tokenizer": json.dumps({"tokenizer": "cl100k-base-tokenizer"}),
    "password-hint": json.dumps({"password_hint": "the-name-of-my-first-pet"}),
    "token-counts": json.dumps({"max_tokens": 4096, "token_count": "12345678"}),
    "masked-fields": json.dumps({"password": "********", "api_key": "REDACTED"}),
    "logprobs-tokens": json.dumps(
        {
            "logprobs": {
                "content": [
                    {
                        "token": "Certainly",
                        "logprob": -0.01,
                        "top_logprobs": [
                            {"token": "Certainly", "logprob": -0.01},
                            {"token": "Absolutely", "logprob": -4.6},
                        ],
                    }
                ]
            }
        }
    ),
    "token-digits-only": json.dumps({"token": "123456789012"}),
    # Under the key `token`, a letter or digit inside an escape sequence is
    # not one of the value's own characters.
    "logprobs-tokens-escaped": json.dumps(
        {
            "logprobs": {
                "content": [
                    {
                        "token": "\u4f60\u597d",
                        "logprob": -0.01,
                        "top_logprobs": [{"token": "\u60a8\u597d", "logprob": -2.3}],
                    }
                ]
            }
        }
    ),
    "token-accented": json.dumps({"token": " \u00e9t\u00e9"}),
    "token-letters-and-escapes": json.dumps({"token": "Gr\u00f6\u00dfenordnung"}),
    "token-byte-fallback": json.dumps({"token": "\\xe4\\xbd\\xa0"}),
    "token-emoji-escaped": ascii({"token": "\U0001f600\U0001f600"}),
    "token-emoji-escaped-double-quoted": '{"token": "\\U0001f600\\U0001F600"}',
    "token-escaped-letters": '{"token": "\\u0041\\u0042123456789"}',
    "token-escaped-letters-in-json": json.dumps(
        {"body": '{"token": "\\u0041\\u0042123456789"}'}
    ),
    "token-letters-after-line-break": json.dumps({"token": "12345678\nabcdefgh"}),
    "ya29-prose": "ya29 tokens are short-lived; see ya29.example for the format",
    "ya29-placeholder": "ya29.<access-token>",
    "gocspx-prose": "client secrets start with GOCSPX and a dash, as in GOCSPX-abc",
    "gocspx-placeholder": "GOCSPX-<client-secret>",
    "url-double-slash": "https://cdn.example.com/v1//assets/1//bundle-main-chunk.js",
    "floor-division": "pages = 1//2 + total_items//page_size  # 1// per page",
    "floor-division-operator": "half = 1//2*total_items-1//3+remaining_items_count",
    "floor-division-float": "x=1//2.5-offset_from_the_start_index",
    "comment": "// 1// TODO(refresh): rotate the refresh token weekly",
}


@pytest.mark.parametrize("case", sorted(_NEAR_MISSES))
def test_a_near_miss_is_not_a_hit(case: str) -> None:
    assert _hits(_NEAR_MISSES[case]) == []


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE",
        "Authorization: Bearer " + "x" * 32,
        "Authorization: Bearer " + "FAKE" * 8,
        "ya29." + "FAKE" * 12,
        "ya29." + "0" * 48,
    ],
    ids=["named", "masked", "fake", "google-fake", "google-zeroed"],
)
def test_a_placeholder_in_a_credential_shape_never_reaches_a_verdict(text: str) -> None:
    hits = _hits(text)
    assert hits, "the placeholder clears the loose pattern, so it is reviewed"
    assert not any(h.eligible for h in hits)


def _windows(values: list[str]) -> set[str]:
    forms = {f for v in values for f in (v, json.dumps(v)[1:-1], _slashes(v))}
    return {f[i : i + THRESHOLD] for f in forms for i in range(len(f) - THRESHOLD + 1)}


def _assert_no_fragment(label: str, text: str, windows: set[str]) -> None:
    __tracebackhide__ = True  # never print the scanned text
    found = [i for i in range(len(text) - THRESHOLD + 1) if text[i : i + THRESHOLD] in windows]
    assert not found, f"{label}: value fragments at offsets {found[:10]}"


def _plants() -> list[str]:
    return [
        _BEARER_FORMS["json-escaped"](TOKEN),
        _BEARER_FORMS["asgi-bytes-escaped"](TOKEN),
        _SLASH_FORMS["refresh-keyed"][0](),
        _SLASH_FORMS["bearer-escaped"][0](),
        _FIELD_FORMS["json-escaped"]("client_secret"),
        _PASSPHRASE_FORMS["json-escaped"](PASSPHRASE),
        *(_GOOGLE_FORMS["json"](v) for v in GOOGLE.values()),
    ]


def test_no_output_prints_a_value_or_a_fragment_of_one(tmp_path: Path) -> None:
    values = [TOKEN, FIELD, PASSPHRASE, *GOOGLE.values()]
    windows = _windows([*values, SLASH_TOKEN])
    attrs = [{"key": f"probe{i}", "value": {"stringValue": s}} for i, s in enumerate(_plants())]
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {"spans": [{"spanId": "ab" * 8, "name": "chat", "attributes": attrs}]}
                        ]
                    }
                ]
            }
        )
    )
    report = tmp_path / "r.html"
    scan = CliRunner().invoke(main, ["scan", str(trace), "--report", str(report)])
    gauge = CliRunner().invoke(main, ["gauge", str(trace)])
    assert scan.exit_code == 1, "verdict-grade credentials must fail the scan"
    for label, text in {
        "scan": scan.output,
        "gauge": gauge.output,
        "html": report.read_text(encoding="utf-8"),
    }.items():
        _assert_no_fragment(label, text, windows)

    # The inventory finds the same values in a code file, by keyed
    # fingerprint, and prints none of them either.
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    (project / "client.py").write_text("\n".join(_plants()) + "\n")
    key_file, store = tmp_path / "fp.key", tmp_path / "store.json"
    args = [
        "inventory",
        "--home",
        str(home),
        "--project",
        str(project),
        "--key",
        str(key_file),
        "--unknown-list",
        str(tmp_path / "u.txt"),
    ]
    text = CliRunner().invoke(main, [*args, "--store", str(store)])
    report_json = CliRunner().invoke(main, [*args, "--json"])
    assert report_json.exit_code == 0
    key = load_or_create_key(key_file)
    found = {r["fingerprint"] for r in json.loads(store.read_text())["records"]}
    assert {fingerprint(key, v) for v in values} <= found
    for label, out in {
        "inventory": text.output,
        "inventory-json": report_json.output,
        "store": store.read_text(),
    }.items():
        _assert_no_fragment(label, out, windows)
