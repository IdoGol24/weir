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
import urllib.parse
from collections.abc import Callable
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
        "http.request.header.proxy_authorization",
        "http.request.header.PROXY_AUTHORIZATION",
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
        _URL_ENCODED_FORMS["query-in-escaped-json"](TOKEN),
        _URL_ENCODED_FORMS["form-body"](TOKEN),
        _field_documents(array=True)["json-escaped-indented"]("api_key", FIELD),
        _field_documents(array=True)["python-repr"]("password", PASSPHRASE),
        _URL_ENCODED_FORMS["header-line"](TOKEN),
        *(_PCT_TOKEN_FORMS["query"](t) for t in B64_TOKENS.values()),
        _SHAPED_DOCUMENTS["json-escaped-indented"]("api_key", _ARRAY_SHAPES["two-skipped"](FIELD)),
    ]


def test_no_output_prints_a_value_or_a_fragment_of_one(tmp_path: Path) -> None:
    values = [TOKEN, FIELD, PASSPHRASE, *GOOGLE.values()]
    encoded = [urllib.parse.quote(t, safe="") for t in B64_TOKENS.values()]
    windows = _windows([*values, SLASH_TOKEN, JWT, *B64_TOKENS.values(), *encoded])
    attrs: list[dict[str, object]] = [
        {"key": f"probe{i}", "value": {"stringValue": s}} for i, s in enumerate(_plants())
    ]
    attrs.append(
        {"key": "http.request.headers", "value": _KVLIST_HEADERS["nested"]("Authorization", JWT)}
    )
    attrs.append(
        {
            "key": "http.request.headers.snake",
            "value": _KVLIST_HEADERS["string"]("proxy_authorization", JWT),
        }
    )
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
    # Every plant is found, so the check below covers every shape.
    found_at = {
        h.location
        for h in classify_exposure(
            scan_surface(decode_input(trace.read_bytes())), DEFAULT_CATALOG
        ).hits
    }
    for attr in attrs:
        where = f"attributes.{attr['key']}"
        assert any(loc == where or loc.startswith(f"{where}.") for loc in found_at), where
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
    assert {fingerprint(key, v) for v in [*values, *B64_TOKENS.values()]} <= found
    for label, out in {
        "inventory": text.output,
        "inventory-json": report_json.output,
        "store": store.read_text(),
    }.items():
        _assert_no_fragment(label, out, windows)


def _kvlist(entries: dict[str, dict[str, object]]) -> dict[str, object]:
    return {"kvlistValue": {"values": [{"key": k, "value": v} for k, v in entries.items()]}}


_KVLIST_HEADERS = {
    "string": lambda name, t: _kvlist(
        {"accept": {"stringValue": "*/*"}, name: {"stringValue": f"Bearer {t}"}}
    ),
    "array": lambda name, t: _kvlist({name: _HEADER_ATTRIBUTES["array"](t)}),
    "nested": lambda name, t: _kvlist(
        {"headers": _kvlist({name: {"stringValue": f"Bearer {t}"}})}
    ),
}


@pytest.mark.parametrize("attribute", ["http.request.headers", "request.headers", "headers"])
@pytest.mark.parametrize(
    "name",
    [
        "authorization",
        "Authorization",
        "AUTHORIZATION",
        "proxy-authorization",
        "proxy_authorization",
        "Proxy_Authorization",
    ],
)
@pytest.mark.parametrize("form", sorted(_KVLIST_HEADERS))
def test_an_authorization_entry_in_a_kvlist_holds_a_bearer_token(
    form: str, name: str, attribute: str
) -> None:
    # A request header map recorded as one kvlist attribute names the header
    # in the entry key, so it is found exactly like the same header recorded
    # as its own `http.request.header.<name>` attribute.
    hits = _attribute_hits(attribute, _KVLIST_HEADERS[form](name, JWT))
    plain = _attribute_hits(f"http.request.header.{name}", {"stringValue": f"Bearer {JWT}"})
    assert _claims(hits) == _claims(plain) == [_claim(JWT, "bearer_token", eligible=True)]
    assert hits[0].prefix == plain[0].prefix
    assert hits[0].prefix.lower() == "authorization: bearer"


@pytest.mark.parametrize(
    "name",
    [
        "accept",
        "x-api-key",
        "x-authorization",
        "x_authorization",
        "authorization-hint",
        "authorization_hint",
        "app.authorization",
    ],
)
def test_bearer_under_another_kvlist_entry_is_not_a_hit(name: str) -> None:
    value = _kvlist({name: {"stringValue": f"Bearer {JWT}"}})
    assert _attribute_hits("http.request.headers", value) == []


@pytest.mark.parametrize(
    "text", ["Bearer <token>", "Bearer ${TOKEN}", "Bearer abc123", "Basic dXNlcjpwYXNzd29yZA=="]
)
def test_a_kvlist_authorization_entry_without_a_real_token_is_not_a_hit(text: str) -> None:
    # The kvlist entry is judged by the same floors and placeholder rules as
    # the plain header attribute.
    assert _attribute_hits(
        "http.request.headers", _kvlist({"authorization": {"stringValue": text}})
    ) == _attribute_hits("http.request.header.authorization", {"stringValue": text}) == []


_URL_ENCODED_FORMS = {
    "query": lambda t: f"GET /v1/callback?authorization=Bearer%20{t}&state=s1 HTTP/1.1",
    "query-capital": lambda t: f"https://api.example.com/v1/models?Authorization=Bearer%20{t}",
    "form-body": lambda t: f"authorization=Bearer+{t}&grant_type=client_credentials",
    "query-in-json": lambda t: json.dumps(
        {"url": f"https://api.example.com/v1/models?authorization=Bearer%20{t}"}
    ),
    "query-in-escaped-json": lambda t: json.dumps(
        {"body": json.dumps({"url": f"/v1/models?authorization=Bearer%20{t}&a=1"})}
    ),
    # The whole header line encoded as one value: `quote` writes the colon
    # as `%3A`, `quote_plus` the space as `+`, and JavaScript's `encodeURI`
    # keeps the colon (the `safe=":"` form).
    "header-line": lambda t: "headers=" + urllib.parse.quote(f"authorization: Bearer {t}", safe=""),
    "header-line-plus": lambda t: urllib.parse.quote_plus(f"Authorization: Bearer {t}"),
    "header-line-lower-hex": lambda t: f"Authorization%3a+Bearer+{t}",
    "header-line-encodeuri": lambda t: urllib.parse.quote(f"authorization: Bearer {t}", safe=":"),
    "doubled-plus": lambda t: f"authorization=Bearer++{t}&a=1",
    "doubled-pct20": lambda t: f"authorization=Bearer%20%20{t}&a=1",
}


@pytest.mark.parametrize("token", [TOKEN, JWT], ids=["opaque", "jwt"])
@pytest.mark.parametrize("form", sorted(_URL_ENCODED_FORMS))
def test_a_url_encoded_authorization_header_holds_a_bearer_token(form: str, token: str) -> None:
    hits = _hits(_URL_ENCODED_FORMS[form](token))
    plain = _hits(f"Authorization: Bearer {token}")
    assert _claims(hits) == _claims(plain) == [_claim(token, "bearer_token", eligible=True)]
    # The display prefix is the header; an encoded space is never shown.
    assert hits[0].prefix.lower() == "authorization: bearer"


@pytest.mark.parametrize(
    "text",
    [
        "/v1/callback?authorization=Bearer%20%3Ctoken%3E",
        "/v1/callback?authorization=Bearer%20%24%7BTOKEN%7D",
        "/v1/callback?authorization=Bearer%20abc123&a=1",
        "/v1/callback?authorization=Bearer%20&a=1",
        f"/v1/callback?xauthorization=Bearer%20{TOKEN}",
        f"/v1/callback?unauthorization=Bearer%20{TOKEN}",
        f"headers=unauthorization%3A%20Bearer%20{TOKEN}",
        f"/v1/search?q=bearer%20{TOKEN}",
        "headers=authorization%3A%20Bearer%20%3Ctoken%3E",
    ],
    ids=[
        "placeholder",
        "shell-placeholder",
        "short",
        "empty",
        "glued-key",
        "glued-key-un",
        "glued-key-header-line",
        "no-key",
        "header-line-placeholder",
    ],
)
def test_a_url_encoded_near_miss_is_not_a_hit(text: str) -> None:
    assert _hits(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "https://docs.example.com/search?q=authorization:Bearer+token+is+missing+or+invalid",
        "authorization=Bearer+token+is+missing+or+invalid&a=1",
        "authorization=Bearer%20token+is+missing+or+invalid+now",
        "authorization%3A+Bearer+token+is+missing+or+invalid",
        "authorization=Bearer++token+is+missing+or+invalid",
        "authorization=Bearer%20%20token+is+missing+or+invalid",
    ],
    ids=["query", "form-body", "pct20-then-plus", "header-line", "doubled-plus", "doubled-pct20"],
)
def test_a_form_encoded_sentence_after_bearer_is_not_a_token(text: str) -> None:
    # In a form body every `+` is an encoded space, so the encoded sentence is
    # judged as the sentence it stands for, which is not a hit.
    decoded = urllib.parse.unquote_plus(text)
    assert _hits(decoded) == []
    assert _hits(text) == []


@pytest.mark.parametrize("space", ["+", "%20"])
def test_a_form_encoded_token_ends_at_the_next_encoded_space(space: str) -> None:
    hits = _hits(f"authorization=Bearer{space}{JWT}+extra+words")
    assert _claims(hits) == _claims(_hits(f"Authorization: Bearer {JWT} extra words"))
    assert _claims(hits) == [_claim(JWT, "bearer_token", eligible=True)]


# Standard-base64 tokens: `/` or `+` early, `=` padding. URL encoding writes
# them as `%2F`, `%2B` and `%3D`.
B64_TOKENS = {
    "slash-early": _v("ab12/ Kq7vR2 mLx9Tz 4Wb8Nc 3Hd6Jf 1Ps5Yg 0Ua=="),
    "plus-early": _v("Kq7vR2+ mLx9Tz 4Wb8Nc 3Hd6Jf/ 1Ps5Yg 0Ua="),
}


def _lower_hex(text: str) -> str:
    return re.sub("%[0-9A-F]{2}", lambda m: m.group().lower(), text)


_PCT_TOKEN_FORMS = {
    "query": lambda t: f"/v1/callback?authorization=Bearer%20{urllib.parse.quote(t, safe='')}&a=1",
    "form-body": lambda t: f"authorization=Bearer+{urllib.parse.quote_plus(t)}&a=1",
    "lower-hex": lambda t: _lower_hex(f"authorization=Bearer%20{urllib.parse.quote(t, safe='')}"),
    "header-line": lambda t: urllib.parse.quote(f"authorization: Bearer {t}", safe=""),
}


def _claims_with_last4(hits: list[ExposureHit]) -> list[tuple[object, ...]]:
    return [(*claim, h.last4) for claim, h in zip(_claims(hits), hits, strict=True)]


@pytest.mark.parametrize("token", sorted(B64_TOKENS))
@pytest.mark.parametrize("form", sorted(_PCT_TOKEN_FORMS))
def test_a_percent_encoded_character_inside_a_token_does_not_cut_it(
    form: str, token: str
) -> None:
    # The hit is the decoded token's claim: the same length, fingerprint and
    # last4 as the plain header holding it, so the two are one credential.
    text = _PCT_TOKEN_FORMS[form](B64_TOKENS[token])
    assert B64_TOKENS[token] not in text
    hits = _hits(text)
    plain = _hits(f"Authorization: Bearer {B64_TOKENS[token]}")
    assert _claims(hits) == [_claim(B64_TOKENS[token], "bearer_token", eligible=True)]
    assert _claims_with_last4(hits) == _claims_with_last4(plain)
    assert hits[0].prefix.lower() == "authorization: bearer"


@pytest.mark.parametrize(
    "decoded", [_v("abababab ababababab ab/+="), _v("abababab ababababab ab//==")]
)
@pytest.mark.parametrize("form", sorted(_PCT_TOKEN_FORMS))
def test_a_percent_encoded_low_entropy_token_is_judged_decoded(form: str, decoded: str) -> None:
    # The escapes' own characters (`%`, `2`, `F`, ...) are not the token's:
    # a value too uniform to be verdict-grade in a plain header is not made
    # verdict-grade by encoding it.
    plain = _hits(f"Authorization: Bearer {decoded}")
    assert _claims(plain) == [_claim(decoded, "bearer_token", eligible=False)]
    assert _claims(_hits(_PCT_TOKEN_FORMS[form](decoded))) == _claims(plain)


def test_a_url_encoded_placeholder_is_only_reviewed() -> None:
    hits = _hits("/v1/callback?authorization=Bearer%20YOUR_ACCESS_TOKEN_HERE")
    assert hits
    assert not any(h.eligible for h in hits)


def _field_documents(*, array: bool) -> dict[str, Callable[[str, str], str]]:
    """One credential field in each document shape, its value written as a
    one-item array (`array`) or as the plain string."""

    def one(v: str) -> object:
        return [v] if array else v

    def two(v: str) -> object:
        return [v, "m-1"] if array else v

    return {
        "json": lambda k, v: json.dumps({k: one(v), "model": "m-1"}),
        "compact": lambda k, v: json.dumps({k: one(v), "model": "m-1"}, separators=(",", ":")),
        "indented": lambda k, v: json.dumps({k: one(v), "model": "m-1"}, indent=2),
        "two-items": lambda k, v: json.dumps({k: two(v)}),
        "json-escaped": lambda k, v: json.dumps({"body": json.dumps({k: one(v), "model": "m-1"})}),
        "json-escaped-indented": lambda k, v: json.dumps(
            {"body": json.dumps({k: one(v), "model": "m-1"}, indent=2)}
        ),
        "python-repr": lambda k, v: repr({k: one(v), "model": "m-1"}),
    }


_ARRAY_FIELD_FORMS = _field_documents(array=True)
_STRING_FIELD_FORMS = _field_documents(array=False)


def _string_form(form: str, key: str, value: str) -> str:
    return _STRING_FIELD_FORMS[form](key, value)


@pytest.mark.parametrize(
    "key", ["api_key", "access_token", "client_secret", "password", "token", "Token"]
)
@pytest.mark.parametrize("form", sorted(_ARRAY_FIELD_FORMS))
def test_a_json_quoted_credential_field_with_an_array_value_is_found(form: str, key: str) -> None:
    hits = _hits(_ARRAY_FIELD_FORMS[form](key, FIELD))
    string = _hits(_string_form(form, key, FIELD))
    assert _claims(hits) == _claims(string)
    assert _claims(hits) == [_claim(FIELD, "json_credential_field", eligible=False)]
    assert hits[0].prefix == string[0].prefix == key


# Values the string form finds and values it rejects (a floor, a
# placeholder rule or the letter-and-digit rule under `token`).
_ARRAY_VALUES = {
    ("password", PASSPHRASE): True,
    ("password", f"don't {PASSPHRASE}"): True,
    ("token", "abc\\u00e9123456"): True,
    ("password", "*" * 12): False,
    ("password", "REDACTED"): False,
    ("api_key", "null"): False,
    ("api_key", "None"): False,
    ("api_key", "abc123"): False,
    ("token", "123456789012"): False,
    ("token", "Certainly"): False,
    ("token", "你好"): False,
    ("tokens", FIELD): False,
    ("max_tokens", FIELD): False,
    ("password_hint", FIELD): False,
    ("tokenizer", FIELD): False,
}


@pytest.mark.parametrize("form", ["json", "json-escaped", "python-repr", "indented"])
@pytest.mark.parametrize(("key", "value"), sorted(_ARRAY_VALUES))
def test_an_array_value_meets_the_same_floors_and_placeholder_rules(
    form: str, key: str, value: str
) -> None:
    hits = _hits(_ARRAY_FIELD_FORMS[form](key, value))
    assert _claims(hits) == _claims(_hits(_string_form(form, key, value)))
    assert bool(hits) is _ARRAY_VALUES[(key, value)]


# Array shapes that hold the value after nesting or after leading items that
# are not candidates: null, a number, or a string under the 8-character floor.
_ARRAY_SHAPES: dict[str, Callable[[str], object]] = {
    "nested": lambda v: [[v]],
    "nested-deep": lambda v: [[[v], "m-1"]],
    "null-first": lambda v: [None, v],
    "number-first": lambda v: [3, v],
    "empty-first": lambda v: ["", v],
    "short-first": lambda v: ["k1", v],
    "two-skipped": lambda v: [None, "k1", v],
    "nested-null-first": lambda v: [[None, v]],
}
_SHAPED_DOCUMENTS: dict[str, Callable[[str, object], str]] = {
    "json": lambda k, o: json.dumps({k: o, "model": "m-1"}),
    "compact": lambda k, o: json.dumps({k: o, "model": "m-1"}, separators=(",", ":")),
    "indented": lambda k, o: json.dumps({k: o, "model": "m-1"}, indent=2),
    "json-escaped": lambda k, o: json.dumps({"body": json.dumps({k: o, "model": "m-1"})}),
    "json-escaped-indented": lambda k, o: json.dumps(
        {"body": json.dumps({k: o, "model": "m-1"}, indent=2)}
    ),
    "python-repr": lambda k, o: repr({k: o, "model": "m-1"}),
}


@pytest.mark.parametrize("key", ["api_key", "token"])
@pytest.mark.parametrize("shape", sorted(_ARRAY_SHAPES))
@pytest.mark.parametrize("form", sorted(_SHAPED_DOCUMENTS))
def test_an_array_is_judged_by_its_first_string_item_of_8_or_more(
    form: str, shape: str, key: str
) -> None:
    hits = _hits(_SHAPED_DOCUMENTS[form](key, _ARRAY_SHAPES[shape](FIELD)))
    string = _hits(_SHAPED_DOCUMENTS[form](key, FIELD))
    assert _claims(hits) == _claims(string)
    assert _claims(hits) == [_claim(FIELD, "json_credential_field", eligible=False)]
    assert hits[0].prefix == string[0].prefix == key


@pytest.mark.parametrize("shape", ["nested", "null-first", "short-first"])
@pytest.mark.parametrize(("key", "value"), sorted(_ARRAY_VALUES))
def test_a_skipped_or_nested_array_value_meets_the_same_rules(
    shape: str, key: str, value: str
) -> None:
    hits = _hits(_SHAPED_DOCUMENTS["json"](key, _ARRAY_SHAPES[shape](value)))
    assert _claims(hits) == _claims(_hits(_SHAPED_DOCUMENTS["json"](key, value)))
    assert bool(hits) is _ARRAY_VALUES[(key, value)]


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"api_key": [], "model": "m-1-abcdefgh"}),
        json.dumps({"api_key": [12345678901]}),
        json.dumps({"api_key": [None, "m-1"]}),
        json.dumps({"api_key": [None, 3, "k1"]}),
        json.dumps({"password": [["********"]]}),
        json.dumps({"password": [None, "REDACTED"]}),
        # Leading items are skipped only inside an array: the next field of
        # the object is never read as the value.
        json.dumps({"api_key": None, "model_name_value": "m-1-abcdefgh"}),
        json.dumps({"api_key": "k1", "model_name_value": "m-1-abcdefgh"}),
        json.dumps({"api_key": 3, "model_name_value": "m-1-abcdefgh"}),
    ],
    ids=[
        "empty",
        "number",
        "null-then-short",
        "only-non-candidates",
        "nested-masked",
        "null-then-placeholder",
        "null-not-in-array",
        "short-not-in-array",
        "number-not-in-array",
    ],
)
def test_an_array_with_no_string_item_of_8_or_more_is_not_a_hit(text: str) -> None:
    assert _hits(text) == []


_LONG_RUN = 300
_RUN_VALUES = {
    "run-then-letter": "abc" + "\\" * _LONG_RUN + "d",
    "letters-then-run": "abcdefgh" + "\\" * 5,
    "run-in-middle": "abcd" + "\\" * 4 + "efgh",
    "short-plus-run": "abcde" + "\\" * 3,
}


@pytest.mark.parametrize("name", sorted(_RUN_VALUES))
def test_a_backslash_run_counts_one_character_per_backslash(name: str) -> None:
    # Every backslash of a run that does not end the value at a quote or an
    # escape letter is one character of the value, up to the 256 cap.
    value = _RUN_VALUES[name]
    hits = _hits(f"password={value} next")
    assert _claims(hits) == [_claim(value[:256], "credential_field", eligible=False)]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('password=abcdefgh' + "\\" * _LONG_RUN + '"', "abcdefgh"),
        ('password=abcdefgh' + "\\" * _LONG_RUN + "n", "abcdefgh"),
        ('{"password": "abcdefgh' + "\\" * _LONG_RUN + '"}', "abcdefgh"),
        ("{'password': 'abcdefgh" + "\\" * _LONG_RUN + "t'}", "abcdefgh"),
    ],
    ids=["field-quote", "field-escape", "json-quote", "repr-escape"],
)
def test_a_backslash_run_before_a_quote_or_escape_letter_ends_the_value(
    text: str, value: str
) -> None:
    hits = _hits(text)
    assert [(h.value_len, h.eligible) for h in hits] == [(len(value), False)]
