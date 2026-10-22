"""The judge's request sink against docs/canary.md ("A placement's own
provider", "The request capture", "The text report").

Each test plants a fake value, places it in a request record built with
the standard library, and expects what the attribution rules say: in a
credential field of a request to the placement's own provider it is
evidence, anywhere else it is a hit naming the request's sink. Values are
prefix-free and synthetic.
"""

from __future__ import annotations

import base64
import json
import typing
from pathlib import Path
from urllib.parse import quote

import canary_fixtures as fx
import pytest
from click.testing import CliRunner

from weir.cli.main import main

SINK_PLACEMENT = "env.SEARCH_KEY"


def _otlp(tmp_path: Path) -> Path:
    """One clean span, so a run with nothing else wrong is complete."""
    path = tmp_path / "otlp.jsonl"
    fx.write(path, fx.traces(fx.span("clean")) + "\n")
    return path


def _run(
    tmp_path: Path,
    records: list[dict[str, object]],
    placements: list[dict[str, object]],
    *,
    as_json: bool = True,
) -> fx.Run:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", placements)
    requests = fx.write_requests(tmp_path / "requests.jsonl", records)
    run = fx.judge(ledger, [_otlp(tmp_path)], requests=[requests], as_json=as_json)
    fx.assert_value_free(
        run.stdout + run.stderr, [str(p["value"]) for p in placements if "value" in p]
    )
    return run


def _hits(run: fx.Run) -> list[tuple[str, str, str | None, str | None, str]]:
    hits = typing.cast(list[dict[str, typing.Any]], run.report["hits"])
    return [(h["placement"], h["signal"], h["sink"], h["location"], h["form"]) for h in hits]


def _state(run: fx.Run, pid: str) -> dict[str, typing.Any]:
    placements = typing.cast(list[dict[str, typing.Any]], run.report["placements"])
    return next(p for p in placements if p["id"] == pid)


# --- its own provider -------------------------------------------------------


def test_a_value_in_a_request_to_its_own_endpoint_is_request_evidence(tmp_path: Path) -> None:
    value = fx.fake_value("own")
    record = fx.request(headers=[("Authorization", f"Bearer {value}")])
    run = _run(tmp_path, [record], [fx.placement("env.MODEL_KEY", value, providers=["model"])])
    assert run.exit_code == 0, run.stdout
    assert _hits(run) == []
    assert _state(run, "env.MODEL_KEY")["state"] == "exercised"
    assert _state(run, "env.MODEL_KEY")["evidence"] == ["request"]


def test_a_model_key_in_the_prompt_of_its_own_model_request_is_a_leak_to_the_model(
    tmp_path: Path,
) -> None:
    value = fx.fake_value("prompt")
    body = json.dumps({"messages": [{"role": "user", "content": f"my key is {value}"}]})
    record = fx.request(headers=[("Authorization", f"Bearer {value}")], body=body.encode())
    run = _run(tmp_path, [record], [fx.placement("env.MODEL_KEY", value, providers=["model"])])
    assert run.exit_code == 1, run.stdout
    assert _hits(run) == [
        ("env.MODEL_KEY", "requests", "model", "body.messages[0].content", "raw")
    ]
    assert _state(run, "env.MODEL_KEY")["state"] == "leaked"
    # Its auth header is still its own provider's credential field.
    assert _state(run, "env.MODEL_KEY")["evidence"] == ["request"]


_FORM = ("Content-Type", "application/x-www-form-urlencoded")


@pytest.mark.parametrize(
    ("field", "place"),
    [
        (("header", "X-Api-Key"), lambda v: fx.request(headers=[("x-api-KEY", v)])),
        (("query", "key"), lambda v: fx.request(query=f"q=1&key={v}")),
        (("body", "api_key"), lambda v: fx.request(body=json.dumps({"api_key": v}).encode())),
        (("body", "auth"), lambda v: fx.request(body=json.dumps({"auth": [{"t": v}]}).encode())),
        (("body", "api_key"), lambda v: fx.request(headers=[_FORM], body=f"api_key={v}".encode())),
    ],
)
def test_only_its_own_endpoints_credential_fields_are_evidence(
    tmp_path: Path, field: tuple[str, str], place: typing.Callable[[str], dict[str, object]]
) -> None:
    value = fx.fake_value(f"field {field}")
    placement = fx.placement("env.MODEL_KEY", value, providers=["model"])
    record = place(value)
    declared = {**record, "credential_fields": [list(f) for f in (*fx.AUTH_HEADERS, field)]}
    run = _run(tmp_path, [declared], [placement])
    assert run.exit_code == 0, run.stdout
    assert _state(run, "env.MODEL_KEY")["evidence"] == ["request"]
    # The same request with the field not declared: the value is in no
    # credential field, so it is a leak to its own provider's sink.
    run = _run(tmp_path, [record], [placement])
    assert run.exit_code == 1, run.stdout
    assert [(h[0], h[2]) for h in _hits(run)] == [("env.MODEL_KEY", "model")]
    assert _state(run, "env.MODEL_KEY")["evidence"] == []


# A refused request to its provider host, as the mock records it: the auth
# headers and the fields its own endpoint declares.
_HOST = "api.search.invalid"
_HOST_FIELDS = (*fx.AUTH_HEADERS, ("header", "x-api-key"), ("query", "key"))


@pytest.mark.parametrize(
    "place",
    [
        lambda v: fx.request("refused", None, host=_HOST, port=80, headers=[("X-Api-Key", v)]),
        lambda v: fx.request("refused", None, host=_HOST, port=80, query=f"q=1&key={v}"),
    ],
    ids=["header:x-api-key", "query:key"],
)
def test_a_declared_field_of_its_endpoint_sent_to_its_provider_host_is_egress(
    tmp_path: Path, place: typing.Callable[[str], dict[str, object]]
) -> None:
    value = fx.fake_value("egress field")
    record = {**place(value), "credential_fields": [list(f) for f in _HOST_FIELDS]}
    placement = fx.placement(SINK_PLACEMENT, value, providers=["search"], provider_host=_HOST)
    run = _run(tmp_path, [record], [placement])
    assert run.exit_code == 0, run.stdout
    assert _hits(run) == []
    assert _state(run, SINK_PLACEMENT)["evidence"] == ["egress"]


def test_a_value_in_the_body_of_a_refused_request_to_its_provider_host_is_a_leak(
    tmp_path: Path,
) -> None:
    value = fx.fake_value("egress body")
    body = json.dumps({"key": value}).encode()
    record = fx.request(
        "refused", None, host=_HOST, port=80, body=body, credential_fields=_HOST_FIELDS
    )
    placement = fx.placement(SINK_PLACEMENT, value, providers=["search"], provider_host=_HOST)
    run = _run(tmp_path, [record], [placement])
    assert _hits(run) == [(SINK_PLACEMENT, "requests", f"{_HOST} (blocked)", "body.key", "raw")]
    assert _state(run, SINK_PLACEMENT)["evidence"] == ["egress"]


def test_a_request_to_its_own_endpoint_without_the_value_is_no_evidence(tmp_path: Path) -> None:
    value = fx.fake_value("unused")
    record = fx.request(headers=[("Authorization", "Bearer unrelated")])
    run = _run(tmp_path, [record], [fx.placement("env.MODEL_KEY", value, providers=["model"])])
    assert _state(run, "env.MODEL_KEY")["state"] == "not_exercised"


@pytest.mark.parametrize("outcome", ["refused", "connect"])
def test_a_blocked_request_to_its_provider_host_is_egress_evidence(
    tmp_path: Path, outcome: str
) -> None:
    value = fx.fake_value("egress")
    headers = [("Authorization", f"Bearer {value}")]
    # The host is matched without regard to letter case.
    record = fx.request(outcome, None, host="api.search.invalid", port=443, headers=headers)
    placement = fx.placement(SINK_PLACEMENT, value, provider_host="API.Search.invalid")
    run = _run(tmp_path, [record], [placement])
    assert _hits(run) == []
    assert _state(run, SINK_PLACEMENT)["evidence"] == ["egress"]
    assert run.exit_code == 0, run.stdout


def test_a_minted_token_belongs_to_every_provider_it_lists(tmp_path: Path) -> None:
    value = fx.fake_value("token")
    pid = "runtime.oauth.access_token#1"
    records = [
        fx.request("served", "search", headers=[("Authorization", f"Bearer {value}")]),
        fx.request(
            "served",
            "oauth",
            headers=[("Content-Type", "application/x-www-form-urlencoded")],
            body=f"refresh_token={value}".encode(),
            credential_fields=[*fx.AUTH_HEADERS, ("body", "refresh_token")],
        ),
        fx.request("served", "model", headers=[("Authorization", f"Bearer {value}")]),
    ]
    placement = fx.placement(pid, value, kind="mock-oauth", providers=["oauth", "search"])
    run = _run(
        tmp_path,
        records,
        [placement, {"type": "exercised", "placement": pid, "evidence": "minted"}],
    )
    assert _hits(run) == [(pid, "requests", "model", "headers.authorization", "raw")]
    assert _state(run, pid)["evidence"] == ["minted", "request"]


# --- anywhere else: the sink ------------------------------------------------


@pytest.mark.parametrize(
    ("record", "sink"),
    [
        (fx.request("served", "model"), "model"),
        (fx.request("served", "oauth", path="/oauth/token"), "oauth"),
        (fx.request("served", "otlp", path="/v1/traces", body=None), "otlp"),
        (fx.request("served", "billing", path="/ep/billing/x"), "billing"),
        (fx.request("served", None, path="/elsewhere"), "unmocked"),
        (
            fx.request("refused", None, host="collector.invalid", port=80),
            "collector.invalid (blocked)",
        ),
        (
            fx.request("connect", None, host="api.other.invalid", port=443),
            "api.other.invalid (blocked)",
        ),
    ],
)
def test_a_value_anywhere_else_is_a_leak_naming_the_sink(
    tmp_path: Path, record: dict[str, object], sink: str
) -> None:
    value = fx.fake_value(f"sink {sink}")
    record = {**record, "headers": [["X-Api-Key", value]]}
    run = _run(tmp_path, [record], [fx.placement(SINK_PLACEMENT, value, providers=["search"])])
    assert run.exit_code == 1
    assert _hits(run) == [(SINK_PLACEMENT, "requests", sink, "headers.x-api-key", "raw")]
    assert _state(run, SINK_PLACEMENT)["state"] == "leaked"


def test_a_placement_with_no_provider_leaks_in_any_request(tmp_path: Path) -> None:
    value = fx.fake_value("nowhere")
    record = fx.request(headers=[("Authorization", f"Bearer {value}")])
    run = _run(tmp_path, [record], [fx.placement("code.local.secret", value, kind="code")])
    assert _hits(run) == [
        ("code.local.secret", "requests", "model", "headers.authorization", "raw")
    ]


def test_every_encoded_form_is_matched_in_a_request(tmp_path: Path) -> None:
    value = fx.fake_value("forms")
    basic = base64.b64encode(f"client:{value}".encode()).decode()
    records = [
        fx.request(headers=[("Authorization", f"Basic {basic}")]),
        fx.request(headers=[("X-Hex", value.encode().hex())]),
    ]
    run = _run(tmp_path, records, [fx.placement(SINK_PLACEMENT, value)])
    assert _hits(run) == [
        (SINK_PLACEMENT, "requests", "model", "headers.authorization", "base64"),
        (SINK_PLACEMENT, "requests", "model", "headers.x-hex", "hex"),
    ]


def test_the_path_query_and_form_fields_are_also_searched_percent_decoded(
    tmp_path: Path,
) -> None:
    # Escaping a character that needs none defeats every encoded form; only
    # the percent-decoded part holds the value.
    value = fx.fake_value("decoded")
    escaped = "".join(f"%{ord(ch):02X}" for ch in value)
    form = [("Content-Type", "application/x-www-form-urlencoded")]
    records = [
        fx.request(path=f"/files/{escaped}"),
        fx.request(query=f"k1={escaped}"),
        fx.request(headers=form, body=f"k1={escaped}".encode()),
    ]
    run = _run(tmp_path, records, [fx.placement(SINK_PLACEMENT, value)])
    assert [h[3] for h in _hits(run)] == ["path", "query.k1", "body.k1"]


def test_a_text_hit_line_names_the_sink_and_the_field(tmp_path: Path) -> None:
    value = fx.fake_value("text line")
    body = json.dumps({"messages": [{"role": "user", "content": f"key {value}"}]}).encode()
    run = _run(
        tmp_path, [fx.request(body=body)], [fx.placement(SINK_PLACEMENT, value)], as_json=False
    )
    assert fx.leak_lines(run) == [
        f"LEAK {SINK_PLACEMENT} file={tmp_path / 'requests.jsonl'}:2 signal=requests"
        ' sink="model" at=body.messages[0].content form=raw'
    ]


def test_the_field_names_are_printed_under_the_printing_rule(tmp_path: Path) -> None:
    value = fx.fake_value("names")
    records = [
        fx.request(headers=[(f"X-{value}", "1")]),
        # A run of 6 consecutive characters of the value is withheld, 5 is not.
        fx.request(query=f"q{value[2:8]}={value}"),
        fx.request(query=f"q{value[2:7]}={value}"),
    ]
    run = _run(tmp_path, records, [fx.placement(SINK_PLACEMENT, value)])
    locations = [h[3] for h in _hits(run)]
    assert locations == ["headers.[withheld]", "query.[withheld]", f"query.q{value[2:7]}"]


def test_a_blocked_host_holding_a_value_is_withheld_in_the_sink(tmp_path: Path) -> None:
    value = fx.fake_value("host")
    host = f"{value.lower()}.exfil.invalid"
    record = fx.request("connect", None, host=host, port=443)
    run = _run(tmp_path, [record], [fx.placement(SINK_PLACEMENT, value.lower())])
    assert _hits(run) == [(SINK_PLACEMENT, "requests", "[withheld] (blocked)", "host", "raw")]
    assert typing.cast(list[dict[str, object]], run.report["blocked"]) == [
        {"kind": "connection", "host": "[withheld]", "port": 443, "count": 1}
    ]


# --- blocked connection attempts --------------------------------------------


def test_blocked_destinations_are_listed_and_counted_never_leaks(tmp_path: Path) -> None:
    value = fx.fake_value("unused")
    records = [
        fx.request("connect", None, host="b.invalid", port=443),
        fx.request("connect", None, host="b.invalid", port=443),
        fx.request("connect", None, host="a.invalid", port=8443),
        fx.request("refused", None, host="c.invalid", port=80),
        fx.request(),
    ]
    run = _run(tmp_path, records, [fx.placement(SINK_PLACEMENT, value)], as_json=False)
    assert run.exit_code == 0, run.stdout
    assert [ln for ln in run.lines if ln.startswith("blocked ")] == [
        "blocked connection: a.invalid:8443 (1x)",
        "blocked connection: b.invalid:443 (2x)",
        "blocked request: c.invalid:80 (1x)",
    ]
    coverage = next(ln for ln in run.lines if ln.startswith("coverage: "))
    assert coverage.endswith(", 5 requests (1 refused, 3 blocked connections)")
    report = _run(tmp_path, records, [fx.placement(SINK_PLACEMENT, value)]).report
    counts = typing.cast(dict[str, int], report["coverage"])
    assert (counts["request_files"], counts["requests"]) == (1, 5)
    assert (counts["requests_refused"], counts["connections_blocked"]) == (1, 3)


def test_without_a_request_capture_the_coverage_line_is_unchanged(tmp_path: Path) -> None:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", fx.fake_value("x"))])
    run = fx.judge(ledger, [_otlp(tmp_path)])
    coverage = next(ln for ln in run.lines if ln.startswith("coverage: "))
    assert coverage.endswith(" bytes swept")


# --- what cannot be attributed ----------------------------------------------


def test_a_line_that_is_not_a_request_record_is_swept_raw_and_incomplete(tmp_path: Path) -> None:
    value = fx.fake_value("unparsed")
    ledger = fx.write_ledger(
        tmp_path / "ledger.jsonl", [fx.placement(SINK_PLACEMENT, value, providers=["model"])]
    )
    requests = tmp_path / "requests.jsonl"
    good = json.dumps(fx.request())
    # Even a value that could be its own provider's is a hit: nothing says
    # where an unparsed line went.
    fx.write(requests, f'{{"schema": "canary-requests/1"}}\n{good}\n{{"outcome": "x {value}"}}\n')
    run = fx.judge(ledger, [_otlp(tmp_path)], requests=[requests], as_json=True)
    assert run.exit_code == 1
    assert _hits(run) == [(SINK_PLACEMENT, "raw", None, None, "raw")]
    assert typing.cast(list[dict[str, object]], run.report["incomplete"]) == [
        {"reason": "unparsed_record", "subject": f"{requests}:3"}
    ]


def test_a_truncated_last_line_is_unparsed(tmp_path: Path) -> None:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", fx.fake_value("t"))])
    requests = tmp_path / "requests.jsonl"
    fx.write(requests, '{"schema": "canary-requests/1"}\n' + json.dumps(fx.request()))
    run = fx.judge(ledger, [_otlp(tmp_path)], requests=[requests])
    assert run.exit_code == 3
    assert f"incomplete: unparsed_record {requests}:2" in run.lines


@pytest.mark.parametrize("unread", ["encoding", "too_large", "error"])
def test_an_unread_body_is_judged_as_given_and_incomplete(tmp_path: Path, unread: str) -> None:
    value = fx.fake_value("unread")
    body = b"\x0bopaque" if unread == "encoding" else None
    record = fx.request(headers=[("X-Key", value)], body=body, unread=unread)
    run = _run(tmp_path, [record], [fx.placement(SINK_PLACEMENT, value)])
    assert _hits(run) == [(SINK_PLACEMENT, "requests", "model", "headers.x-key", "raw")]
    assert typing.cast(list[dict[str, object]], run.report["incomplete"]) == [
        {"reason": "unparsed_record", "subject": f"{tmp_path / 'requests.jsonl'}:2"}
    ]


@pytest.mark.parametrize(
    "content", ["", "\n", '{"schema": "canary-ledger/1"}\n', json.dumps(fx.request()) + "\n"]
)
def test_a_file_without_the_header_is_unusable(tmp_path: Path, content: str) -> None:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", fx.fake_value("h"))])
    requests = tmp_path / "requests.jsonl"
    fx.write(requests, content)
    run = fx.judge(ledger, [_otlp(tmp_path)], requests=[requests])
    assert run.exit_code == 2
    assert run.stdout == ""
    assert "not a request capture" in run.stderr


def test_sample_takes_no_request_capture(tmp_path: Path) -> None:
    requests = fx.write_requests(tmp_path / "requests.jsonl", [])
    result = CliRunner().invoke(main, ["canary", "judge", "--sample", "--requests", str(requests)])
    assert result.exit_code == 2
    assert "--requests" in result.stderr


# --- determinism ------------------------------------------------------------


def test_two_runs_with_fresh_values_print_identical_reports(tmp_path: Path) -> None:
    outputs: list[str] = []
    for seed in ("first", "second"):
        root = tmp_path / seed
        root.mkdir()
        model, search = fx.fake_value(f"{seed} model"), fx.fake_value(f"{seed} search")
        body = json.dumps({"messages": [{"content": search}]}).encode()
        records = [
            fx.request(headers=[("Authorization", f"Bearer {model}")], body=body),
            fx.request("refused", None, host="c.invalid", port=80, query=f"k={quote(search)}"),
            fx.request("connect", None, host="d.invalid", port=443),
        ]
        placements = [
            fx.placement("env.MODEL_KEY", model, providers=["model"]),
            fx.placement(SINK_PLACEMENT, search, providers=["search"]),
        ]
        ledger = fx.write_ledger(root / "ledger.jsonl", placements)
        requests = fx.write_requests(root / "requests.jsonl", records)
        for as_json in (False, True):
            run = fx.judge(ledger, [_otlp(root)], requests=[requests], as_json=as_json)
            outputs.append(run.stdout.replace(str(root), "ROOT"))
    assert outputs[:2] == outputs[2:]
