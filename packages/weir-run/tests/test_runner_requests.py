"""Outbound requests as a sink, end to end: `weir-run run` with a real flow
over real HTTP, judged by the real `weir canary judge` (docs/canary.md,
"A placement's own provider" and "The request capture").

These are the acceptance tests for the request sink, locked before the
code they judge was written. Each expectation is the contract's rule for
one case:

1. a key in a prompt is a leak to `model`;
2. a tool key in the model API's auth header is a leak to `model`;
3. a key in its own provider's auth header is exercised, not a leak;
4. a key in a plain-HTTP request to a foreign host is a leak to
   `<host> (blocked)`;
5. an HTTPS CONNECT to a foreign host is a blocked connection attempt in
   the coverage, not a leak.

The flow (`_request_flow.py`) writes its fake keys to a side file in the
test's temporary directory; that is the only way a test learns a value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from _network import NetworkLog
from click.testing import CliRunner, Result

from weir_run import cli
from weir_run import judge as judge_cli

PROBE = Path(__file__).parent / "_request_flow.py"
REQUESTS_FILE = "capture/requests.jsonl"
FOREIGN_HTTP_HOST = "collector.foreign.invalid"
FOREIGN_HTTPS_HOST = "api.foreign.invalid"
# The contract's printing rule: never a value or a
# fragment of 6 or more characters of one.
FRAGMENT = 6

CONFIG = """
[[mock.endpoint]]
id = "search"
reply = '{{"results": []}}'

[[placement]]
id = "env.MODEL_KEY"
kind = "env"
required = true
provider = "model"

[[placement]]
id = "env.SEARCH_KEY"
kind = "env"
required = true
provider = "search"

[[flow]]
id = "probe"
command = ["{{python}}", {probe}]
timeout_seconds = 60
env = {{ {env} }}
"""


class Outcome:
    def __init__(self, result: Result, report: dict[str, Any], keys: list[str]) -> None:
        self.result = result
        self.report = report
        self.keys = keys

    @property
    def hits(self) -> list[tuple[str, str, str | None, str | None, str]]:
        return [
            (h["placement"], h["signal"], h["sink"], h["location"], h["form"])
            for h in self.report["hits"]
        ]

    def placement(self, pid: str) -> dict[str, Any]:
        return next(p for p in self.report["placements"] if p["id"] == pid)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], mode: str) -> Outcome:
    side = tmp_path / "side.json"
    env = {"SEARCH_BASE_URL": "{mock}/ep/search", "MODE": mode, "SIDE_FILE": side.as_posix()}
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items())
    config = tmp_path / "canary.toml"
    config.write_text(
        CONFIG.format(env=inline, probe=json.dumps(PROBE.as_posix())), encoding="utf-8"
    )
    report = tmp_path / "report.json"

    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config), "--report", str(report)])
    assert report.exists(), result.output
    keys: list[str] = json.loads(side.read_text(encoding="utf-8"))
    outcome = Outcome(result, json.loads(report.read_text(encoding="utf-8")), keys)
    _assert_value_free(result.output + report.read_text(encoding="utf-8"), keys)
    return outcome


def _assert_value_free(text: str, keys: list[str]) -> None:
    for key in keys:
        for i in range(len(key) - FRAGMENT + 1):
            assert key[i : i + FRAGMENT] not in text, "output holds a fragment of a canary"


def _leak_line(sink: str, location: str) -> re.Pattern[str]:
    return re.compile(
        rf"^LEAK env\.SEARCH_KEY file={re.escape(REQUESTS_FILE)}:\d+ signal=requests"
        rf" sink={re.escape(json.dumps(sink))} at={re.escape(location)} form=raw$",
        re.MULTILINE,
    )


def test_a_key_in_a_prompt_is_a_leak_to_the_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "prompt")
    assert run.result.exit_code == 1, run.result.output
    assert run.report["result"] == "leak"
    assert run.hits == [("env.SEARCH_KEY", "requests", "model", "body.messages[0].content", "raw")]
    assert run.report["hits"][0]["file"] == REQUESTS_FILE
    assert _leak_line("model", "body.messages[0].content").search(run.result.stdout)
    assert run.placement("env.SEARCH_KEY")["state"] == "leaked"
    # The model's own key went to the model: exercised, not a leak.
    assert run.placement("env.MODEL_KEY")["state"] == "exercised"
    assert "request" in run.placement("env.MODEL_KEY")["evidence"]


def test_a_tool_key_in_the_model_apis_auth_header_is_a_leak_to_the_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "model-auth")
    assert run.result.exit_code == 1, run.result.output
    assert run.report["result"] == "leak"
    assert run.hits == [("env.SEARCH_KEY", "requests", "model", "headers.authorization", "raw")]
    assert _leak_line("model", "headers.authorization").search(run.result.stdout)
    assert run.placement("env.SEARCH_KEY")["state"] == "leaked"
    assert run.placement("env.MODEL_KEY")["state"] == "exercised"


def test_a_key_in_its_own_providers_auth_header_is_exercised_not_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "own")
    assert run.result.exit_code == 0, run.result.output
    assert run.report["result"] == "clean"
    assert run.hits == []
    assert "LEAK " not in run.result.stdout
    for pid in ("env.MODEL_KEY", "env.SEARCH_KEY"):
        placement = run.placement(pid)
        assert placement["state"] == "exercised", pid
        assert "request" in placement["evidence"], pid
    assert run.report["blocked"] == []


def test_a_key_in_a_plain_http_request_to_a_foreign_host_is_a_blocked_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], network_log: NetworkLog
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "foreign-http")
    sink = f"{FOREIGN_HTTP_HOST} (blocked)"
    assert run.result.exit_code == 1, run.result.output
    assert run.report["result"] == "leak"
    assert run.hits == [("env.SEARCH_KEY", "requests", sink, "body.key", "raw")]
    assert _leak_line(sink, "body.key").search(run.result.stdout)
    assert run.report["blocked"] == [
        {"kind": "request", "host": FOREIGN_HTTP_HOST, "port": 80, "count": 1}
    ]
    assert run.report["coverage"]["requests_refused"] == 1
    # Refused, never forwarded: the mock itself reached and resolved nothing.
    assert network_log.refused == []


def test_an_https_connect_to_a_foreign_host_is_a_blocked_attempt_not_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], network_log: NetworkLog
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "foreign-connect")
    assert run.result.exit_code == 0, run.result.output
    assert run.report["result"] == "clean"
    assert run.hits == []
    assert run.report["blocked"] == [
        {"kind": "connection", "host": FOREIGN_HTTPS_HOST, "port": 443, "count": 1}
    ]
    assert run.report["coverage"]["connections_blocked"] == 1
    assert f"blocked connection: {FOREIGN_HTTPS_HOST}:443 (1x)" in run.result.stdout.splitlines()
    coverage = next(ln for ln in run.result.stdout.splitlines() if ln.startswith("coverage: "))
    assert coverage.endswith(" requests (0 refused, 1 blocked connections)")
    assert network_log.refused == []
