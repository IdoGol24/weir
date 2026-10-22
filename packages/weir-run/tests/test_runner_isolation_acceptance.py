"""Acceptance tests for network isolation, locked before the implementation.

Two captain tests (docs/canary.md, "Network isolation"):

- with isolation on, a client that bypasses the proxy fails and is reported;
- without isolation, the report carries the line "network not isolated:
  direct connections were not observed", and `--require-isolation` turns
  that run into incomplete, exit 3.

The flow plants nothing real: its key is the runner's fake canary, it talks
to the mock on 127.0.0.1, and its one direct connection goes to 203.0.113.7,
an address in TEST-NET-3 (RFC 5737) that is never routed on the internet.

Isolation needs Linux and unprivileged user and network namespaces. Where
the runner reports it unavailable, the isolated cases skip, unless
WEIR_TEST_REQUIRE_NETNS is set (CI on Linux sets it), when they fail.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from weir_run import cli, isolation
from weir_run import judge as judge_cli

NOT_ISOLATED_LINE = "network not isolated: direct connections were not observed"
FOREIGN = "203.0.113.7"

FLOW = """
import json, os, socket, urllib.request

def post(url, body, headers):
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()

key = os.environ["APP_KEY"]
mock = os.environ["CANARY_MOCK_URL"]
post(mock + "/v1/chat/completions", b"{}",
     {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "clean span"}]}]}]}
post(os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"], json.dumps(doc).encode(),
     {"Content-Type": "application/json"})
outcome = "not attempted"
if os.environ.get("BYPASS") == "1":
    # A client that ignores the proxy settings: a raw socket, straight out.
    try:
        socket.create_connection((%(foreign)r, 443), timeout=5).close()
        outcome = "connected"
    except OSError as exc:
        outcome = "failed " + type(exc).__name__
with open(os.environ["SIDE_FILE"], "w", encoding="utf-8") as side:
    side.write(outcome)
"""

CONFIG = """
[[placement]]
id = "env.APP_KEY"
kind = "env"
required = true
provider = "model"

[[flow]]
id = "main"
command = ["{{python}}", {flow}]
env = {{ SIDE_FILE = {side}, BYPASS = {bypass} }}
"""


def _config(tmp_path: Path, *, bypass: bool) -> tuple[Path, Path]:
    flow = tmp_path / "flow.py"
    flow.write_text(FLOW % {"foreign": FOREIGN}, encoding="utf-8")
    side = tmp_path / "side.txt"
    config = tmp_path / "canary.toml"
    config.write_text(
        CONFIG.format(
            flow=json.dumps(flow.as_posix()),
            side=json.dumps(side.as_posix()),
            bypass=json.dumps("1" if bypass else "0"),
        ),
        encoding="utf-8",
    )
    return config, side


def _run(
    monkeypatch: pytest.MonkeyPatch, judge: list[str], config: Path, *args: str
) -> tuple[Result, dict[str, Any]]:
    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    report = config.parent / "report.json"
    result = CliRunner().invoke(
        cli.main, ["run", "--config", str(config), "--report", str(report), *args]
    )
    doc: dict[str, Any] = json.loads(report.read_text()) if report.exists() else {}
    return result, doc


def _require_isolated(result: Result) -> None:
    """Skip a case that needs isolation where the runner says it has none."""
    if NOT_ISOLATED_LINE in result.stdout:
        if os.environ.get("WEIR_TEST_REQUIRE_NETNS"):
            pytest.fail(f"isolation is required here but was unavailable:\n{result.output}")
        pytest.skip("network isolation is not available on this machine")


def _unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def jail() -> isolation.Jail:
        raise isolation.Unavailable("user namespaces are disabled")

    monkeypatch.setattr(isolation, "jail", jail)


# -- captain test 6: with isolation on, a bypassing client fails and is reported


def test_isolated_a_client_that_bypasses_the_proxy_fails_and_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, side = _config(tmp_path, bypass=True)
    result, report = _run(monkeypatch, judge, config)
    _require_isolated(result)

    # The direct connection failed inside the flow: nothing left the host.
    assert side.read_text().startswith("failed "), side.read_text()
    # The run's own output names it...
    assert f"blocked direct tcp connection to {FOREIGN}:443 from flow main" in result.stderr
    # ...and so does the judge: a blocked direct attempt makes the run
    # incomplete, because what it would have carried was never seen.
    assert result.exit_code == 3, result.output
    lines = result.stdout.splitlines()
    assert f"incomplete: direct_connection main=tcp:{FOREIGN}:443" in lines
    assert "network isolated: 1 direct connections blocked" in lines
    assert lines[-1] == "result: incomplete"
    assert report["network"] == {
        "isolated": True,
        "required": False,
        "direct": [{"flow": "main", "protocol": "tcp", "target": f"{FOREIGN}:443", "attempts": 1}],
    }
    assert {"reason": "direct_connection", "subject": f"main=tcp:{FOREIGN}:443"} in report[
        "incomplete"
    ]


def test_isolated_a_clean_run_passes_with_require_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, side = _config(tmp_path, bypass=False)
    result, report = _run(monkeypatch, judge, config, "--require-isolation")
    _require_isolated(result)

    assert side.read_text() == "not attempted"
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert "network isolated: 0 direct connections blocked" in lines
    assert lines[-1] == "result: clean"
    assert report["network"] == {"isolated": True, "required": True, "direct": []}


# -- captain test 7: without isolation, the line, and --require-isolation exits 3


def test_without_isolation_the_coverage_line_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _unavailable(monkeypatch)
    config, _ = _config(tmp_path, bypass=False)
    result, report = _run(monkeypatch, judge, config)
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert NOT_ISOLATED_LINE in lines
    assert lines[-1] == "result: clean"
    assert report["network"] == {"isolated": False, "required": False, "direct": []}


def test_where_isolation_is_unavailable_the_run_goes_ahead_and_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _unavailable(monkeypatch)
    config, _ = _config(tmp_path, bypass=False)
    result, report = _run(monkeypatch, judge, config)
    assert result.exit_code == 0, result.output
    assert "network: not isolated (user namespaces are disabled)" in result.stderr
    assert NOT_ISOLATED_LINE in result.stdout.splitlines()
    assert report["network"] == {"isolated": False, "required": False, "direct": []}


def test_require_isolation_makes_an_unisolated_run_incomplete_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _unavailable(monkeypatch)
    config, _ = _config(tmp_path, bypass=False)
    result, report = _run(monkeypatch, judge, config, "--require-isolation")
    assert result.exit_code == 3, result.output
    lines = result.stdout.splitlines()
    assert "incomplete: network_not_isolated" in lines
    assert NOT_ISOLATED_LINE in lines
    assert lines[-1] == "result: incomplete"
    assert report["result"] == "incomplete"
    assert report["exit_code"] == 3
    assert {"reason": "network_not_isolated", "subject": None} in report["incomplete"]
    assert report["network"] == {"isolated": False, "required": True, "direct": []}


def test_require_isolation_never_hides_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # A found leak outranks incompleteness (docs/canary.md, "Coverage states").
    _unavailable(monkeypatch)
    config, side = _config(tmp_path, bypass=False)
    flow = tmp_path / "flow.py"
    flow.write_text(
        flow.read_text().replace('"clean span"', '"leaky span " + key'), encoding="utf-8"
    )
    result, _ = _run(monkeypatch, judge, config, "--require-isolation")
    assert result.exit_code == 1, result.output
    assert "incomplete: network_not_isolated" in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == "result: leak"
    assert side.read_text() == "not attempted"
