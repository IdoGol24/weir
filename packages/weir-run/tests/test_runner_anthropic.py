"""The Anthropic Messages API mock, end to end: `weir-run run` with a
Claude-shaped flow over real HTTP, judged by the real `weir canary judge`
(docs/canary.md, "Runtime values" and "Attribution").

These are the acceptance tests for the Messages API mock, locked before
the code they judge was written. The flow (`_anthropic_flow.py`) reaches
the mock through `ANTHROPIC_BASE_URL`, sends its key in `x-api-key`, gets
a scripted `tool_use`, answers it with a `tool_result` and streams the
final reply. Each expectation is the contract's rule for one case:

1. the key in `x-api-key`, the model API's credential field, is
   exercised, not a leak;
2. the same key inside a tool result sent back to the model is a leak to
   `model`;
3. the same key inside the user's message is a leak to `model`, once per
   request that carries the message.

The flow writes its fake key to a side file in the test's temporary
directory; that is the only way a test learns the value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from weir_run import cli
from weir_run import judge as judge_cli

PROBE = Path(__file__).parent / "_anthropic_flow.py"
REQUESTS_FILE = "capture/requests.jsonl"
PLACEMENT = "env.ANTHROPIC_API_KEY"
REPLY = "The project's .env sets LOG_LEVEL to info."
# The contract's printing rule: never a value or a
# fragment of 6 or more characters of one.
FRAGMENT = 6

CONFIG = """
[mock]
model_reply = {reply}

[[placement]]
id = "env.ANTHROPIC_API_KEY"
kind = "env"
shape = "anthropic"
required = true
provider = "model"

[[flow]]
id = "claude-turn"
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

    @property
    def placement(self) -> dict[str, Any]:
        return next(p for p in self.report["placements"] if p["id"] == PLACEMENT)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], mode: str) -> Outcome:
    side = tmp_path / "side.json"
    env = {"MODE": mode, "SIDE_FILE": side.as_posix()}
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items())
    config = tmp_path / "canary.toml"
    config.write_text(
        CONFIG.format(env=inline, probe=json.dumps(PROBE.as_posix()), reply=json.dumps(REPLY)),
        encoding="utf-8",
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
    # The flow finished its turn: the streamed final reply is in its relayed output.
    assert REPLY in result.output, result.output
    return outcome


def _assert_value_free(text: str, keys: list[str]) -> None:
    for key in keys:
        for i in range(len(key) - FRAGMENT + 1):
            assert key[i : i + FRAGMENT] not in text, "output holds a fragment of a canary"


def _leak_lines(stdout: str, location: str) -> list[str]:
    prefix = f"LEAK {PLACEMENT} file={REQUESTS_FILE}:"
    suffix = f" signal=requests sink={json.dumps('model')} at={location} form=raw"
    return [ln for ln in stdout.splitlines() if ln.startswith(prefix) and ln.endswith(suffix)]


def test_the_key_in_x_api_key_is_exercised_not_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "own")
    assert run.result.exit_code == 0, run.result.output
    assert run.report["result"] == "clean"
    assert run.hits == []
    assert "LEAK " not in run.result.stdout
    assert run.placement["state"] == "exercised"
    assert "request" in run.placement["evidence"]


def test_the_key_in_a_tool_result_is_a_leak_to_the_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "tool-result")
    location = "body.messages[2].content[0].content"
    assert run.result.exit_code == 1, run.result.output
    assert run.report["result"] == "leak"
    # Only the second request carries the tool result.
    assert run.hits == [(PLACEMENT, "requests", "model", location, "raw")]
    assert run.report["hits"][0]["file"] == REQUESTS_FILE
    assert len(_leak_lines(run.result.stdout, location)) == 1
    assert run.placement["state"] == "leaked"


def test_the_key_in_the_users_message_is_a_leak_to_the_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, "prompt")
    location = "body.messages[0].content"
    assert run.result.exit_code == 1, run.result.output
    assert run.report["result"] == "leak"
    # Both requests carry the user's message, so each is its own hit.
    assert run.hits == [(PLACEMENT, "requests", "model", location, "raw")] * 2
    assert len({h["line"] for h in run.report["hits"]}) == 2
    assert len(_leak_lines(run.result.stdout, location)) == 2
    assert run.placement["state"] == "leaked"
