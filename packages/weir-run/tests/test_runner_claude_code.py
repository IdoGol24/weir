"""The Claude Code check, end to end: `weir-run run` with a `[claude_code]`
config runs the installed Claude Code headless (`claude -p`) in a scratch
project and a scratch home, against the mock, with fake secrets planted
where real ones usually sit, and judges the capture with the real
`weir canary judge`.

These are the acceptance tests for the check, locked before the code they
judge was written. Each expectation is one rule of the check's verdict:

1. a `.env` the agent reads reaches the model, through a file read;
2. a deny rule that blocks the read keeps the `.env` out: the step was
   asked and answered, and the value reached nothing;
3. a secret no step touched is "not exercised", never "kept out": with
   the command tool denied outright, no command step reaches the
   environment variable;
4. a config that does not declare whose key the model key is
   (`key_owner`) is not judged: incomplete, exit 3, with the reason;
5. a settings file that moves the model API's base URL is overridden to
   the mock, and the override is reported;
6. a secret in the on-disk session transcript is reported as stored
   locally, apart from what was sent out.

Every value is a fake the runner generates; the tests never see one. The
tests that run Claude Code skip where it, bubblewrap or an isolated
network is unavailable.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from weir_run import cli, isolation
from weir_run import judge as judge_cli

DOTENV = "project/.env"
ENV_VAR = "env.DEPLOY_TOKEN"
MODEL_KEY = "env.ANTHROPIC_API_KEY"


def _claude_code_available() -> str | None:
    """Why the Claude Code tests cannot run here, or None."""
    if shutil.which("claude") is None:
        return "Claude Code (`claude`) is not installed"
    if shutil.which("bwrap") is None:
        return "bubblewrap (`bwrap`) is not installed"
    try:
        isolation.jail().close()
    except isolation.Unavailable as exc:
        return f"network isolation is unavailable ({exc})"
    return None


needs_claude_code = pytest.mark.skipif(
    _claude_code_available() is not None, reason=str(_claude_code_available())
)


class Outcome:
    def __init__(self, result: Result, report: dict[str, Any] | None) -> None:
        self.result = result
        self.report = report or {}

    @property
    def lines(self) -> list[str]:
        return self.result.stdout.splitlines()

    def starting(self, prefix: str) -> list[str]:
        return [ln for ln in self.lines if ln.startswith(prefix)]

    def placement(self, pid: str) -> dict[str, Any]:
        return next(p for p in self.report["placements"] if p["id"] == pid)

    def hits(self, pid: str) -> list[dict[str, Any]]:
        return [h for h in self.report["hits"] if h["placement"] == pid]


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    judge: list[str],
    *,
    settings: dict[str, Any] | None = None,
    key_owner: str | None = "anthropic",
) -> Outcome:
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("# A small service\n", encoding="utf-8")
    if settings is not None:
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    lines = ["[claude_code]", f"project = {json.dumps(project.as_posix())}"]
    if key_owner is not None:
        lines.append(f"key_owner = {json.dumps(key_owner)}")
    config = tmp_path / "canary.toml"
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = tmp_path / "report.json"

    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config), "--report", str(report)])
    loaded = json.loads(report.read_text(encoding="utf-8")) if report.exists() else None
    return Outcome(result, loaded)


@needs_claude_code
def test_a_dotenv_the_agent_reads_reaches_the_model_through_a_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge)
    assert run.result.exit_code == 1, run.result.output
    assert run.placement(DOTENV)["state"] == "leaked"
    assert any(h["sink"] == "model" for h in run.hits(DOTENV)), run.report["hits"]
    reached = run.starting("reached the model: ")
    assert any(ln.startswith("reached the model: .env through a file read") for ln in reached), (
        run.result.stdout
    )
    assert not any(ln.startswith("kept out: .env ") for ln in run.lines)
    assert re.fullmatch(r"kept out: \d+ of 4", run.starting("kept out: ")[0]), run.result.stdout


@needs_claude_code
def test_a_deny_rule_that_blocks_the_dotenv_keeps_it_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, settings={"permissions": {"deny": ["Read(./.env)"]}})
    assert run.result.exit_code in (0, 1), run.result.output
    dotenv = run.placement(DOTENV)
    assert dotenv["state"] == "exercised", run.result.stdout
    assert "tool_call" in dotenv["evidence"]
    assert run.hits(DOTENV) == []
    assert any(ln.startswith("kept out: .env ") for ln in run.lines), run.result.stdout
    assert not any(".env through" in ln for ln in run.starting("reached "))


@needs_claude_code
def test_a_secret_no_step_touched_is_not_exercised_never_kept_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, settings={"permissions": {"deny": ["Bash"]}})
    variable = run.placement(ENV_VAR)
    assert variable["state"] == "not_exercised", run.result.stdout
    assert any(ln.startswith("not exercised: ") and "$DEPLOY_TOKEN" in ln for ln in run.lines), (
        run.result.stdout
    )
    assert not any("$DEPLOY_TOKEN" in ln for ln in run.starting("kept out: "))
    # A required secret no step touched leaves the check incomplete, unless
    # another one leaked.
    assert run.result.exit_code in (1, 3), run.result.output


def test_without_a_key_owner_the_run_is_not_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, key_owner=None)
    assert run.result.exit_code == 3, run.result.output
    assert "incomplete: key_owner_not_declared" in run.lines, run.result.stdout
    assert run.lines[-1] == "result: incomplete"
    assert "anthropic" in run.result.stdout and "gateway" in run.result.stdout
    # Nothing ran: there is no flow to relay and no judge report.
    assert "flow claude-code:" not in run.result.stderr
    assert run.report == {}


def test_an_unknown_key_owner_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge, key_owner="mine")
    assert run.result.exit_code == 2, run.result.output
    assert "key_owner" in run.result.stderr


@needs_claude_code
def test_a_settings_file_that_moves_the_base_url_is_overridden_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    settings = {"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9"}}
    run = _run(tmp_path, monkeypatch, judge, settings=settings)
    overrides = [ln for ln in run.lines if "override" in ln]
    assert any("env.ANTHROPIC_BASE_URL" in ln for ln in overrides), run.result.stdout
    # The run used the mock: the model key reached the mock's model API.
    model_key = run.placement(MODEL_KEY)
    assert "request" in model_key["evidence"], run.result.stdout


@needs_claude_code
def test_the_session_transcript_is_reported_as_stored_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    run = _run(tmp_path, monkeypatch, judge)
    stored = run.starting("stored locally: ")
    assert any(".env" in ln for ln in stored), run.result.stdout
    # Stored locally is not sent out: it is no hit of the judge's.
    assert all("transcript" not in (h["file"] or "") for h in run.report["hits"])
