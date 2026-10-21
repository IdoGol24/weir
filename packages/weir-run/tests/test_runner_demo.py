"""The synthetic demo: red with the leak, green without.

The two configs must differ only in the flow's DEMO_LEAK switch, which the
test derives from the files rather than assumes, so the red and the green
are caused by the flow's telemetry and nothing else. The judge is the
real `weir canary judge`.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from weir_run import cli
from weir_run import judge as judge_cli

DEMO = Path(__file__).parents[1] / "demo"
CLEAN = DEMO / "canary.toml"
LEAK = DEMO / "canary-leak.toml"


def _run(monkeypatch: pytest.MonkeyPatch, judge: list[str], config: Path) -> tuple[int, str, str]:
    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config)])
    return result.exit_code, result.stdout, result.stderr


def _load(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_the_two_configs_differ_only_in_the_leak_switch() -> None:
    clean, leak = _load(CLEAN), _load(LEAK)
    switch = leak["flow"][0]["env"].pop("DEMO_LEAK")
    assert switch == "1"
    assert "DEMO_LEAK" not in clean["flow"][0]["env"]
    assert clean == leak


def test_green_without_the_leak(monkeypatch: pytest.MonkeyPatch, judge: list[str]) -> None:
    code, out, _ = _run(monkeypatch, judge, CLEAN)
    assert code == 0, out
    placements = len(_load(CLEAN)["placement"])
    # Every planted placement and the minted access token were exercised.
    assert f"coverage: {placements + 1} placements (0 leaked, {placements + 1} exercised" in out
    assert out.rstrip().endswith("result: clean")


def test_red_with_the_leak(monkeypatch: pytest.MonkeyPatch, judge: list[str]) -> None:
    code, out, err = _run(monkeypatch, judge, LEAK)
    assert code == 1, out
    leaked = set(re.findall(r"^LEAK (\S+) ", out, re.MULTILINE))
    planted = {p["id"] for p in _load(LEAK)["placement"]}
    # The flow's documented mistakes: the search key, the client secret
    # inside a Basic credential, and the minted access token.
    assert leaked <= planted | {"runtime.oauth.access_token#1"}
    assert "runtime.oauth.access_token#1" in leaked
    assert {"env.SEARCH_API_KEY", "code.auth.client_secret"} <= leaked
    assert "env.OPENAI_API_KEY" not in leaked
    # The flow's debug line is relayed with the canary replaced.
    assert "debug: search key <canary:env.SEARCH_API_KEY>" in err
    assert out.rstrip().endswith("result: leak")


def _bare_env(tmp_path: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(tmp_path)}
    env["TMP"] = env["TEMP"] = env["TMPDIR"] = str(tmp_path)
    if sys.platform == "win32":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    return env


def test_the_demo_runs_from_the_installed_command(judge: list[str], tmp_path: Path) -> None:
    # The runner's command line, as a maintainer runs it, naming the judge.
    [weir] = judge
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "weir_run.cli",
            "run",
            "--config",
            str(LEAK),
            "--weir",
            weir,
        ],
        env=_bare_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 1, done.stdout + done.stderr
