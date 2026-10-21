"""`weir-run run` end to end, judged by the real `weir canary judge` through its
documented command line (docs/canary.md: "Exit codes", "What the runner
owes the judge").

Flows that need to show a test their canary write it to a side file in the
test's own temporary directory; the runner's output is then checked
against that value. That is the only way a test learns a value, and the
values are fake.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from weir_run import cli
from weir_run import judge as judge_cli

CONFIG = """
[[placement]]
id = "env.APP_KEY"
kind = "env"
required = true

[[flow]]
id = "main"
command = ["{{python}}", {probe}]
env = {{ {env} }}
"""

PROBE = Path(__file__).parent / "_probe_flow.py"


def _setup(tmp_path: Path, mode: str = "", extra: str = "") -> tuple[Path, Path]:
    side = tmp_path / "side.txt"
    env = {"SIDE_FILE": side.as_posix(), "MODE": mode}
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items())
    path = tmp_path / "canary.toml"
    path.write_text(
        CONFIG.format(env=inline, probe=json.dumps(PROBE.as_posix())) + extra, encoding="utf-8"
    )
    return path, side


def _run(monkeypatch: pytest.MonkeyPatch, judge: list[str], config: Path, *args: str) -> Result:
    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    return CliRunner().invoke(cli.main, ["run", "--config", str(config), *args])


def test_a_clean_run_exits_0_with_the_coverage_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, _ = _setup(tmp_path)
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 0, result.output
    assert "coverage: 1 placements (0 leaked, 1 exercised" in result.stdout
    assert result.stdout.rstrip().endswith("result: clean")


def test_a_leak_exits_1_and_never_prints_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, side = _setup(tmp_path, "leak")
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 1, result.output
    assert "LEAK env.APP_KEY file=capture/otlp/traces.jsonl:1" in result.stdout
    assert side.read_text() not in result.output


def test_relayed_output_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, side = _setup(tmp_path, "print")
    result = _run(monkeypatch, judge, config)
    value = side.read_text()
    assert result.exit_code == 1  # the flow printed it: its output is capture too
    assert "raw <canary:env.APP_KEY>" in result.stderr
    assert "b64 " in result.stderr
    assert value not in result.output
    basic = base64.b64encode(f"u:{value}".encode()).decode()
    assert basic not in result.output
    assert "<canary:env.APP_KEY>" in result.stderr.split("b64 ", 1)[1]


def test_a_crashed_flow_makes_the_run_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, _ = _setup(tmp_path, "crash")
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 3
    assert "incomplete: flow_not_ok main=failed" in result.stdout


def test_a_required_placement_never_sent_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    extra = '\n[[placement]]\nid = "env.UNUSED_KEY"\nkind = "env"\nrequired = true\n'
    config, _ = _setup(tmp_path, extra=extra)
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 3
    assert "incomplete: required_not_exercised env.UNUSED_KEY" in result.stdout


def test_the_ledger_and_the_capture_are_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    made: list[Path] = []
    real = tempfile.mkdtemp

    def recording(prefix: str | None = None) -> str:
        path = real(prefix=prefix)
        made.append(Path(path))
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", recording)
    config, _ = _setup(tmp_path, "leak")
    assert _run(monkeypatch, judge, config).exit_code == 1
    assert made and not any(p.exists() for p in made)


def test_the_json_report_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, _ = _setup(tmp_path, "leak")
    report = tmp_path / "report.json"
    assert _run(monkeypatch, judge, config, "--report", str(report)).exit_code == 1
    doc = json.loads(report.read_text())
    assert doc["schema"] == "canary-report/1" and doc["result"] == "leak"


def test_two_runs_print_the_same_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, _ = _setup(tmp_path, "leak")
    first = _run(monkeypatch, judge, config).stdout
    second = _run(monkeypatch, judge, config).stdout
    assert first == second


@pytest.mark.parametrize(
    ("config_text", "message"),
    [
        ("[[flow]]\nid = 'a'\ncommand = ['x']\nnot_a_key = 1\n", "unknown key 'not_a_key'"),
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n[[placement]]\nid = 'p'\nkind = 'mcp'\n",
            "cannot be planted",
        ),
        ("[[placement]]\nid = 'env.A'\nkind = 'env'\n", "no flow is defined"),
        ("[[flow]]\nid = 'a'\ncommand = ['x']\nenv = { PATH = '/x' }\n", "set by the runner"),
        ("not toml [", "not valid TOML"),
    ],
)
def test_configuration_errors_exit_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    judge: list[str],
    config_text: str,
    message: str,
) -> None:
    config = tmp_path / "canary.toml"
    config.write_text(config_text, encoding="utf-8")
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 2
    assert message in result.stderr


def test_a_weir_without_the_judge_exits_2_before_any_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, side = _setup(tmp_path)
    no_judge = [sys.executable, "-c", "import sys; sys.exit(2)"]
    result = _run(monkeypatch, no_judge, config)
    assert result.exit_code == 2
    assert "no `weir canary judge` command" in result.stderr
    assert not side.exists()


def test_a_judge_input_error_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # A judge that accepts --help and then refuses the run's input.
    script = tmp_path / "judge.py"
    script.write_text(
        "import sys\nif '--help' in sys.argv: sys.exit(0)\n"
        "print('ledger.jsonl:3: bad record', file=sys.stderr)\nsys.exit(2)\n",
        encoding="utf-8",
    )
    config, _ = _setup(tmp_path)
    result = _run(monkeypatch, [sys.executable, str(script)], config)
    assert result.exit_code == 2
    assert "ledger.jsonl:3: bad record" in result.stderr
