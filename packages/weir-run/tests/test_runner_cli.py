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
import os
import signal
import subprocess
import sys
import tempfile
import time
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
provider = "model"

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


def test_a_placement_without_a_provider_is_named_before_any_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    extra = '\n[[placement]]\nid = "env.LOOSE_KEY"\nkind = "env"\n'
    config, side = _setup(tmp_path, extra=extra)
    result = _run(monkeypatch, judge, config)
    assert result.exit_code == 0, result.output
    warning = "placement env.LOOSE_KEY has no provider: any request holding it counts as a leak\n"
    assert result.stderr.count("has no provider") == 1, result.stderr
    assert result.stderr.startswith(warning), result.stderr
    assert side.read_text(encoding="utf-8") not in result.output


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
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n"
            "[mock.credential_fields]\notlp = ['body:token']\n",
            "has no body: fields",
        ),
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n"
            "[[placement]]\nid = 'env.A'\nkind = 'env'\nprovider = 'search'\n",
            "provider 'search' is not an endpoint",
        ),
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n"
            "[[placement]]\nid = 'env.A'\nkind = 'env'\nprovider = 'oauth'\n",
            "needs oauth = true",
        ),
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n"
            "[[placement]]\nid = 'env.A'\nkind = 'env'\nprovider_host = 'a b'\n",
            "is not a host",
        ),
        (
            "[[flow]]\nid = 'a'\ncommand = ['x']\n[[mock.endpoint]]\nid = 'unmocked'\n",
            "endpoint id 'unmocked' is not usable",
        ),
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


# A fake judge's answer to the runner's `--help` probe: one that can judge
# the request capture.
HELP = "if '--help' in sys.argv: print('--requests'); sys.exit(0)\n"


def test_a_judge_that_cannot_judge_requests_exits_2_before_any_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A weir-scan release from before the request sink: `canary judge`
    # exists, `--requests` does not.
    script = tmp_path / "judge.py"
    script.write_text("import sys\nprint('--otlp PATH')\nsys.exit(0)\n", encoding="utf-8")
    config, side = _setup(tmp_path)
    result = _run(monkeypatch, [sys.executable, str(script)], config)
    assert result.exit_code == 2
    assert "cannot judge outbound requests" in result.stderr
    assert not side.exists()


def test_a_judge_input_error_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # A judge that accepts --help and then refuses the run's input.
    script = tmp_path / "judge.py"
    script.write_text(
        f"import sys\n{HELP}print('ledger.jsonl:3: bad record', file=sys.stderr)\nsys.exit(2)\n",
        encoding="utf-8",
    )
    config, _ = _setup(tmp_path)
    result = _run(monkeypatch, [sys.executable, str(script)], config)
    assert result.exit_code == 2
    assert "ledger.jsonl:3: bad record" in result.stderr


def _sleeping_judge(tmp_path: Path, *, on_help: bool) -> list[str]:
    script = tmp_path / "judge.py"
    script.write_text(
        "import sys, time\n"
        f"if '--help' in sys.argv and not {on_help}: print('--requests'); sys.exit(0)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)]


def test_a_judge_that_times_out_is_exit_2_never_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(judge_cli, "JUDGE_TIMEOUT_SECONDS", 1)
    config, side = _setup(tmp_path, "leak")
    result = _run(monkeypatch, _sleeping_judge(tmp_path, on_help=False), config)
    assert result.exit_code == 2, result.output
    assert "timed out" in result.stderr
    assert side.read_text() not in result.output


def test_a_judge_probe_that_hangs_is_exit_2_before_any_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(judge_cli, "JUDGE_TIMEOUT_SECONDS", 1)
    config, side = _setup(tmp_path)
    result = _run(monkeypatch, _sleeping_judge(tmp_path, on_help=True), config)
    assert result.exit_code == 2, result.output
    assert "timed out" in result.stderr
    assert not side.exists()


def test_a_report_in_a_missing_directory_is_exit_2_before_any_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, side = _setup(tmp_path)
    report = tmp_path / "missing" / "report.json"
    result = _run(monkeypatch, judge, config, "--report", str(report))
    assert result.exit_code == 2, result.output
    assert "no such directory" in result.stderr
    assert not side.exists()


def test_a_report_that_cannot_be_written_is_exit_2_never_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    config, _ = _setup(tmp_path)
    report = tmp_path / "out" / "report.json"
    report.parent.mkdir()
    real = judge_cli.judge

    def judge_then_lose_the_directory(
        command: list[str], run_dir: Path, *, json_report: bool = False
    ) -> judge_cli.Verdict:
        verdict = real(command, run_dir, json_report=json_report)
        if report.parent.exists():
            report.parent.rmdir()
        return verdict

    monkeypatch.setattr(judge_cli, "judge", judge_then_lose_the_directory)
    result = _run(monkeypatch, judge, config, "--report", str(report))
    assert result.exit_code == 2, result.output
    assert "weir-run:" in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_judge_killed_by_a_signal_is_exit_2_never_its_raw_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "judge.py"
    script.write_text(
        f"import os, signal, sys\n{HELP}os.kill(os.getpid(), signal.SIGKILL)\n",
        encoding="utf-8",
    )
    config, side = _setup(tmp_path, "leak")
    result = _run(monkeypatch, [sys.executable, str(script)], config)
    assert result.exit_code == 2, result.output
    assert "the judge failed (signal 9)" in result.stderr
    assert side.read_text() not in result.output


TERM_FLOW = """
import os, subprocess, sys, time
beat = os.environ["BEAT_FILE"]
child = "import time\\nwhile True:\\n    open(%r, 'a').write('.')\\n    time.sleep(0.05)\\n" % beat
subprocess.Popen([sys.executable, "-c", child])
time.sleep(60)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_during_a_flow_exits_2_and_cleans_up(tmp_path: Path, judge: list[str]) -> None:
    flow = tmp_path / "flow.py"
    flow.write_text(TERM_FLOW, encoding="utf-8")
    beat = tmp_path / "beat.txt"
    config = tmp_path / "canary.toml"
    config.write_text(
        '[[placement]]\nid = "env.APP_KEY"\nkind = "env"\n\n[[flow]]\nid = "main"\n'
        f'command = ["{{python}}", {json.dumps(flow.as_posix())}]\n'
        f"env = {{ BEAT_FILE = {json.dumps(beat.as_posix())} }}\n",
        encoding="utf-8",
    )
    run_tmp = tmp_path / "run-tmp"
    run_tmp.mkdir()
    runner = subprocess.Popen(
        [sys.executable, "-m", "weir_run.cli", "run", "--config", str(config), "--weir", judge[0]],
        env={**os.environ, "TMPDIR": str(run_tmp)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 30
    while not (beat.exists() and beat.stat().st_size) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert beat.exists(), "the flow never started"
    runner.send_signal(signal.SIGTERM)
    _, stderr = runner.communicate(timeout=30)
    assert runner.returncode == 2, stderr
    assert b"weir-run: interrupted" in stderr
    assert list(run_tmp.iterdir()) == []
    size = beat.stat().st_size
    time.sleep(0.5)
    assert beat.stat().st_size == size, "the flow's child outlived the run"
