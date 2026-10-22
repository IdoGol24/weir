"""Running flows: the allowlisted environment and the flow statuses
(docs/canary.md, "The boundary": each flow under `env -i` with an
allowlisted environment; "The ledger": flow `status`).

Flows here are tiny Python scripts written by the test. They report what
they saw by writing variable names, never values, into a file the test
reads, except for values the test itself planted.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from weir_run import flows
from weir_run.check import CheckRun
from weir_run.spec import RUNNER_VARIABLES, FlowSpec, MockSpec, PlacementSpec, RunSpec


def _script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _env(tmp_path: Path) -> dict[str, str]:
    """The allowlisted environment a flow gets, never the test process's own."""
    return flows.flow_environment("http://127.0.0.1:9", {}, {}, tmp_path, tmp_path)


PROBE = """
import json, os, sys
out = sys.argv[1]
names = sorted(os.environ)
json.dump({"names": names, "planted": os.environ.get("PROBE_KEY"),
           "code": os.environ.get("CANARY_CODE_CLIENT_TOKEN"),
           "setting": os.environ.get("APP_SETTING"),
           "mock": os.environ.get("CANARY_MOCK_URL")}, open(out, "w"))
"""


def test_a_flow_sees_only_the_allowlist(
    tmp_path: Path, judge: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A variable of the test process, standing in for a CI secret.
    monkeypatch.setenv("CI_ONLY_TOKEN", "inherited-and-must-not-reach-the-flow")
    script = _script(tmp_path, "probe.py", PROBE)
    out = tmp_path / "seen.json"
    spec = RunSpec(
        placements=(
            PlacementSpec("env.PROBE_KEY", "env", "PROBE_KEY"),
            PlacementSpec("code.client.token", "code", "CANARY_CODE_CLIENT_TOKEN"),
        ),
        flows=(),
        mock=MockSpec(),
    )
    run = CheckRun(spec, judge, validate_spec=False)
    try:
        flow = FlowSpec(
            id="probe",
            command=("{python}", str(script), str(out)),
            cwd=tmp_path,
            env={"APP_SETTING": "{mock}/ep/x"},
        )
        assert run.run_flow(flow).status == "ok"
        seen = json.loads(out.read_text())
        values = {p.id: p.value for p in run.ledger.placements}
        mock_url = run.mock_url
    finally:
        run.cleanup()
    allowed = RUNNER_VARIABLES | {"PROBE_KEY", "CANARY_CODE_CLIENT_TOKEN", "APP_SETTING"}
    # Interpreters may add a few of their own at start-up (macOS adds
    # __CF_USER_TEXT_ENCODING, for one); nothing may come from the job.
    extra = {n for n in seen["names"] if n not in allowed and not n.startswith("__")}
    assert extra == set()
    assert "CI_ONLY_TOKEN" not in seen["names"]
    assert seen["planted"] == values["env.PROBE_KEY"]
    assert seen["code"] == values["code.client.token"]
    assert seen["setting"] == f"{mock_url}/ep/x"
    assert seen["mock"] == mock_url


def test_the_environment_points_every_client_at_the_mock(tmp_path: Path) -> None:
    url = "http://127.0.0.1:1"
    env = flows.flow_environment(url, {"K": "v"}, {}, tmp_path, tmp_path)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        assert env[name] == url
    assert env["OPENAI_BASE_URL"].startswith(url)
    # The Anthropic SDKs append /v1/messages themselves.
    assert env["ANTHROPIC_BASE_URL"] == url
    assert env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] == f"{url}/v1/traces"
    assert "127.0.0.1" in env["NO_PROXY"].split(",")
    assert env["HOME"] == str(tmp_path)
    assert set(env) - {"K"} <= RUNNER_VARIABLES


@pytest.mark.parametrize(
    ("body", "timeout", "status"),
    [
        ("pass", 30.0, "ok"),
        ("import sys; sys.exit(4)", 30.0, "failed"),
        ("raise SystemExit('boom')", 30.0, "failed"),
        ("import time; time.sleep(30)", 0.5, "timeout"),
    ],
)
def test_flow_statuses(tmp_path: Path, body: str, timeout: float, status: str) -> None:
    script = _script(tmp_path, "flow.py", body)
    stdout, stderr = tmp_path / "out", tmp_path / "err"
    flow = FlowSpec(
        id="f", command=("{python}", str(script)), cwd=tmp_path, timeout_seconds=timeout
    )
    assert flows.run(flow, _env(tmp_path), stdout, stderr, sys.executable) == status


def test_a_flow_that_cannot_start_failed(tmp_path: Path) -> None:
    flow = FlowSpec(id="f", command=(str(tmp_path / "no-such-program"),), cwd=tmp_path)
    stderr = tmp_path / "err"
    assert flows.run(flow, {}, tmp_path / "out", stderr, sys.executable) == "failed"
    assert b"could not start" in stderr.read_bytes()


def test_a_skipped_flow_does_not_run(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    script = _script(tmp_path, "flow.py", f"open({str(marker)!r}, 'w').close()")
    flow = FlowSpec(id="f", command=("{python}", str(script)), cwd=tmp_path, skip="not on CI")
    assert flows.run(flow, {}, tmp_path / "out", tmp_path / "err", sys.executable) == "skipped"
    assert not marker.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX")
def test_a_flows_leftover_children_are_stopped(tmp_path: Path) -> None:
    marker = tmp_path / "child-alive"
    child = _script(
        tmp_path,
        "child.py",
        f"import time, pathlib\ntime.sleep(1.5)\npathlib.Path({str(marker)!r}).write_text('x')\n",
    )
    parent = _script(
        tmp_path,
        "parent.py",
        f"import subprocess, sys\nsubprocess.Popen([sys.executable, {str(child)!r}])\n",
    )
    flow = FlowSpec(id="f", command=("{python}", str(parent)), cwd=tmp_path)
    assert (
        flows.run(flow, _env(tmp_path), tmp_path / "out", tmp_path / "err", sys.executable) == "ok"
    )
    time.sleep(2.5)
    assert not marker.exists()
