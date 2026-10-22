"""Running one flow: an allowlisted environment and a bounded subprocess.

A flow starts from an empty environment, the `env -i` of the contract, and
gets only what is listed here: PATH, a private HOME and temporary
directory, a fixed locale, its planted canaries, the mock's URLs and its
own non-secret settings from the config. Nothing else from the job's
environment reaches it, so a real provider key in CI secrets never does.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from weir_run.isolation import Jail
from weir_run.spec import FlowSpec

PYTHON_TOKEN = "{python}"
MOCK_TOKEN = "{mock}"


def flow_environment(
    mock_url: str,
    planted: Mapping[str, str],
    extra: Mapping[str, str],
    home: Path,
    tmp: Path,
) -> dict[str, str]:
    """The whole environment of a flow: variable name -> value."""
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "TEMP": str(tmp),
        "TMP": str(tmp),
        "LANG": "C.UTF-8",
        "PYTHONUTF8": "1",
        "CANARY_MOCK_URL": mock_url,
        "OPENAI_BASE_URL": f"{mock_url}/v1",
        "OPENAI_API_BASE": f"{mock_url}/v1",
        # The Anthropic SDKs append /v1/messages themselves.
        "ANTHROPIC_BASE_URL": mock_url,
        "OTEL_EXPORTER_OTLP_ENDPOINT": mock_url,
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
    }
    for signal_name in ("TRACES", "LOGS", "METRICS"):
        env[f"OTEL_EXPORTER_OTLP_{signal_name}_ENDPOINT"] = f"{mock_url}/v1/{signal_name.lower()}"
        env[f"OTEL_EXPORTER_OTLP_{signal_name}_PROTOCOL"] = "http/protobuf"
    # Every client that honours the proxy variables reaches other hosts only
    # through the mock, which refuses them. The mock itself is reached direct.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env[name] = env[name.lower()] = mock_url
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    if sys.platform == "win32":
        env["USERPROFILE"] = str(home)
        # Windows processes cannot start without these; neither holds a secret.
        for name in ("SYSTEMROOT", "PATHEXT"):
            if name in os.environ:
                env[name] = os.environ[name]
    env.update(planted)
    env.update({k: v.replace(MOCK_TOKEN, mock_url) for k, v in extra.items()})
    return env


def command_line(flow: FlowSpec, python: str) -> list[str]:
    return [python if part == PYTHON_TOKEN else part for part in flow.command]


def run(
    flow: FlowSpec,
    env: Mapping[str, str],
    stdout: Path,
    stderr: Path,
    python: str,
    jail: Jail | None = None,
) -> str:
    """Run a flow to completion, inside jail when there is one; return its
    ledger status."""
    if flow.skip is not None:
        return "skipped"
    command = command_line(flow, python)
    with stdout.open("wb") as out, stderr.open("wb") as err:
        # Its own process group, so a timeout or the end of the flow can
        # stop everything it started.
        options: dict[str, Any] = {"cwd": flow.cwd, "env": dict(env), "stdout": out, "stderr": err}
        if sys.platform == "win32":
            options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        if jail is not None:
            command = jail.command(command)
            options["pass_fds"] = jail.fds
        try:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, **options)
        except OSError as exc:
            err.write(f"weir-run: could not start the flow: {exc.strerror}\n".encode())
            return "failed"
        try:
            code = proc.wait(timeout=flow.timeout_seconds)
            status = "ok" if code == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timeout"
        finally:
            # A flow's leftover children do not outlive it: the mock and the
            # telemetry receiver exist only for the length of the run.
            if sys.platform == "win32":
                proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            proc.wait()
    return status
