"""Calling the judge, `weir canary judge`, through its documented command
line only (docs/canary.md, "Running it"). The runner never imports weir.

The judge runs in the run directory with relative paths, so the report
names `capture/...` files and two runs print the same bytes. Its
environment is as bare as a flow's: the judge's output depends on no
variable, and none of the job's secrets need to reach it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from weir_run.spec import SpecError

LEDGER = "ledger.jsonl"
OTLP_DIR = "capture/otlp"
SWEPT_DIR = "capture/swept"
JUDGE_TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class Verdict:
    code: int
    stdout: bytes
    stderr: bytes


def _environment() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8", "PYTHONUTF8": "1"}
    if sys.platform == "win32" and "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def resolve(explicit: str | None = None) -> list[str]:
    """The judge's command prefix: an explicit `weir` executable, else the
    one installed beside this interpreter, else the first on PATH."""
    if explicit:
        return [explicit]
    search = os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])
    found = shutil.which("weir", path=search)
    if found is None:
        raise SpecError("the judge is not installed: no `weir` executable (weir-scan) was found")
    return [found]


def check_available(command: Sequence[str]) -> None:
    """Fail before any flow runs when this weir has no canary judge."""
    try:
        done = subprocess.run(
            [*command, "canary", "judge", "--help"],
            env=_environment(),
            capture_output=True,
            timeout=JUDGE_TIMEOUT_SECONDS,
            check=False,
        )
    except OSError as exc:
        raise SpecError(f"cannot run the judge: {exc.strerror}") from None
    if done.returncode != 0:
        raise SpecError(
            "this weir has no `weir canary judge` command; "
            "install a weir-scan release that ships it"
        )


def judge(command: Sequence[str], run_dir: Path, *, json_report: bool = False) -> Verdict:
    args = [*command, "canary", "judge", "--ledger", LEDGER, "--otlp", OTLP_DIR]
    if json_report:
        args.append("--json")
    args.append(SWEPT_DIR)
    done = subprocess.run(
        args,
        cwd=run_dir,
        env=_environment(),
        capture_output=True,
        timeout=JUDGE_TIMEOUT_SECONDS,
        check=False,
    )
    return Verdict(done.returncode, done.stdout, done.stderr)
