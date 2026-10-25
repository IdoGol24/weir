"""Running the status line command already in the settings beside the
segment (docs/statusline.md, "Beside an existing status line")."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from collections.abc import Callable
from types import FrameType

from weir.statusline.segment import RESET

SEPARATOR = " | "
INNER_TIMEOUT_S = 10.0
# The signals that cancel a run.
_CANCELS = [signal.SIGTERM, signal.SIGINT]
if sys.platform != "win32":  # Windows has no SIGHUP
    _CANCELS.append(signal.SIGHUP)


def run_beside(
    inner: str | None, stdin: bytes, segment: Callable[[], str], *, colour: bool
) -> str:
    """The existing command's output, then the segment on its last line.
    One that fails, prints nothing or runs too long shows the segment
    alone, as Claude Code would show nothing for it. With colour, a reset
    after the output ends any colour it leaves on."""
    shown = "" if inner is None else _run(inner, stdin)
    line = segment()
    if not shown.strip():
        return line
    return shown + (RESET if colour else "") + SEPARATOR + line


def _run(inner: str, stdin: bytes) -> str:
    """The command's output, or "" when it fails or runs too long. It runs
    in a process group of its own, killed whole at the time bound and when
    this run is cancelled (SIGTERM, SIGINT or SIGHUP). A child that leaves
    the group (`setsid`, say) is not reached."""
    proc = subprocess.Popen(
        inner, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True,
    )

    def cancelled(signum: int, _: FrameType | None) -> None:
        _kill(proc)
        raise SystemExit(128 + signum)

    previous = {signum: signal.signal(signum, cancelled) for signum in _CANCELS}
    try:
        out, _ = proc.communicate(stdin, timeout=INNER_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        _kill(proc)
        return ""
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return out.decode("utf-8", "replace").rstrip("\r\n") if proc.returncode == 0 else ""


def _kill(proc: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        proc.kill()  # Windows has no process groups to signal
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # the group has ended already
    proc.wait()
