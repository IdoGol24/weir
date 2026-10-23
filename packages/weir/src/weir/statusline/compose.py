"""Running the status line command already in the settings beside the
segment (docs/statusline.md, "Beside an existing status line").

The existing command gets the same JSON on stdin, runs while the segment
reads the session, and its output comes first. When Claude Code cancels
this run, the existing command is stopped with it.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from types import FrameType

SEPARATOR = " | "
# The existing command's run is bounded even if Claude Code never cancels it.
INNER_TIMEOUT_S = 10.0
# Once the existing command has exited, how long its output may stay open
# (a background child it left behind holds it) before that child is stopped.
_OUTPUT_GRACE_S = 0.5
# Each existing command runs in a process group of its own, so stopping it
# stops what it started (POSIX; on Windows only the command itself).
_GROUPS = sys.platform != "win32"


def _stop_group(proc: subprocess.Popen[bytes]) -> None:
    """Stop the existing command and every process it started."""
    try:
        # Tested on sys.platform itself, not _GROUPS, so the type checker
        # knows os.killpg exists here.
        if sys.platform == "win32":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass  # gone already


def run_beside(inner: str | None, stdin: bytes, segment: Callable[[], str]) -> str:
    """The existing command's output, then the segment on its last line.
    An existing command that fails, prints nothing or runs more than
    INNER_TIMEOUT_S shows the segment alone, as Claude Code would show
    nothing for it; it is then stopped, with everything it started.

    When Claude Code cancels the run (SIGTERM), it ends as an exception
    would, so a cache file being written is removed whole, never left
    half-written, and the existing command's process group is stopped."""
    proc: subprocess.Popen[bytes] | None = None

    def stop(signum: int, frame: FrameType | None) -> None:
        del frame
        if proc is not None:
            _stop_group(proc)
        raise SystemExit(128 + signum)

    # Only the main thread can set a signal handler; a run on another thread
    # (a test's) is cancelled some other way.
    main = threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGTERM, stop) if main else None
    try:
        if inner is None:
            return segment()
        deadline = time.monotonic() + INNER_TIMEOUT_S
        proc = subprocess.Popen(
            inner, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=_GROUPS,
        )
        started = proc
        output: list[bytes] = []
        # The existing command takes its input and is read on threads while
        # the segment reads the session here.
        feeder = threading.Thread(target=_feed, args=(started, stdin), daemon=True)
        reader = threading.Thread(target=_read, args=(started, output), daemon=True)
        feeder.start()
        reader.start()
        line = segment()
        try:
            started.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _stop_group(started)
            return line
        reader.join(timeout=max(0.0, min(_OUTPUT_GRACE_S, deadline - time.monotonic())))
        if reader.is_alive():
            # A child it left in the background still holds the output.
            _stop_group(started)
            reader.join(timeout=_OUTPUT_GRACE_S)
    finally:
        if main:
            signal.signal(signal.SIGTERM, previous)
    shown = b"".join(output).decode("utf-8", "replace").rstrip("\n")
    if started.returncode != 0 or not shown.strip():
        return line
    return shown + SEPARATOR + line


def _feed(proc: subprocess.Popen[bytes], stdin: bytes) -> None:
    assert proc.stdin is not None
    try:
        proc.stdin.write(stdin)
        proc.stdin.close()
    except OSError:
        pass  # the command does not read its input


def _read(proc: subprocess.Popen[bytes], output: list[bytes]) -> None:
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    while chunk := os.read(fd, 65536):
        output.append(chunk)
