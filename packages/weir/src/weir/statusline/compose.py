"""Running the status line command already in the settings beside the
segment (docs/statusline.md, "Beside an existing status line").

The existing command gets the same JSON on stdin, runs while the segment
reads the session, and its output comes first. When Claude Code cancels
this run, the existing command is stopped with it.
"""

from __future__ import annotations

import signal
import subprocess
import threading
from collections.abc import Callable
from types import FrameType

SEPARATOR = " | "
# The existing command's run is bounded even if Claude Code never cancels it.
INNER_TIMEOUT_S = 10.0


def run_beside(inner: str | None, stdin: bytes, segment: Callable[[], str]) -> str:
    """The existing command's output, then the segment on its last line.
    An existing command that fails, prints nothing or runs too long shows
    the segment alone, as Claude Code would show nothing for it."""
    if inner is None:
        return segment()
    proc = subprocess.Popen(
        inner, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    def stop(signum: int, frame: FrameType | None) -> None:
        del frame
        proc.kill()
        raise SystemExit(128 + signum)

    # The existing command takes its input and runs on a thread while the
    # segment reads the session here.
    result: list[bytes | None] = [None]

    def talk() -> None:
        try:
            result[0], _ = proc.communicate(stdin, timeout=INNER_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()

    previous = signal.signal(signal.SIGTERM, stop)
    worker = threading.Thread(target=talk, daemon=True)
    worker.start()
    try:
        line = segment()
        worker.join()
    finally:
        signal.signal(signal.SIGTERM, previous)
    out = result[0]
    if out is None:
        return line
    shown = out.decode("utf-8", "replace").rstrip("\n")
    if proc.returncode != 0 or not shown.strip():
        return line
    return shown + SEPARATOR + line
