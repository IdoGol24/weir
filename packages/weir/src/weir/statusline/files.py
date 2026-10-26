"""Writing files whole: a reader sees the old bytes or the new ones, never
a mix, and a run Claude Code cancels mid-write leaves no partial file."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    """Write `data` to `path` through a temporary file in the same
    directory, with permission bits `mode`."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_private(path: Path, data: bytes) -> None:
    """Write atomically, readable by the owner only, creating each missing
    directory on the way owner-only; an existing one keeps its mode."""
    missing = [d for d in (path.parent, *path.parent.parents) if not d.exists()]
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
    write_atomic(path, data, 0o600)
