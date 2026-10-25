"""Collect the capture files (docs/canary.md, "Running it" and "The capture").

Each file has one of three roles, fixed by the command line: telemetry
(`--otlp`), requests (`--requests`) or swept (every other path). A directory under either role is
read recursively in sorted path order; a symbolic link inside it is not
followed and is reported as not scanned. Everything else must be read in
full: a capture the judge cannot read in full would leave a value
unsearched, so no part of it is ever skipped silently.
"""

from __future__ import annotations

import enum
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import msgspec

from weir.canary._types import NotScannedReason, RequestsHeader

_GZIP_MAGIC = b"\x1f\x8b"
# Never block on a FIFO swapped in after the type check, and never follow a
# symbolic link swapped in for an entry found under a directory.
_OPEN = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def compressed(data: bytes) -> bool:
    """A file that starts this way is compressed (gzip): it is not scanned,
    and so it is unknown, never clean."""
    return data.startswith(_GZIP_MAGIC)


class Role(enum.Enum):
    TELEMETRY = "otlp"
    REQUESTS = "requests"
    SWEPT = "swept"


class CaptureError(Exception):
    """An unusable capture path: exit 2. The message names the path only."""


@dataclass(frozen=True)
class CaptureFile:
    """One capture file. `data` is None when the file was not scanned."""

    path: str
    role: Role
    data: bytes | None
    not_scanned: NotScannedReason | None = None


def _join(given: str, name: str) -> str:
    return given + name if given.endswith(("/", os.sep)) else f"{given}/{name}"


class _Collector:
    def __init__(self, display: Callable[[str], str]) -> None:
        self._display = display
        self._seen: set[tuple[int, int]] = set()
        self.files: list[CaptureFile] = []

    def _fail(self, path: str, why: str) -> CaptureError:
        return CaptureError(f"capture {self._display(path)}: {why}")

    def _read(self, path: str, role: Role, *, found: bool) -> None:
        try:
            fd = os.open(path, _OPEN | (_NOFOLLOW if found else 0))
        except OSError as exc:
            raise self._fail(path, f"cannot be read ({exc.strerror})") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise self._fail(path, "not a regular file or directory")
            identity = (info.st_dev, info.st_ino)
            if identity in self._seen:
                raise self._fail(path, "reached through more than one given path")
            self._seen.add(identity)
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read()
        except OSError as exc:
            raise self._fail(path, f"cannot be read ({exc.strerror})") from None
        finally:
            os.close(fd)
        if compressed(data):
            self.files.append(CaptureFile(path, role, None, NotScannedReason.COMPRESSED))
            return
        if role is Role.REQUESTS and not _has_requests_header(data):
            raise self._fail(path, "not a request capture (no canary-requests/1 header)")
        self.files.append(CaptureFile(path, role, data))

    def _walk_dir(self, path: str, role: Role) -> None:
        try:
            with os.scandir(path) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError as exc:
            raise self._fail(path, f"cannot be read ({exc.strerror})") from None
        for entry in entries:
            child = _join(path, entry.name)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
                link = entry.is_symlink() or entry.is_junction()
            except OSError as exc:
                raise self._fail(child, f"cannot be read ({exc.strerror})") from None
            if link:
                self.files.append(CaptureFile(child, role, None, NotScannedReason.SYMLINK))
            elif stat.S_ISDIR(mode):
                self._walk_dir(child, role)
            elif stat.S_ISREG(mode):
                self._read(child, role, found=True)
            else:
                raise self._fail(child, "not a regular file or directory")

    def add(self, path: str, role: Role) -> None:
        try:
            mode = os.stat(path).st_mode
        except OSError as exc:
            raise self._fail(path, f"cannot be read ({exc.strerror})") from None
        if stat.S_ISDIR(mode):
            self._walk_dir(path, role)
        elif stat.S_ISREG(mode):
            self._read(path, role, found=False)
        else:
            raise self._fail(path, "not a regular file or directory")


def _has_requests_header(data: bytes) -> bool:
    first, newline, _ = data.partition(b"\n")
    if not newline:
        return False
    try:
        msgspec.json.decode(first, type=RequestsHeader)
    except (msgspec.DecodeError, msgspec.ValidationError):
        return False
    return True


def collect_capture(
    otlp: Sequence[str],
    swept: Sequence[str],
    display: Callable[[str], str],
    requests: Sequence[str] = (),
) -> list[CaptureFile]:
    """Read every capture file in full: telemetry paths, then request
    capture paths, then swept paths.

    `display` renders a path for an error message under the report's
    printing rule, since a file name can come from the program under test.
    """
    collector = _Collector(display)
    for path in otlp:
        collector.add(path, Role.TELEMETRY)
    for path in requests:
        collector.add(path, Role.REQUESTS)
    for path in swept:
        collector.add(path, Role.SWEPT)
    return collector.files
