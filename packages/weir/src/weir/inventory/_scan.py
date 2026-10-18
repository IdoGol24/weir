"""Shared plumbing for the inventory sources: reading files, offsets, and
the internal hit record that still carries a value.

`Hit` is the one place a value travels between a detector and the core. It
is internal: the core turns it into a value-free `Credential` and a
`StoredRecord` (keyed fingerprint plus offsets), and nothing else ever sees
it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from weir.inventory._types import NotScannedReason, Reason

MAX_FILE_BYTES = 4 * 1024 * 1024
_BINARY_PROBE = 8192


@dataclass
class Hit:
    name: str
    reason: Reason
    detectors: set[str]
    value: str | None  # None: dynamic or absent, per `dynamic`
    spans: list[tuple[int, int]]  # character spans into the scanned text
    line: int | None
    scope: str | None = None
    dynamic: bool = False
    commit: str | None = None
    # Lower ranks name the record when hits merge: an assignment key names
    # a value better than the catalog class that also matched it.
    name_rank: int = 50


class Unreadable(Exception):
    def __init__(self, reason: NotScannedReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def read_text(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> str:
    """The file as text, or Unreadable(reason). UTF-8 with surrogateescape,
    so a stray invalid byte never hides the rest of the file."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise Unreadable(NotScannedReason.UNREADABLE) from exc
    if size > max_bytes:
        raise Unreadable(NotScannedReason.TOO_LARGE)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise Unreadable(NotScannedReason.UNREADABLE) from exc
    if b"\0" in data[:_BINARY_PROBE]:
        raise Unreadable(NotScannedReason.BINARY)
    return data.decode("utf-8", "surrogateescape")


def byte_offset(text: str, index: int) -> int:
    return len(text[:index].encode("utf-8", "surrogateescape"))


def byte_spans(text: str, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    return sorted({(byte_offset(text, s), byte_offset(text, e)) for s, e in spans})


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def find_all(text: str, needle: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if not needle:
        return spans
    start = text.find(needle)
    while start != -1:
        spans.append((start, start + len(needle)))
        start = text.find(needle, start + len(needle))
    return spans


def find_encoded(text: str, value: str) -> list[tuple[int, int]]:
    """Where a parsed string value sits in its source text: the raw value
    first, else its JSON-escaped form (a JSON or YAML file that escaped a
    character in it)."""
    spans = find_all(text, value)
    if spans:
        return spans
    escaped = json.dumps(value)[1:-1]
    return find_all(text, escaped) if escaped != value else []


def absolute(path: Path) -> Path:
    """Absolute and lexically normalized (`a/../b` is `b`), so one file has
    one key however an input named it."""
    return Path(os.path.normpath(path.absolute()))


def posix(path: Path) -> str:
    return path.as_posix()


def display_path(path: Path, *, home: Path, project: Path) -> str:
    """`./x` under the project, `~/x` under the home, else absolute. The
    project wins when it sits inside the home, which is the usual case."""
    for base, prefix in ((project, "./"), (home, "~/")):
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        return prefix + rel.as_posix() if rel.parts else prefix.rstrip("/")
    return path.as_posix()
