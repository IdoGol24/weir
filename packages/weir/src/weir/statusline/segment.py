"""The status-line segment (docs/statusline.md, "The segment").

Claude Code runs the status line after each assistant message and cancels
a run still going when the next one starts. So the segment reads the
session files that can move a count, the transcript and the subagent
transcripts, in steps of whole lines, and after each step writes a
checkpoint: per file its device and inode, the byte offset reached, a
keyed MAC of the 4 KiB before that offset, the credential ids found so
far, and the format the file was recognised as, which every later step
is audited in. A file that only grew is read on from its offset; anything
else is read again from the start, and so is a file whose first steps
were recognised as no format once a later one is. A long record not
searched whole in LONG_RECORD_TRIES tries, each within its own time bound,
is skipped, and the session is then partly checked. The checkpoint never
holds a value, a fragment of one or a file name.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import signal
import stat
import sys
import time
from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import BinaryIO

import msgspec

from weir.audit import Format, Inputs, Kind, Report, audit_chunks
from weir.canary.capture import compressed
from weir.statusline.files import write_private

CACHE_SCHEMA = "weir-statusline-cache/1"
# The word the segment shows until every file is read to its end.
SCANNING = "scanning…"
# A step reads whole lines and stops at the first line end past this.
CHUNK_BYTES = 64 * 1024
# A record longer than this, its image data aside, is searched first in a
# run, within LONG_RECORD_S, each try counted in the checkpoint first.
LONG_RECORD_BYTES = 128 * 1024
# A long record's own time bound, whatever --budget-ms says: Claude Code
# cancels a run only when it starts the next one.
LONG_RECORD_S = 5.0
# Tries, each cancelled or out of time, after which a long record is skipped.
LONG_RECORD_TRIES = 3
# The bytes before the offset whose MAC shows the part read is unchanged.
_PREFIX_BYTES = 4096
# A last line without its line end, in a file changed this recently, is a
# record Claude Code is still writing: unread for now.
FRESH_TAIL_S = 5.0
# A temporary checkpoint this old is one a killed run left behind.
_STALE_TEMP_S = 60.0
# The data of an `image` block's base64 source, as Claude Code writes it
_IMAGE_DATA = re.compile(rb'"media_type": ?"image/[^"]*", ?"data": ?"([A-Za-z0-9+/=]*)"')


class Tally(msgspec.Struct):
    """The credential ids whose value entered the context, those sent in a
    tool call, whether anything read is unknown, and whether a long record
    was skipped, not searched whole in LONG_RECORD_TRIES tries."""

    context: set[str] = msgspec.field(default_factory=set[str])
    sent: set[str] = msgspec.field(default_factory=set[str])
    unknown: bool = False
    partial: bool = False

    def add(self, other: Tally) -> None:
        self.context |= other.context
        self.sent |= other.sent
        self.unknown = self.unknown or other.unknown
        self.partial = self.partial or other.partial


def tally(report: Report) -> Tally:
    """docs/statusline.md, "What is counted": a `context` or `tool_call` hit
    put the value in the context; a `tool_call` hit sent it."""
    out = Tally(unknown=bool(report.unknown))
    for hit in report.hits:
        if hit.kind in (Kind.CONTEXT, Kind.TOOL_CALL):
            out.context.add(hit.credential)
        if hit.kind is Kind.TOOL_CALL:
            out.sent.add(hit.credential)
    return out


def value_groups(inputs: Inputs) -> dict[str, str]:
    """Credential id -> the value it holds: records whose stored
    fingerprints are equal hold one value."""
    out = {c.id: c.id for c in inputs.credentials}
    for ids in inputs.by_fingerprint.values():
        for cid in ids:
            out[cid] = ids[0]
    return out


def counted(t: Tally, inputs: Inputs) -> tuple[int, int]:
    """(in context, sent), counting values, not inventory records."""
    groups = value_groups(inputs)
    return len({groups[c] for c in t.context}), len({groups[c] for c in t.sent})


# The ANSI SGR code each part of the segment is drawn in (docs/statusline.md,
# "Colours"); every coloured part is reset after itself, so the status line
# beside it keeps its own colours.
GREEN, AMBER, RED, DIM = 32, 33, 31, 2
RESET = "\x1b[0m"
POINTER = "→ /weir"
# The words for an inventory that holds no credential weir can check.
NOTHING_TO_CHECK = "nothing to check"


def colour_wanted(environ: Mapping[str, str]) -> bool:
    """Colour unless NO_COLOR is set and not empty (no-color.org)."""
    return not environ.get("NO_COLOR")


def _paint(text: str, sgr: int, colour: bool) -> str:
    return f"\x1b[{sgr}m{text}{RESET}" if colour else text


def note(words: str, *, colour: bool, pointer: bool = False) -> str:
    """A line with no counts: its words dim."""
    return "weir " + _paint(f"{words} {POINTER}" if pointer else words, DIM, colour)


def segment_text(
    context: int, sent: int, *, unknown: bool, partial: bool = False,
    scanning: int | None = None, colour: bool = False, pointer: bool = True,
) -> str:
    """The segment's line; without `pointer`, the /weir report's first line."""
    if partial:
        return note("partly checked", colour=colour, pointer=pointer)
    counts = (
        f"{_paint('⚠', AMBER, colour)} "
        f"{_paint(f'{context} in context', AMBER if context else DIM, colour)} · "
        f"{_paint(f'{sent} sent', RED if sent else DIM, colour)}"
    )
    if scanning is not None:
        progress = _paint(f"{SCANNING} {scanning}%", DIM, colour)
        return f"weir {counts} · {progress}" if context or sent else f"weir {progress}"
    if not (context or sent):
        # Nothing exposed only when every file was read and nothing is unknown.
        return note("unknown", colour=colour) if unknown else (
            "weir " + _paint("✓ nothing exposed", GREEN, colour)
        )
    line = f"weir {counts}"
    if unknown:
        line += " · " + _paint("part unknown", DIM, colour)
    return f"{line} {POINTER}" if pointer else line


@dataclass
class SessionFiles:
    stepped: list[str]
    whole: list[str] = field(default_factory=list[str])
    unknown: bool = False


def session_files(transcript: str, session_id: str) -> SessionFiles:
    """docs/statusline.md, "The session's files": the transcripts, read in
    steps, the sidecars, read whole, and whether anything else is unknown."""
    files = SessionFiles([transcript])
    top = os.path.join(os.path.dirname(transcript), session_id)
    if not session_id or not os.path.lexists(top):
        return files
    if os.path.islink(top) or not os.path.isdir(top):
        files.unknown = True
        return files
    def unlisted(_: OSError) -> None:
        files.unknown = True  # a directory that cannot be listed: never a clean zero

    for root, dirs, names in os.walk(top, onerror=unlisted):
        links = [d for d in dirs if os.path.islink(os.path.join(root, d))]
        files.unknown = files.unknown or bool(links)
        dirs[:] = sorted(d for d in dirs if d not in links)
        where = os.path.relpath(root, top)
        for name in sorted(names):
            path = os.path.join(root, name)
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    files.unknown = True
                elif where == "subagents" and name.endswith(".jsonl"):
                    files.stepped.append(path)
                elif where == "subagents" and name.endswith(".meta.json"):
                    files.whole.append(path)
                elif where != "tool-results" or _starts_compressed(path):
                    files.unknown = True
            except OSError:
                files.unknown = True  # gone or unreadable: never a clean zero
    return files


def _starts_compressed(path: str) -> bool:
    with open(path, "rb") as handle:
        return compressed(handle.read(4))


class _Entry(msgspec.Struct):
    dev: int
    ino: int
    offset: int
    prefix_mac: str
    found: Tally
    # The format a step was recognised as; None until one is.
    format: Format | None
    # The offset of the long record runs have tried to search, and how many
    # tries began; -1: none.
    marked: int = -1
    tries: int = 0


class _Cache(msgspec.Struct, frozen=True):
    schema: str
    inputs: str
    files: dict[str, _Entry]


class Reader:
    """Reads a session's files in steps until a deadline, keeping progress
    in one checkpoint file per session."""

    def __init__(
        self, inputs: Inputs, cache: Path, session_key: str,
        claude_config_dirs: Sequence[str], deadline: float,
    ) -> None:
        self._inputs = inputs
        self._dirs = list(claude_config_dirs)
        self._deadline = deadline
        self._stepped = False
        self._path = cache / f"{self._mac('session', session_key.encode())[:32]}.json"
        # A new inventory starts every checkpoint over.
        ids = "\0".join(sorted(c.id for c in inputs.credentials)).encode()
        self._inputs_mac = self._mac("inputs", ids + b"".join(sorted(inputs.by_fingerprint)))
        self._entries: dict[str, _Entry] = {}

    def _mac(self, label: str, data: bytes) -> str:
        message = b"weir-statusline " + label.encode() + b"\0" + data
        return hmac.new(self._inputs.key, message, hashlib.sha256).hexdigest()

    def load(self) -> None:
        now = time.time()
        for temp in self._path.parent.glob(f".{self._path.name}.*"):
            try:
                if now - temp.stat().st_mtime > _STALE_TEMP_S:
                    temp.unlink()
            except OSError:
                pass  # gone already: the next run tries again
        try:
            cache = msgspec.json.decode(self._path.read_bytes(), type=_Cache)
        except (OSError, msgspec.DecodeError):
            return
        if cache.schema == CACHE_SCHEMA and cache.inputs == self._inputs_mac:
            self._entries = dict(cache.files)

    def save(self) -> None:
        cache = _Cache(CACHE_SCHEMA, self._inputs_mac, dict(sorted(self._entries.items())))
        write_private(self._path, msgspec.json.encode(cache) + b"\n")

    def read(self, files: SessionFiles) -> tuple[Tally, int, int]:
        """What the files hold, the bytes read and the bytes in all."""
        found = Tally(unknown=files.unknown)
        done = total = 0
        keys = {self._mac("path", os.fsencode(p)): p for p in files.stepped}
        self._entries = {k: e for k, e in self._entries.items() if k in keys}
        # A file whose next record is long first, so that record has the whole run.
        for key, path in sorted(keys.items(), key=lambda kv: not self._next_is_long(*kv)):
            try:
                part, file_done, size = self._file(path, key)
            except OSError:
                found.unknown = True  # missing or unreadable: never a clean zero
                continue
            found.add(part)
            done, total = done + file_done, total + size
        for path in files.whole:
            try:
                data = Path(path).read_bytes()
            except OSError:
                found.unknown = True
                continue
            found.add(Tally(unknown=True) if compressed(data) else self._audit(path, data)[0])
        return found, done, total

    def _next_is_long(self, key: str, path: str) -> bool:
        """Does the record at the file's offset run past LONG_RECORD_BYTES?"""
        entry = self._entries.get(key)
        try:
            with open(path, "rb") as handle:
                handle.seek(0 if entry is None else entry.offset)
                head = handle.read(LONG_RECORD_BYTES + 1)
        except OSError:
            return False  # read in its turn, which says what is wrong
        return len(head) > LONG_RECORD_BYTES and b"\n" not in head[:LONG_RECORD_BYTES]

    def _over(self) -> bool:
        """Past the deadline, once a step was taken: every run moves on."""
        return self._stepped and time.monotonic() >= self._deadline

    def _file(self, path: str, key: str) -> tuple[Tally, int, int]:
        st = os.stat(path)
        size = st.st_size
        with open(path, "rb") as handle:
            entry = self._entries.get(key)
            window = b""
            if entry is not None:
                # Read on only the same file, grown, its read part's end unchanged.
                handle.seek(max(0, entry.offset - _PREFIX_BYTES))
                window = handle.read(entry.offset - max(0, entry.offset - _PREFIX_BYTES))
                if (entry.dev, entry.ino) != (st.st_dev, st.st_ino) or size < entry.offset or (
                    not hmac.compare_digest(self._mac("prefix", window), entry.prefix_mac)
                ):
                    entry = None
            if entry is None:
                handle.seek(0)
                if compressed(handle.read(4)):
                    return Tally(unknown=True), size, size
                window = b""
                entry = _Entry(st.st_dev, st.st_ino, 0, self._mac("prefix", b""), Tally(), None)
            # Kept before the first step, so every checkpoint holds it.
            self._entries[key] = entry
            if size == 0:
                return Tally(unknown=True), 0, 0  # an empty transcript is not a clean one
            return self._steps(path, st, entry, handle, window)

    def _steps(
        self, path: str, st: os.stat_result, entry: _Entry, handle: BinaryIO, window: bytes
    ) -> tuple[Tally, int, int]:
        """Read whole lines on from the entry's offset, up to the size `st`
        gave, one step of at least CHUNK_BYTES at a time."""
        size = st.st_size
        handle.seek(entry.offset)
        read_to = entry.offset
        pending = bytearray()
        while True:
            if self._over():
                return entry.found, entry.offset, size
            start = CHUNK_BYTES - 1
            while (cut := pending.find(b"\n", start)) < 0 and read_to < size:
                more = handle.read(min(CHUNK_BYTES, size - read_to))
                if not more:
                    break
                start = max(CHUNK_BYTES - 1, len(pending))
                pending += more
                read_to += len(more)
            if cut < 0:
                cut = pending.rfind(b"\n")  # the last whole line left
            if cut < 0:
                break
            chunk = bytes(pending[: cut + 1])
            if len(chunk) > LONG_RECORD_BYTES:
                # The lines before a long line are a step of their own.
                chunk = chunk[: chunk.rfind(b"\n", 0, len(chunk) - 1) + 1] or chunk
            step = self._audit_step(path, chunk, entry)
            if step is None:
                return entry.found, entry.offset, size
            part, fmt = step
            del pending[: len(chunk)]
            if entry.format is None and fmt is not None and entry.offset:
                return self._again(path, st, entry, handle, fmt)
            entry.format = fmt
            entry.found.add(part)
            entry.offset += len(chunk)
            window = (window + chunk)[-_PREFIX_BYTES:]
            entry.prefix_mac = self._mac("prefix", window)
            self._stepped = True
            self.save()
        found = Tally()
        found.add(entry.found)
        if pending:
            if time.time() - st.st_mtime_ns / 1e9 < FRESH_TAIL_S:
                return found, entry.offset, size  # still being written: unread
            step = self._audit_step(path, bytes(pending), entry)  # it stopped mid-line
            if step is None:
                return found, entry.offset, size
            part, fmt = step
            if entry.format is None and fmt is not None and entry.offset:
                return self._again(path, st, entry, handle, fmt)
            found.add(part)
        return found, size, size

    def _again(
        self, path: str, st: os.stat_result, entry: _Entry, handle: BinaryIO, fmt: Format
    ) -> tuple[Tally, int, int]:
        """The steps before were recognised as no format on their own (what
        Claude Code writes before the first prompt, say): read the file again
        from its start in the format this step was recognised as, as `weir
        audit` reads the whole file."""
        entry.offset, entry.prefix_mac = 0, self._mac("prefix", b"")
        entry.found, entry.format = Tally(), fmt
        return self._steps(path, st, entry, handle, b"")

    def _audit_step(
        self, path: str, data: bytes, entry: _Entry
    ) -> tuple[Tally, Format | None] | None:
        """What a step holds and its format. A long record is searched only
        as a run's first step (None: left for the next run, which reads its
        file first), within LONG_RECORD_S, and each try is counted in the
        checkpoint before it begins: one tried LONG_RECORD_TRIES times, each
        cancelled or out of time, is skipped, and the session is partly
        checked."""
        if not (
            len(data) > LONG_RECORD_BYTES and data.find(b"\n") in (-1, len(data) - 1)
            and len(data) - _image_bytes(data) > LONG_RECORD_BYTES
        ):
            return self._audit(path, data, entry.format)
        if entry.marked != entry.offset:
            entry.marked, entry.tries = entry.offset, 0
        if entry.tries >= LONG_RECORD_TRIES:
            return Tally(partial=True), entry.format
        if self._stepped:
            return None
        entry.tries += 1
        self.save()
        try:
            with _time_bound(LONG_RECORD_S):
                step = self._audit(path, data, entry.format)
        except _TimeUp:
            self._stepped = True  # this run's time is spent: the next tries again
            return None
        entry.marked, entry.tries = -1, 0
        return step

    def _audit(
        self, path: str, data: bytes, as_format: Format | None = None
    ) -> tuple[Tally, Format | None]:
        """What `data` holds, audited in `as_format`, else in the format it
        is recognised as, and that format (None: none)."""
        report = audit_chunks(self._inputs, [(path, data)], self._dirs, as_format)
        fmt = report.files[0].format
        return tally(report), None if fmt is Format.UNKNOWN else fmt


class _TimeUp(Exception):
    pass


@contextmanager
def _time_bound(seconds: float) -> Generator[None, None, None]:
    """Raise _TimeUp in the main thread once `seconds` have passed (not on
    Windows, which has no SIGALRM)."""
    if seconds <= 0:
        raise _TimeUp
    if sys.platform == "win32":
        yield
        return

    def up(_signum: int, _frame: FrameType | None) -> None:
        raise _TimeUp

    previous = signal.signal(signal.SIGALRM, up)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _image_bytes(line: bytes) -> int:
    """The bytes of the base64 image data in a line, which the audit never
    searches, found without parsing it: a record of very many blocks takes
    seconds to parse."""
    return sum(len(match[1]) for match in _IMAGE_DATA.finditer(line))


def read_session(
    inputs: Inputs, cache: Path, transcript: str, session_id: str,
    claude_config_dirs: Sequence[str], budget_s: float, *, colour: bool = False,
) -> str:
    """The segment for one session."""
    if not inputs.by_fingerprint:
        return note(NOTHING_TO_CHECK, colour=colour)  # nothing to count: never a clean
    deadline = time.monotonic() + budget_s
    reader = Reader(inputs, cache, transcript + "\0" + session_id, claude_config_dirs, deadline)
    reader.load()
    found, done, total = reader.read(session_files(transcript, session_id))
    reader.save()
    context, sent = counted(found, inputs)
    scanning = done * 100 // total if done < total else None
    return segment_text(
        context, sent, unknown=found.unknown, partial=found.partial, scanning=scanning,
        colour=colour,
    )
