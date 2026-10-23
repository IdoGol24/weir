"""The status-line segment (docs/statusline.md, "The segment").

Claude Code runs the status line after every assistant message and cancels
a run that is still going when the next one starts, so the segment reads a
session in steps and keeps what each step found: a session file is read in
chunks of whole lines, each chunk is audited with `weir.audit` as the
format of the whole file, and the credential ids it found are cached with
the byte offset reached. A file that only grew is read from that offset
on; a file that changed in any other way is read again from the start.

The cache holds credential ids, offsets, sizes and keyed MACs (HMAC-SHA256
under the inventory's fingerprint key), never a value, a fragment, a file
name or an unkeyed hash of one.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import stat
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import BinaryIO

import msgspec

from weir.audit import Chunk, Form, Format, Inputs, Kind, Report, audit_chunks
from weir.audit.formats import is_session_record, json_lines, recognise
from weir.statusline.files import write_private

CACHE_SCHEMA = "weir-statusline-cache/1"
# A temporary cache file this old is one a run killed mid-write left behind
# (SIGKILL ends a run without cleanup); a live run's is far younger.
_STALE_TEMP_S = 60.0
# The word the segment shows until every file is read to its end.
SCANNING = "scanning\u2026"
# A step reads at least one whole line and stops at the first line end past this.
CHUNK_BYTES = 64 * 1024
# The bytes at the start of a file, and the bytes before the offset, whose
# MACs show a file only grew: the read part is checked at both ends, never
# read whole again.
_PREFIX_BYTES = 4096
# Formats whose lines are read each on their own: a chunk of whole lines
# gives the hits those lines give in the whole file.
_LINEWISE = frozenset({
    Format.CLAUDE_CODE, Format.CLAUDE_CODE_TOOL_RESULTS, Format.CLAUDE_CODE_MEMORY,
    Format.UNKNOWN,
})


class Tally(msgspec.Struct):
    """What part of a session holds: the credential ids whose value entered
    the context, those sent in a tool call by value or by name, and whether
    anything there is unknown."""

    context: set[str] = msgspec.field(default_factory=set[str])
    sent: set[str] = msgspec.field(default_factory=set[str])
    unknown: bool = False

    def add(self, other: Tally) -> None:
        self.context |= other.context
        self.sent |= other.sent
        self.unknown = self.unknown or other.unknown


def tally(report: Report) -> Tally:
    """docs/statusline.md, "What is counted": a `context` hit, or a
    `tool_call` hit by value, put the value in the context; any `tool_call`
    hit, by value or by name, sent it."""
    out = Tally(unknown=bool(report.unknown))
    for hit in report.hits:
        if hit.kind is Kind.CONTEXT or (hit.kind is Kind.TOOL_CALL and hit.form is not Form.NAME):
            out.context.add(hit.credential)
        if hit.kind is Kind.TOOL_CALL:
            out.sent.add(hit.credential)
    return out


def value_groups(inputs: Inputs) -> dict[str, str]:
    """Credential id -> the credential it stands for: records that share a
    fingerprint are one value, and records of an environment variable
    assignment (the launch environment, a shell startup file) that share a
    name are one variable; each is counted once. In memory only."""
    out = {c.id: c.id for c in inputs.credentials}

    def find(cid: str) -> str:
        while out[cid] != cid:
            cid = out[cid]
        return cid

    names: dict[str, list[str]] = {}
    for c in inputs.credentials:
        if c.variable:
            names.setdefault(c.name, []).append(c.id)
    for ids in [*inputs.by_fingerprint.values(), *names.values()]:
        for cid in ids[1:]:
            out[find(cid)] = find(ids[0])
    return {cid: find(cid) for cid in out}


def segment_text(
    context: int, sent: int, *, unknown: bool, scanning: int | None = None
) -> str:
    """The segment's words (docs/statusline.md, "The segment")."""
    counts = f"{context} in context, {sent} sent"
    if scanning is not None:
        return f"weir: {counts}, {SCANNING} {scanning}%" if context or sent else (
            f"weir: {SCANNING} {scanning}%"
        )
    if unknown and not (context or sent):
        return "weir: unknown"
    return f"weir: {counts}, part unknown" if unknown else f"weir: {counts}"


def counted(t: Tally, groups: dict[str, str]) -> tuple[int, int]:
    return (
        len({groups.get(c, c) for c in t.context}), len({groups.get(c, c) for c in t.sent}),
    )


# --- the session's files ---------------------------------------------------------


@dataclass(frozen=True)
class SessionFiles:
    files: list[str]
    # Something in the session that cannot be read: it makes the result unknown.
    unreadable: bool


def session_files(transcript: str, session_id: str) -> SessionFiles:
    """The transcript, then every file in the session's own directory
    beside it (`<session>/subagents/`, `<session>/tool-results/` and
    anything else there), in sorted path order. A missing transcript, a
    symbolic link or an entry that is not a regular file or directory is
    unreadable, never skipped."""
    files = [transcript]
    unreadable = not os.path.isfile(transcript)
    top = os.path.join(os.path.dirname(transcript), session_id)
    if os.path.islink(top):
        return SessionFiles(files, True)
    for root, dirs, names in os.walk(top):
        dirs.sort()
        for d in list(dirs):
            if os.path.islink(os.path.join(root, d)):
                dirs.remove(d)
                unreadable = True
        for n in sorted(names):
            path = os.path.join(root, n)
            mode = os.lstat(path).st_mode
            if stat.S_ISREG(mode):
                files.append(path)
            else:
                unreadable = True
    return SessionFiles(files, unreadable)


# --- reading a file in steps --------------------------------------------------------


class _Entry(msgspec.Struct):
    """The cached progress through one file."""

    dev: int
    ino: int
    size: int
    mtime_ns: int
    format: Format
    # The whole file is a Claude Code session for sure: it holds a message
    # record, so whatever is appended, it stays one.
    certain: bool
    offset: int
    # MACs of the file's first bytes up to the offset (at most
    # _PREFIX_BYTES), and of the _PREFIX_BYTES before the offset.
    head_mac: str
    prefix_mac: str
    lines: Tally
    # What the bytes after the last line end held, at this size and time.
    tail: Tally | None

    @property
    def done(self) -> bool:
        return self.tail is not None

    def same_file(self, st: os.stat_result) -> bool:
        return (self.dev, self.ino) == (st.st_dev, st.st_ino) and st.st_size >= self.offset

    def unchanged(self, st: os.stat_result) -> bool:
        return self.same_file(st) and (self.size, self.mtime_ns) == (
            st.st_size, st.st_mtime_ns
        )


class _Cache(msgspec.Struct, frozen=True):
    schema: str
    inputs: str
    files: dict[str, _Entry]


class Reader:
    """Reads a session's files in steps under a deadline, keeping progress
    in a cache file."""

    def __init__(
        self, inputs: Inputs, cache: Path, session_key: str,
        claude_config_dirs: Sequence[str], deadline: float,
    ) -> None:
        self._inputs = inputs
        self._dirs = list(claude_config_dirs)
        self._projects = [PurePath(os.path.abspath(d), "projects") for d in claude_config_dirs]
        self._deadline = deadline
        self._stepped = False
        self._path = cache / f"{self._mac('session', session_key.encode())[:32]}.json"
        self._inputs_mac = ""
        self._entries: dict[str, _Entry] = {}

    def _mac(self, label: str, data: bytes) -> str:
        message = b"weir-statusline " + label.encode() + b"\0" + data
        return hmac.new(self._inputs.key, message, hashlib.sha256).hexdigest()

    # -- the cache file --

    def load(self, inputs_bytes: bytes) -> None:
        """Read the cache, dropping it when the inventory changed, and
        remove what a killed run left half-written."""
        self._inputs_mac = self._mac("inputs", inputs_bytes)
        now = time.time()
        for temp in self._path.parent.glob(f".{self._path.name}.*"):
            try:
                if now - temp.stat().st_mtime > _STALE_TEMP_S:
                    temp.unlink()
            except OSError:
                pass  # gone already, or another run's: the next run tries again
        try:
            cache = msgspec.json.decode(self._path.read_bytes(), type=_Cache)
        except (OSError, msgspec.DecodeError):
            return
        if cache.schema == CACHE_SCHEMA and cache.inputs == self._inputs_mac:
            self._entries = dict(cache.files)

    def save(self) -> None:
        cache = _Cache(CACHE_SCHEMA, self._inputs_mac, dict(sorted(self._entries.items())))
        write_private(self._path, msgspec.json.encode(cache) + b"\n")

    # -- reading --

    def read(self, files: Iterable[str]) -> tuple[Tally, int, int]:
        """Read every file as far as the deadline allows. Returns what was
        found, the bytes read and the bytes in all."""
        found = Tally()
        done = total = 0
        keep: dict[str, _Entry] = {}
        for path in files:
            key = self._mac("path", os.fsencode(path))
            try:
                entry, file_done, size = self._file(path, self._entries.get(key))
            except OSError:
                found.unknown = True
                continue
            total += size
            done += file_done
            if entry is not None:
                keep[key] = entry
                self._entries[key] = entry
                found.add(entry.lines)
                if entry.tail is not None:
                    found.add(entry.tail)
        self._entries = keep
        return found, done, total

    def _over(self) -> bool:
        """Past the deadline, once at least one step was taken this run, so
        every run moves the reading on."""
        return self._stepped and time.monotonic() >= self._deadline

    def _file(self, path: str, cached: _Entry | None) -> tuple[_Entry | None, int, int]:
        st = os.stat(path)
        if cached is not None and cached.done and cached.unchanged(st):
            return cached, st.st_size, st.st_size
        if self._over():
            # Not reached this run: count it unread, keep what an earlier run read.
            ahead = cached is not None and cached.same_file(st)
            return (cached if ahead else None), (cached.offset if cached and ahead else 0), (
                st.st_size
            )
        with open(path, "rb") as handle:
            if cached is not None and cached.certain and cached.same_file(st):
                # A session file for sure: when its read part is unchanged at
                # both ends, read on from the offset, never the read part.
                head = handle.read(min(cached.offset, _PREFIX_BYTES))
                handle.seek(max(0, cached.offset - _PREFIX_BYTES))
                window = handle.read(cached.offset - max(0, cached.offset - _PREFIX_BYTES))
                if self._read_part_unchanged(cached, head, window):
                    return self._lines(path, st, cached, handle, head, window)
                handle.seek(0)
            first = self._first_lines(handle, st.st_size)
            if first is not None:
                # A message record in the first whole lines settles the
                # format without reading the rest: a long transcript is read
                # in the steps the deadline bounds, from its start, the
                # bytes already read taken as they are.
                entry = self._new_entry(st, Format.CLAUDE_CODE, certain=True)
                return self._lines(path, st, entry, handle, b"", b"", read=first)
            handle.seek(0)
            data = handle.read()
        lines = json_lines(data)
        fmt = recognise(path, data, lines, self._projects)
        certain = fmt is Format.CLAUDE_CODE and any(
            is_session_record(line.parsed) for line in lines
        )
        head = window = b""
        if cached is not None:
            head = data[: min(cached.offset, _PREFIX_BYTES)]
            window = data[max(0, cached.offset - _PREFIX_BYTES) : cached.offset]
        resume = (
            cached is not None and cached.format is fmt and fmt in _LINEWISE
            and cached.same_file(st) and self._read_part_unchanged(cached, head, window)
        )
        if resume and cached is not None:
            entry = cached
        else:
            entry, head, window = self._new_entry(st, fmt, certain=certain), b"", b""
        entry.certain = certain
        if fmt not in _LINEWISE:
            # A whole-file format: one step, all or nothing.
            entry.lines = self._audit(path, data, fmt)
            entry.offset = len(data)
            entry.head_mac = self._mac("head", data[:_PREFIX_BYTES])
            entry.prefix_mac = self._mac("prefix", data[-_PREFIX_BYTES:])
            entry.tail = Tally()
            self._stamp(entry, st)
            self._stepped = True
            self.save()
            return entry, len(data), len(data)
        source = io.BytesIO(data)
        source.seek(entry.offset)
        return self._lines(path, st, entry, source, head, window)

    def _new_entry(self, st: os.stat_result, fmt: Format, *, certain: bool) -> _Entry:
        return _Entry(
            dev=st.st_dev, ino=st.st_ino, size=st.st_size, mtime_ns=st.st_mtime_ns, format=fmt,
            certain=certain, offset=0, head_mac=self._mac("head", b""),
            prefix_mac=self._mac("prefix", b""), lines=Tally(), tail=None,
        )

    def _read_part_unchanged(self, cached: _Entry, head: bytes, before_offset: bytes) -> bool:
        return (
            hmac.compare_digest(self._mac("head", head), cached.head_mac)
            and hmac.compare_digest(self._mac("prefix", before_offset), cached.prefix_mac)
        )

    @staticmethod
    def _first_lines(handle: BinaryIO, size: int) -> bytes | None:
        """The bytes read from the start, when the first whole lines (at
        least CHUNK_BYTES) hold a Claude Code message record: the file is a
        session file whatever the rest holds. None otherwise."""
        first = bytearray(handle.read(min(size, CHUNK_BYTES)))
        start = CHUNK_BYTES - 1
        while (cut := first.find(b"\n", start)) < 0 and len(first) < size:
            more = handle.read(min(CHUNK_BYTES, size - len(first)))
            if not more:
                break
            start = max(CHUNK_BYTES - 1, len(first))
            first += more
        if cut >= 0 and any(
            is_session_record(line.parsed) for line in json_lines(bytes(first[: cut + 1]))
        ):
            return bytes(first)
        return None

    def _lines(
        self, path: str, st: os.stat_result, entry: _Entry, handle: BinaryIO, head: bytes,
        window: bytes, read: bytes = b"",
    ) -> tuple[_Entry, int, int]:
        """Read whole lines from the entry's offset on, in steps of at least
        CHUNK_BYTES, from `handle`. `read` holds bytes from the offset on
        already read, and `handle` stands just after them. `head` and
        `window` are the file's first bytes up to the offset (at most
        _PREFIX_BYTES) and the _PREFIX_BYTES before it. Only the bytes of
        the step being taken are held, and only up to the size `st` gave."""
        size = st.st_size
        entry.tail = None
        self._stamp(entry, st)
        pending = bytearray(read)  # bytes from the offset on, read and not yet audited
        read_to = entry.offset + len(read)
        handle.seek(read_to)
        while True:
            if self._over():
                self.save()
                return entry, entry.offset, size
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
            del pending[: cut + 1]
            entry.lines.add(self._audit(path, chunk, entry.format))
            if entry.offset < _PREFIX_BYTES:
                head = (head + chunk)[:_PREFIX_BYTES]
                entry.head_mac = self._mac("head", head)
            entry.offset += len(chunk)
            window = (window + chunk)[-_PREFIX_BYTES:]
            entry.prefix_mac = self._mac("prefix", window)
            self._stepped = True
            self.save()
        entry.tail = self._audit(path, bytes(pending), entry.format) if pending else Tally()
        self.save()
        return entry, size, size

    def _stamp(self, entry: _Entry, st: os.stat_result) -> None:
        entry.dev, entry.ino = st.st_dev, st.st_ino
        entry.size, entry.mtime_ns = st.st_size, st.st_mtime_ns

    def _audit(self, path: str, data: bytes, fmt: Format) -> Tally:
        report = audit_chunks(self._inputs, [Chunk(path, data, fmt)], self._dirs)
        return tally(report)


def read_session(
    inputs: Inputs, inputs_bytes: bytes, cache: Path, transcript: str, session_id: str,
    claude_config_dirs: Sequence[str], budget_s: float,
) -> str:
    """The segment for one session (docs/statusline.md)."""
    deadline = time.monotonic() + budget_s
    reader = Reader(inputs, cache, transcript + "\0" + session_id, claude_config_dirs, deadline)
    reader.load(inputs_bytes)
    files = session_files(transcript, session_id)
    found, done, total = reader.read(files.files)
    found.unknown = found.unknown or files.unreadable
    reader.save()
    context, sent = counted(found, value_groups(inputs))
    if done < total:
        return segment_text(context, sent, unknown=found.unknown, scanning=done * 100 // total)
    return segment_text(context, sent, unknown=found.unknown)
