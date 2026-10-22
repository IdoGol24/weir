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
import os
import stat
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

import msgspec

from weir.audit import Chunk, Form, Format, Inputs, Kind, Report, audit_chunks
from weir.audit.formats import is_session_record, json_lines, recognise
from weir.statusline.files import write_private

CACHE_SCHEMA = "weir-statusline-cache/1"
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
    context: int, sent: int, *, unknown: bool, checking: int | None = None
) -> str:
    """The segment's words (docs/statusline.md, "The segment")."""
    counts = f"{context} in context, {sent} sent"
    if checking is not None:
        return f"weir: {counts}, checking {checking}%" if context or sent else (
            f"weir: checking {checking}%"
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
    parent = os.path.dirname(transcript)
    stem = PurePath(transcript).stem
    for name in dict.fromkeys((stem, session_id)):
        top = os.path.join(parent, name)
        if not name or not os.path.isdir(top) or os.path.islink(top):
            unreadable = unreadable or os.path.islink(top)
            continue
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
        """Read the cache, dropping it when the inventory changed."""
        self._inputs_mac = self._mac("inputs", inputs_bytes)
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
                # both ends, read only what was appended.
                head = handle.read(min(cached.offset, _PREFIX_BYTES))
                start = max(0, cached.offset - _PREFIX_BYTES)
                handle.seek(start)
                data = handle.read()
                if self._read_part_unchanged(cached, head, data[: cached.offset - start]):
                    return self._lines(path, st, cached, data, start)
                handle.seek(0)
            data = handle.read()
        fmt, certain = self._recognise(path, data)
        resume = (
            cached is not None and cached.format is fmt and fmt in _LINEWISE
            and cached.same_file(st)
            and self._read_part_unchanged(
                cached, data[: min(cached.offset, _PREFIX_BYTES)],
                data[max(0, cached.offset - _PREFIX_BYTES) : cached.offset],
            )
        )
        entry = cached if resume and cached is not None else _Entry(
            dev=st.st_dev, ino=st.st_ino, size=st.st_size, mtime_ns=st.st_mtime_ns, format=fmt,
            certain=certain, offset=0, head_mac=self._mac("head", b""),
            prefix_mac=self._mac("prefix", b""), lines=Tally(), tail=None,
        )
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
        return self._lines(path, st, entry, data, 0)

    def _read_part_unchanged(self, cached: _Entry, head: bytes, before_offset: bytes) -> bool:
        return (
            hmac.compare_digest(self._mac("head", head), cached.head_mac)
            and hmac.compare_digest(self._mac("prefix", before_offset), cached.prefix_mac)
        )

    def _recognise(self, path: str, data: bytes) -> tuple[Format, bool]:
        """The file's format, and whether it is a Claude Code session for
        sure. A message record in the first whole lines settles both
        without parsing the rest, so a first read of a long transcript
        costs its auditing steps, which the deadline bounds."""
        first = data.find(b"\n", CHUNK_BYTES - 1)
        if first >= 0 and any(
            is_session_record(line.parsed) for line in json_lines(data[: first + 1])
        ):
            return Format.CLAUDE_CODE, True
        lines = json_lines(data)
        fmt = recognise(path, data, lines, self._projects)
        return fmt, fmt is Format.CLAUDE_CODE and any(
            is_session_record(line.parsed) for line in lines
        )

    def _lines(
        self, path: str, st: os.stat_result, entry: _Entry, data: bytes, base: int
    ) -> tuple[_Entry, int, int]:
        """Read whole lines from the entry's offset on. `data` holds the
        file's bytes from `base` on."""
        end = base + data.rfind(b"\n") + 1  # the end of the last whole line
        entry.tail = None
        self._stamp(entry, st)
        while entry.offset < end:
            if self._over():
                self.save()
                return entry, entry.offset, st.st_size
            stop = data.find(b"\n", entry.offset - base + CHUNK_BYTES - 1)
            stop = end if stop < 0 else min(end, base + stop + 1)
            chunk = data[entry.offset - base : stop - base]
            entry.lines.add(self._audit(path, chunk, entry.format))
            entry.offset = stop
            if base == 0:
                entry.head_mac = self._mac("head", data[: min(stop, _PREFIX_BYTES)])
            window = data[max(0, stop - base - _PREFIX_BYTES) : stop - base]
            entry.prefix_mac = self._mac("prefix", window)
            self._stepped = True
            self.save()
        tail = data[end - base :]
        entry.tail = self._audit(path, tail, entry.format) if tail else Tally()
        self.save()
        return entry, st.st_size, st.st_size

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
        return segment_text(context, sent, unknown=found.unknown, checking=done * 100 // total)
    return segment_text(context, sent, unknown=found.unknown)
