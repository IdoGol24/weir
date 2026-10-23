"""The status-line segment (docs/statusline.md, "The segment").

Claude Code runs the status line after every assistant message and cancels
a run that is still going when the next one starts, so the segment reads a
session in steps and keeps what each step found: a file is read in chunks
of whole lines (one that may be a whole-file format, in one step), each
chunk is audited with `weir.audit` as the format the file's path and the
lines read so far give, and the credential ids it found are cached with the
byte offset reached. A file that only grew is read from that offset on; a
file that changed in any other way, or whose format a later line changes,
is read again from the start.

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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import BinaryIO

import msgspec

from weir.audit import Chunk, Form, Format, Inputs, Kind, Report, audit_chunks
from weir.audit.formats import (
    Signs,
    json_lines,
    may_be_whole,
    recognise,
    recognise_signs,
    signs,
)
from weir.canary.capture import compressed
from weir.statusline.files import write_private

CACHE_SCHEMA = "weir-statusline-cache/4"
# A temporary cache file this old is one a run killed mid-write left behind
# (SIGKILL ends a run without cleanup); a live run's is far younger.
_STALE_TEMP_S = 60.0
# The word the segment shows until every file is read to its end.
SCANNING = "scanning\u2026"
# Enough of a file's start to tell a compressed one (weir.canary.capture).
_MAGIC_BYTES = 4
# A step reads at least one whole line and stops at the first line end past this.
CHUNK_BYTES = 64 * 1024
# A step of a text file never holds more than this: a longer line is read in
# windows of it that overlap (Reader._overlap), with a checkpoint inside it.
STEP_MAX_BYTES = 4 * CHUNK_BYTES
# A file that needs to be read whole (a whole-file format) is read whole
# only up to this size; a larger one is read in steps as unknown text.
WHOLE_MAX_BYTES = 1024 * 1024
# The read part of a file is kept as keyed MACs of blocks this size, and
# one block is checked on each refresh, so a rewrite inside the part already
# read is found within as many refreshes as the file has blocks.
BLOCK_BYTES = 1024 * 1024
# A Claude Code session file's last line without its line end is one still
# being written while the file changed this recently: not counted as unknown
# yet. Older, it is (a session that stopped mid-line).
FRESH_TAIL_S = 5.0
# The bytes at the start of a file, and the bytes before the offset, whose
# MACs show a file only grew: the read part is checked at both ends, never
# read whole again.
_PREFIX_BYTES = 4096
# Text formats: a line longer than a step can be read in overlapping windows.
_TEXT = frozenset({
    Format.CLAUDE_CODE_TOOL_RESULTS, Format.CLAUDE_CODE_MEMORY, Format.UNKNOWN,
})
# Formats whose lines are read each on their own: a chunk of whole lines
# gives the hits those lines give in the whole file.
_LINEWISE = frozenset({
    Format.CLAUDE_CODE, Format.CLAUDE_CODE_TOOL_RESULTS, Format.CLAUDE_CODE_MEMORY,
    Format.UNKNOWN,
})


class Tally(msgspec.Struct):
    """What part of a session holds: the credential ids whose value entered
    the context, those whose value was sent in a tool call, those a tool
    call sent by name, and whether anything there is unknown."""

    context: set[str] = msgspec.field(default_factory=set[str])
    sent: set[str] = msgspec.field(default_factory=set[str])
    named: set[str] = msgspec.field(default_factory=set[str])
    unknown: bool = False

    def add(self, other: Tally) -> None:
        self.context |= other.context
        self.sent |= other.sent
        self.named |= other.named
        self.unknown = self.unknown or other.unknown


def tally(report: Report) -> Tally:
    """docs/statusline.md, "What is counted": a `context` hit, or a
    `tool_call` hit by value, put the value in the context; any `tool_call`
    hit, by value or by name, sent it."""
    out = Tally(unknown=bool(report.unknown))
    for hit in report.hits:
        by_value = hit.form is not Form.NAME
        if hit.kind is Kind.CONTEXT or (hit.kind is Kind.TOOL_CALL and by_value):
            out.context.add(hit.credential)
        if hit.kind is Kind.TOOL_CALL:
            (out.sent if by_value else out.named).add(hit.credential)
    return out


def value_groups(inputs: Inputs) -> dict[str, str]:
    """Credential id -> the value it stands for: records whose stored
    fingerprints are equal hold one value. In memory only."""
    out = {c.id: c.id for c in inputs.credentials}
    for ids in inputs.by_fingerprint.values():
        for cid in ids:
            out[cid] = ids[0]
    return out


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


def counted(t: Tally, inputs: Inputs) -> tuple[int, int]:
    """(in context, sent): distinct values, not inventory records. A
    variable sent by name counts once for its name, and not at all when a
    value of a record of that name is already counted as sent."""
    groups = value_groups(inputs)
    variables = {c.id: c.name for c in inputs.credentials if c.variable}
    context = {groups.get(c, c) for c in t.context}
    by_value = {groups.get(c, c) for c in t.sent}
    covered = {name for cid, name in variables.items() if groups[cid] in by_value}
    by_name = {variables[c] for c in t.named if c in variables} - covered
    return len(context), len(by_value) + len(by_name)


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
    # What the lines read so far show of the format. Once they hold a
    # message record the file is a Claude Code session file whatever else
    # it holds or is appended.
    seen: Signs
    # Read as a whole in one step (a whole-file format), never read on.
    whole: bool
    # Read as unknown text in steps, its format no longer recognised: a
    # whole-file format too large to read in one step.
    text: bool
    offset: int
    # MACs of the file's first bytes up to the offset (at most
    # _PREFIX_BYTES), and of the _PREFIX_BYTES before the offset.
    head_mac: str
    prefix_mac: str
    lines: Tally
    # What the bytes after the last line end held, at this size and time.
    tail: Tally | None
    # The tail was a session file's line still being written, not counted.
    fresh_tail: bool = False
    # Keyed MACs of the read part's whole BLOCK_BYTES blocks, and the block
    # the next refresh checks.
    blocks: list[str] = msgspec.field(default_factory=list[str])
    next_block: int = 0

    @property
    def done(self) -> bool:
        return self.tail is not None

    def same_file(self, st: os.stat_result) -> bool:
        return (self.dev, self.ino) == (st.st_dev, st.st_ino) and st.st_size >= self.offset

    def unchanged(self, st: os.stat_result) -> bool:
        return self.same_file(st) and (self.size, self.mtime_ns) == (
            st.st_size, st.st_mtime_ns
        )


class _BlockMacs:
    """Keeps the MAC of each BLOCK_BYTES block of a file's read part as the
    steps of one run complete it, from the bytes the steps hold. Only the
    start of the one block a run resumes inside is read again."""

    def __init__(self, mac: Callable[[bytes], str], handle: BinaryIO, entry: _Entry) -> None:
        self._mac = mac
        self._handle = handle
        self._entry = entry
        # The read part's bytes from the first block with no MAC yet
        self._buf: bytearray | None = None

    def grew(self, consumed: bytes, read_to: int) -> None:
        """The read part grew by `consumed`; `read_to` is where `handle`
        stands, and stands again after."""
        entry = self._entry
        if self._buf is not None:
            self._buf += consumed
        if len(entry.blocks) >= entry.offset // BLOCK_BYTES:
            return
        if self._buf is None:
            start = len(entry.blocks) * BLOCK_BYTES
            self._handle.seek(start)
            self._buf = bytearray(self._handle.read(entry.offset - start))
            self._handle.seek(read_to)
        while len(entry.blocks) < entry.offset // BLOCK_BYTES:
            entry.blocks.append(self._mac(bytes(self._buf[:BLOCK_BYTES])))
            del self._buf[:BLOCK_BYTES]


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
        # Long text lines are read in windows that overlap by more than any
        # encoding of the longest value (JSON escaping twice, URL encoding),
        # and by at least 32 KiB when the store gives no length.
        self._overlap = max(32 * 1024, 6 * inputs.longest_value + 1024)
        self._step = max(STEP_MAX_BYTES, 2 * self._overlap)
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
                entry, file_done, size = self._file(path, key)
            except OSError:
                found.unknown = True
                continue
            total += size
            done += file_done
            if entry is not None:
                keep[key] = entry
                found.add(entry.lines)
                if entry.tail is not None:
                    found.add(entry.tail)
        self._entries = keep
        return found, done, total

    def _over(self) -> bool:
        """Past the deadline, once at least one step was taken this run, so
        every run moves the reading on."""
        return self._stepped and time.monotonic() >= self._deadline

    def _file(self, path: str, key: str) -> tuple[_Entry | None, int, int]:
        """Read one file on from its cached entry. A new entry is kept under
        `key` before its first step, so every checkpoint holds its progress."""
        cached = self._entries.get(key)
        st = os.stat(path)
        size = st.st_size
        if (
            cached is not None and cached.same_file(st) and size == cached.size
            and st.st_mtime_ns != cached.mtime_ns
        ):
            # Rewritten in place at the same size: an append changes the
            # size, so nothing of the read part can be trusted.
            cached = None
        settled = (
            cached is not None and cached.done and cached.unchanged(st)
            and not self._tail_ripe(cached, st)
        )
        if cached is not None and settled and (not cached.blocks or self._over()):
            return cached, size, size
        if not settled and self._over():
            # Not reached this run: count it unread, keep what an earlier run read.
            ahead = cached is not None and cached.same_file(st)
            return (cached if ahead else None), (cached.offset if cached and ahead else 0), size
        with open(path, "rb") as handle:
            if (
                cached is not None and not cached.whole and cached.same_file(st)
                and self._block_holds(handle, cached)
            ):
                if settled:
                    return cached, size, size
                # When the read part is unchanged at both ends, read on from
                # the offset, never the read part.
                head = handle.read(min(cached.offset, _PREFIX_BYTES))
                handle.seek(max(0, cached.offset - _PREFIX_BYTES))
                window = handle.read(cached.offset - max(0, cached.offset - _PREFIX_BYTES))
                if self._read_part_unchanged(cached, head, window):
                    return self._steps(path, st, cached, handle, head, window)
            entry = self._entries[key] = _Entry(
                dev=st.st_dev, ino=st.st_ino, size=size, mtime_ns=st.st_mtime_ns,
                format=recognise_signs(path, Signs(), self._projects), seen=Signs(),
                whole=False, text=False, offset=0, head_mac="", prefix_mac="", lines=Tally(),
                tail=None,
            )
            self._restart(entry)
            handle.seek(0)
            if compressed(handle.read(_MAGIC_BYTES)):
                # Not scanned, as `weir audit` does not scan it: unknown,
                # never a clean zero. Read again when it changes.
                entry.whole = True
                entry.offset = size
                entry.lines = Tally(unknown=True)
                entry.tail = Tally()
                self.save()
                return entry, size, size
            return self._steps(path, st, entry, handle, b"", b"")

    def _tail_ripe(self, entry: _Entry, st: os.stat_result) -> bool:
        """A line still being written when it was read, that has stopped
        changing long enough to count as it is."""
        return entry.fresh_tail and time.time() - st.st_mtime_ns / 1e9 >= FRESH_TAIL_S

    def _block_holds(self, handle: BinaryIO, entry: _Entry) -> bool:
        """Check the next block of the read part against its MAC (one block
        per refresh, in turn); True when it holds or there is none."""
        if not entry.blocks:
            return True
        n = entry.next_block % len(entry.blocks)
        entry.next_block = n + 1
        handle.seek(n * BLOCK_BYTES)
        holds = hmac.compare_digest(self._block_mac(handle.read(BLOCK_BYTES)), entry.blocks[n])
        handle.seek(0)
        return holds

    def _block_mac(self, data: bytes) -> str:
        return self._mac("block", data)[:32]

    def _restart(self, entry: _Entry) -> None:
        """Back to the start of the file, the format and its signs kept."""
        entry.offset = 0
        entry.head_mac = self._mac("head", b"")
        entry.prefix_mac = self._mac("prefix", b"")
        entry.lines = Tally()
        entry.tail = None
        entry.fresh_tail = False
        entry.blocks = []
        entry.next_block = 0

    def _read_part_unchanged(self, cached: _Entry, head: bytes, before_offset: bytes) -> bool:
        return (
            hmac.compare_digest(self._mac("head", head), cached.head_mac)
            and hmac.compare_digest(self._mac("prefix", before_offset), cached.prefix_mac)
        )

    def _format(self, path: str, seen: Signs) -> Format | None:
        """The format the path and `seen` give; None for a whole-file one."""
        fmt = recognise_signs(path, seen, self._projects)
        return fmt if fmt in _LINEWISE else None

    def _steps(
        self, path: str, st: os.stat_result, entry: _Entry, handle: BinaryIO, head: bytes,
        window: bytes,
    ) -> tuple[_Entry, int, int]:
        """Read whole lines from the entry's offset on, in steps of at least
        CHUNK_BYTES, from `handle`. `head` and `window` are the file's first
        bytes up to the offset (at most _PREFIX_BYTES) and the _PREFIX_BYTES
        before it. Only the bytes of the step being taken are held, and only
        up to the size `st` gave. In a text format a step holds at most
        `self._step` bytes: a longer line is read in windows that overlap by
        `self._overlap`, so a value cut by one window's end is whole in the
        next, and the offset is kept inside the line.

        Until a message record settles it, the format is the one the path
        and the lines read so far give: a line that changes it starts the
        reading again from the start, in the new format; a whole-file
        format, or a file that may be one JSON document, is read whole."""
        size = st.st_size
        entry.tail = None
        entry.fresh_tail = False
        self._stamp(entry, st)
        pending = bytearray()  # bytes from the offset on, read and not yet audited
        read_to = entry.offset
        handle.seek(read_to)
        blocks = _BlockMacs(self._block_mac, handle, entry)
        while True:
            if self._over():
                self.save()
                return entry, entry.offset, size
            text = entry.format in _TEXT
            start = CHUNK_BYTES - 1
            while (cut := pending.find(b"\n", start)) < 0 and read_to < size:
                if text and len(pending) >= self._step:
                    break
                more = handle.read(min(CHUNK_BYTES, size - read_to))
                if not more:
                    break
                start = max(CHUNK_BYTES - 1, len(pending))
                pending += more
                read_to += len(more)
            if cut < 0:
                cut = pending.rfind(b"\n")  # the last whole line left
            if cut >= 0:
                chunk = bytes(pending[: cut + 1])
                used = len(chunk)
            elif text and len(pending) >= self._step:
                # A line longer than a step: a window of it, and the offset
                # moves on by less than the window, inside the line.
                chunk = bytes(pending[: self._step])
                used = self._step - self._overlap
            else:
                break
            if not entry.seen.message and not entry.text:
                lines = json_lines(chunk) if cut >= 0 else []
                entry.seen |= signs(lines)
                fmt = self._format(path, entry.seen)
                if fmt is None or (
                    fmt is Format.UNKNOWN and entry.offset == 0 and cut >= 0
                    and may_be_whole(chunk, lines)
                ):
                    return self._whole(path, st, entry, handle)
                if fmt is not entry.format:
                    entry.format = fmt
                    if entry.offset:
                        self._restart(entry)
                        pending.clear()
                        read_to, head, window = 0, b"", b""
                        handle.seek(0)
                        blocks = _BlockMacs(self._block_mac, handle, entry)
                        continue
            del pending[:used]
            entry.lines.add(self._audit(path, chunk, entry.format))
            consumed = chunk[:used]
            if entry.offset < _PREFIX_BYTES:
                head = (head + consumed)[:_PREFIX_BYTES]
                entry.head_mac = self._mac("head", head)
            entry.offset += used
            window = (window + consumed)[-_PREFIX_BYTES:]
            entry.prefix_mac = self._mac("prefix", window)
            blocks.grew(consumed, read_to)
            self._stepped = True
            self.save()
        if not entry.seen.message and not entry.text and self._format(
            path, entry.seen | signs(json_lines(bytes(pending)))
        ) is not entry.format:
            # The bytes after the last line end change the format: read whole.
            return self._whole(path, st, entry, handle)
        if pending and entry.format is Format.CLAUDE_CODE and (
            time.time() - st.st_mtime_ns / 1e9 < FRESH_TAIL_S
        ):
            # A record Claude Code is still writing: counted once it is
            # whole, or once it has stopped changing (_tail_ripe).
            entry.fresh_tail = True
            entry.tail = Tally()
        else:
            entry.tail = self._audit(path, bytes(pending), entry.format) if pending else Tally()
        if entry.format is Format.UNKNOWN:
            # A file in no format the audit reads is unknown however little
            # it holds: an empty transcript is not a clean one.
            entry.tail.unknown = True
        self.save()
        return entry, size, size

    def _whole(
        self, path: str, st: os.stat_result, entry: _Entry, handle: BinaryIO
    ) -> tuple[_Entry, int, int]:
        """Read the file whole and audit it as `weir audit` would: one step,
        all or nothing. A file too large for one step is read in steps as
        unknown text instead: what it holds is not counted, and it makes the
        session unknown, never clean."""
        if st.st_size > WHOLE_MAX_BYTES:
            entry.format = Format.UNKNOWN
            entry.text = True
            self._restart(entry)
            return self._steps(path, st, entry, handle, b"", b"")
        handle.seek(0)
        data = handle.read()
        lines = json_lines(data)
        entry.format = recognise(path, data, lines, self._projects)
        entry.seen = signs(lines)
        entry.whole = True
        entry.lines = self._audit(path, data, entry.format)
        entry.offset = len(data)
        entry.tail = Tally()
        self._stamp(entry, st)
        self._stepped = True
        self.save()
        return entry, len(data), len(data)

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
    context, sent = counted(found, inputs)
    if done < total:
        return segment_text(context, sent, unknown=found.unknown, scanning=done * 100 // total)
    return segment_text(context, sent, unknown=found.unknown)
