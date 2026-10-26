"""The redaction hook (docs/statusline.md, "The redaction hook").

A Claude Code `PostToolUse` command hook for the tools in COVERED. It
replaces each inventoried value in the tool's result with
`[weir: NAME removed]` before the model sees it, finding values by keyed
fingerprint (`Matcher.spans`), so it holds no plaintext key. It keeps the
result's shape: every key in its order, every type, list length and
non-string leaf. Claude Code sends the original output when a built-in
tool's replacement does not match its schema, and whenever the hook fails,
so every call leaves a marker the status line and /weir read: `pending`
first, then `done` with the count of each name kept out, once its output
is written, or `failed`. A marker holds no value, fragment or decoded form.

For a large output Claude Code also saves the whole output in the
session's `tool-results` folder and names that file in the result's
`persistedOutputPath`. The hook rewrites it with the same replacements,
owner-only, before the call is done; a saved file it cannot rewrite, one
over SAVED_MAX_BYTES or one not searched SAVED_DEADLINE_S after the hook
began, leaves the call `failed`, while the result itself is still replaced.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

import msgspec

from weir.audit import AuditInputError, Inputs, load_inputs
from weir.audit.matching import Matcher
from weir.canary.walk import Json
from weir.statusline import valid_session_id
from weir.statusline.files import write_atomic, write_private

COVERED = ("Read", "Bash", "Grep", "Glob", "WebFetch")
TIMEOUT_S = 10
# A saved output larger than this is not rewritten: searching it could pass TIMEOUT_S.
SAVED_MAX_BYTES = 256 * 1024
# Searching a saved output stops this long after the hook began, so
# searching it never holds the hook past TIMEOUT_S, whatever the file holds:
# some content takes far longer to search than its size suggests.
SAVED_DEADLINE_S = 6.0
MARKER_SCHEMA = "weir-redaction-marker/1"
OLD_SCHEMA = "weir-redaction-old/1"
# A marker this old is folded into its session's `.old.json`, at most once a day.
MAX_AGE_S = 7 * 24 * 3600
_FOLD_EVERY_S = 24 * 3600
_OLD = ".old.json"  # a leading dot: never a tool use id
_FOLDED = ".compacted"  # in the markers folder: when markers were last folded


class Marker(msgspec.Struct, frozen=True):
    schema: str
    state: str  # "pending", "done" or "failed"
    at: float  # when the call began, in seconds since the epoch
    kept_out: dict[str, int] = msgspec.field(default_factory=dict[str, int])


class HookError(Exception):
    """What failed in a call, in fixed words. Raised out of `run` or
    `finish`, the call was not redacted: its output reached the model as it
    was. From the saved output it only flags the call (`Redacted.problem`)."""


class _Abandoned(HookError):
    """A search thread past its deadline, still running: the hook ends its
    own process once the result is out."""


class Redacted(NamedTuple):
    """A call redacted, its marker still `pending`: `output`, the hook's
    stdout ("" when nothing matched), and the `final` marker to write at
    `path` once that output is written: `done`, or `failed` with the
    `problem`, in fixed words, when the saved output could not be rewritten."""

    output: str
    path: Path
    final: Marker
    problem: str | None = None
    abandoned: bool = False  # a search thread still runs: end the process when done


def marker_path(markers: Path, session_id: object, tool_use_id: object) -> Path | None:
    """`markers/<session id>/<tool use id>.json`; None for an id that is not
    one plain name."""
    if not (isinstance(session_id, str) and valid_session_id(session_id)):
        return None
    if not (isinstance(tool_use_id, str) and valid_session_id(tool_use_id)):
        return None
    return markers / session_id / f"{tool_use_id}.json"


def _replaced(text: str, spans: list[tuple[int, int, bytes]], names: dict[bytes, str],
              kept: dict[str, int]) -> str:
    """Overlapping spans are one replacement, naming each value in it."""
    merged: list[tuple[int, int, list[str]]] = []
    for start, end, fp in spans:
        if merged and start < merged[-1][1]:
            first, last, labels = merged[-1]
            if names[fp] not in labels:
                labels.append(names[fp])
            merged[-1] = (first, max(last, end), labels)
        else:
            merged.append((start, end, [names[fp]]))
    out: list[str] = []
    at = 0
    for start, end, labels in merged:
        out += (text[at:start], *(f"[weir: {name} removed]" for name in labels))
        for name in labels:
            kept[name] = kept.get(name, 0) + 1
        at = end
    return "".join(out) + text[at:]


def _matching(inputs: Inputs) -> tuple[Matcher, dict[bytes, str]]:
    """The matcher, and the name each fingerprint is replaced by: the first
    in the inventory for a value with records of several names."""
    name = {c.id: c.name for c in inputs.credentials}
    names = {fp: name[ids[0]] for fp, ids in inputs.by_fingerprint.items()}
    return Matcher(inputs.key, set(inputs.by_fingerprint)), names


def redact(
    matcher: Matcher, names: dict[bytes, str], response: Json
) -> tuple[Json, dict[str, int]]:
    """`response` with each stored value in its strings replaced, and how
    many times each name was. Values with records of several names are
    named by the first in the inventory. The binary payloads a Read returns
    are left as they are: an image's or a PDF's `file.base64`, and a
    notebook output's `image.image_data` (Claude Code's Read output
    schema). They are megabytes long and slow to search. Image data holds
    no value as text, and the audit leaves it aside too; a PDF's data can
    hold text, which the hook does not search."""
    kept: dict[str, int] = {}
    binary = response.get("file") if isinstance(response, dict) and response.get(
        "type") in ("image", "pdf") else None

    def payload(node: dict[str, Json], key: str) -> bool:
        return (node is binary and key == "base64") or (
            key == "image_data" and "media_type" in node
        )

    def walk(node: Json) -> Json:
        if isinstance(node, str):
            spans = matcher.spans(node)
            return _replaced(node, spans, names, kept) if spans else node
        if isinstance(node, dict):
            return {k: v if payload(node, k) else walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(response), kept


def _saved_output(payload: dict[str, Json], response: Json) -> Path | None:
    """The file Claude Code saved the whole output to, as the result's
    `persistedOutputPath` names it; None when it names none. HookError
    unless that is a regular file, no symbolic link, directly in
    `<transcript directory>/<session id>/tool-results/`, neither folder a
    symbolic link: the hook writes nowhere else."""
    named = response.get("persistedOutputPath") if isinstance(response, dict) else None
    if named is None:
        return None
    transcript, session = payload.get("transcript_path"), payload.get("session_id")
    if not (isinstance(named, str) and isinstance(transcript, str) and isinstance(session, str)
            and os.path.isabs(named) and os.path.isabs(transcript)):
        raise HookError("its saved output is not named by an absolute path")
    folder = os.path.join(os.path.dirname(transcript), session, "tool-results")
    path = os.path.normpath(named)
    if path != named or os.path.dirname(path) != os.path.normpath(folder):
        raise HookError("its saved output is not in the session's tool-results folder")
    if any(os.path.islink(d) or not os.path.isdir(d) for d in (os.path.dirname(folder), folder)):
        raise HookError("its saved output's folder is not the session's own")
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        raise HookError("its saved output is not there") from None
    if not stat.S_ISREG(mode):
        raise HookError("its saved output is not a regular file")
    return Path(path)


_LATE = "its saved output could not be searched within the hook's timeout"
_Spans = list[tuple[int, int, bytes]]


def _spans_by(matcher: Matcher, text: str, deadline: float) -> _Spans:
    """`matcher.spans(text)`, or HookError at `deadline` (time.monotonic()).
    On POSIX the search runs in a child process, killed at the deadline:
    the hook then ends at once, which a thread still searching would hold
    up. Elsewhere it runs in a daemon thread, left searching past the
    deadline (`_Abandoned`): the hook then ends its own process once the
    result is out. Neither writes anything."""
    if sys.platform == "win32":
        return _spans_in_thread(matcher, text, deadline)
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:  # the child: search, hand the spans back, end
        try:
            os.close(reader)
            with os.fdopen(writer, "wb") as out:
                out.write(msgspec.msgpack.encode(matcher.spans(text)))
        finally:
            os._exit(0)
    os.close(writer)
    data = b""
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([reader], [], [], left)[0]:
                raise HookError(_LATE)
            chunk = os.read(reader, 1 << 16)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(reader)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    if not data:
        raise HookError("its saved output could not be searched")
    return msgspec.msgpack.decode(data, type=_Spans)


def _spans_in_thread(matcher: Matcher, text: str, deadline: float) -> _Spans:
    found: list[_Spans | BaseException] = []

    def search() -> None:
        try:
            found.append(matcher.spans(text))
        except BaseException as exc:  # handed to the caller
            found.append(exc)

    worker = threading.Thread(target=search, daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if not found:
        raise _Abandoned(_LATE)
    if isinstance(found[0], BaseException):
        raise found[0]
    return found[0]


def _rewrite(
    path: Path, matcher: Matcher, names: dict[bytes, str], deadline: float
) -> dict[str, int]:
    """`path` rewritten with each value replaced, owner-only, through a
    temporary file beside it; how many times each name was. A file with
    no value is left as it is. HookError, and the file left as it is, for
    one that is not a regular file once open (opened without blocking: a
    FIFO never waits for a writer), one over SAVED_MAX_BYTES, before it is
    read, and one not searched by `deadline`."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise HookError("its saved output is not a regular file")
        if info.st_size > SAVED_MAX_BYTES:
            raise HookError("its saved output is too large to rewrite within the hook's timeout")
        text = handle.read().decode("utf-8", "surrogateescape")
    kept: dict[str, int] = {}
    spans = _spans_by(matcher, text, deadline)
    if spans:
        replaced = _replaced(text, spans, names, kept)
        write_atomic(path, replaced.encode("utf-8", "surrogateescape"), 0o600)
    return kept


def run(stdin: bytes, report: Path, store: Path, key: Path, markers: Path) -> Redacted:
    """One PostToolUse input redacted, its marker left `pending` until
    `finish`. Raises HookError, naming what failed in fixed words, after
    marking the call failed when it can."""
    try:
        payload = json.loads(stdin)
        path = marker_path(markers, payload.get("session_id"), payload.get("tool_use_id"))
    except (ValueError, AttributeError):
        raise HookError("its input is not JSON") from None
    if path is None:
        raise HookError("its input names no session and tool call")
    began, started = time.time(), time.monotonic()
    try:
        write_private(path, msgspec.json.encode(Marker(MARKER_SCHEMA, "pending", began)))
    except OSError:
        raise HookError(f"its marker cannot be written in {markers}") from None
    try:
        if "tool_response" not in payload:
            raise HookError("its input holds no tool_response")
        matcher, names = _matching(load_inputs(report, store, key))
        updated, kept = redact(matcher, names, payload["tool_response"])
        output = {"hookEventName": "PostToolUse", "updatedToolOutput": updated}
        out = json.dumps({"hookSpecificOutput": output}) if kept else ""
    except Exception as exc:
        try:
            write_private(path, msgspec.json.encode(Marker(MARKER_SCHEMA, "failed", began)))
        except OSError:
            pass  # still pending: past the timeout, that reads as failed too
        if isinstance(exc, HookError):
            raise
        what = "the inventory, store or key cannot be used" if isinstance(
            exc, AuditInputError) else f"an unexpected {type(exc).__name__}"
        raise HookError(what) from None
    try:
        saved = _saved_output(payload, payload["tool_response"])
        # The saved file holds the whole output, the result a part of it:
        # each name is counted once, as often as the larger held it.
        deadline = started + SAVED_DEADLINE_S
        for name, count in (_rewrite(saved, matcher, names, deadline) if saved else {}).items():
            kept[name] = max(kept.get(name, 0), count)
    except Exception as exc:  # the result is still replaced; the call is flagged
        problem = str(exc) if isinstance(exc, HookError) else (
            "its saved output cannot be rewritten" if isinstance(exc, OSError)
            else f"an unexpected {type(exc).__name__} in its saved output")
        return Redacted(out, path, Marker(MARKER_SCHEMA, "failed", began), problem,
                        isinstance(exc, _Abandoned))
    return Redacted(out, path, Marker(MARKER_SCHEMA, "done", began, kept))


def finish(call: Redacted) -> None:
    """After `call.output` reached Claude Code. Unwritten, the marker stays
    `pending`, which reads as failed past the timeout."""
    try:
        write_private(call.path, msgspec.json.encode(call.final))
    except OSError:
        raise HookError(f"its marker cannot be written in {call.path.parent}") from None


# --- what the status line and /weir read -------------------------------------------


def read_marker(path: Path) -> Marker | None:
    try:
        return msgspec.json.decode(path.read_bytes(), type=Marker)
    except (OSError, msgspec.DecodeError):
        return None


class Old(msgspec.Struct):
    """A session's markers older than MAX_AGE_S, folded into one file: the
    calls done, those failed (or pending past the timeout, or unreadable),
    and the names kept out with their counts. Never a value."""

    schema: str = OLD_SCHEMA
    done: list[str] = msgspec.field(default_factory=list[str])
    failed: list[str] = msgspec.field(default_factory=list[str])
    kept_out: dict[str, int] = msgspec.field(default_factory=dict[str, int])


def _read_old(session: Path) -> Old:
    try:
        return msgspec.json.decode((session / _OLD).read_bytes(), type=Old)
    except FileNotFoundError:
        return Old()
    except (OSError, msgspec.DecodeError):
        return Old(failed=["(unreadable)"])  # never a clean session


def _markers_in(session: Path) -> list[Path]:
    if not session.is_dir() or session.is_symlink():
        return []
    return sorted(p for p in session.glob("*.json") if valid_session_id(p.stem))


def fold_old_markers(root: Path, now: float) -> None:
    """Fold each session's markers older than MAX_AGE_S into its `.old.json`,
    at most once a day: the summary is written before the markers it holds
    are removed, and readers read both, so no session reads otherwise after.
    A marker younger than that, a call still running included, is left."""
    stamp = root / _FOLDED
    with contextlib.suppress(FileNotFoundError):
        if now - stamp.stat().st_mtime < _FOLD_EVERY_S:
            return
    if not root.is_dir():
        return
    write_private(stamp, b"")
    for session in root.iterdir():
        if not valid_session_id(session.name):
            continue
        old = [p for p in _markers_in(session) if now - p.stat().st_mtime > MAX_AGE_S]
        if not old:
            continue
        summary = _read_old(session)
        seen = {*summary.done, *summary.failed}
        for path in old:
            marker = read_marker(path)
            if path.stem in seen:
                continue  # folded before, its removal cut short
            if marker is not None and marker.state == "done":
                summary.done.append(path.stem)
                for name, count in marker.kept_out.items():
                    summary.kept_out[name] = summary.kept_out.get(name, 0) + count
            else:
                summary.failed.append(path.stem)
        write_private(session / _OLD, msgspec.json.encode(summary))
        for path in old:
            path.unlink(missing_ok=True)


def remove_markers(root: Path) -> None:
    """Every marker, summary and folder the hook wrote under `root`, and
    nothing else: a folder that holds anything more stays."""
    for session in list(root.iterdir()) if root.is_dir() and not root.is_symlink() else []:
        if session.is_dir() and not session.is_symlink() and valid_session_id(session.name):
            for path in [*_markers_in(session), session / _OLD]:
                path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                session.rmdir()
    (root / _FOLDED).unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        root.rmdir()


def session_marks(session: Path, now: float) -> tuple[dict[str, int], set[str]]:
    """The names a session's calls kept out, with their counts, and the
    calls whose marker says the hook failed: `failed`, unreadable, or
    `pending` past the hook's timeout, when Claude Code has killed it. The
    session's folded markers count the same."""
    old = _read_old(session)
    kept = dict(old.kept_out)
    failed = set(old.failed)
    for path in _markers_in(session):
        if path.stem in old.done or path.stem in old.failed:
            continue  # folded already
        marker = read_marker(path)
        if marker is not None and marker.state == "done":
            for name, count in marker.kept_out.items():
                kept[name] = kept.get(name, 0) + count
        elif marker is None or marker.state != "pending" or now - marker.at > TIMEOUT_S:
            failed.add(path.stem)
    return kept, failed


def unredacted_results(data: bytes, waiting: set[str], done: Callable[[str], bool]) -> set[str]:
    """The covered tool results in `data`, whole session records, whose
    call has no `done` marker. `waiting` holds the covered tool calls seen
    with no result yet, read on and updated. A failed call (`is_error`)
    never ran the hook: Claude Code runs PostToolUse after a success only."""
    out: set[str] = set()
    for line in data.split(b"\n"):
        if b'"tool_use' not in line:
            continue
        try:
            record: Json = msgspec.json.decode(line)
        except msgspec.DecodeError:
            continue
        message = record.get("message") if isinstance(record, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                continue
            kind, use, result = block.get("type"), block.get("id"), block.get("tool_use_id")
            if kind == "tool_use" and block.get("name") in COVERED and isinstance(use, str):
                waiting.add(use)
            elif kind == "tool_result" and isinstance(result, str) and result in waiting:
                waiting.discard(result)
                if block.get("is_error") is not True and not done(result):
                    out.add(result)
    return out


def done_in(session: Path) -> Callable[[str], bool]:
    folded = set(_read_old(session).done)

    def done(tool_use_id: str) -> bool:
        if tool_use_id in folded:
            return True
        path = marker_path(session.parent, session.name, tool_use_id)
        marker = None if path is None else read_marker(path)
        return marker is not None and marker.state == "done"

    return done
