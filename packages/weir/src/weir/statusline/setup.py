"""`weir statusline setup` and `undo` (docs/statusline.md, "Setup and undo").

Setup adds the weir segment to Claude Code's user settings, beside the
status line command already there (that command keeps running, and its
output is printed first), and installs the /weir command file. It shows
the exact change first and writes only after an explicit yes. Undo puts
back the bytes setup replaced, and removes what setup created, refusing
when a file changed after setup.

The undo record lives in the weir state directory and holds paths and an
HMAC-SHA256, under the inventory's fingerprint key, of the bytes setup
wrote, so undo can tell a file it may restore from one edited since, and
the record holds no unkeyed hash of a settings file that may hold a
credential. The bytes a file held before setup are kept beside it, as
`<file>.weir-backup`, readable by the owner only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from weir.audit.inputs import AuditInputError, read_key
from weir.statusline.files import write_atomic, write_private

UNDO_SCHEMA = "weir-statusline-undo/1"
UNDO_FILE = "setup-undo.json"
BACKUP_SUFFIX = ".weir-backup"


class SetupError(Exception):
    """Setup or undo cannot go ahead; nothing was written."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Paths:
    """Where setup writes, and the inputs it bakes into the commands."""

    claude_dir: Path
    report: Path
    store: Path
    key: Path
    cache: Path

    @property
    def settings(self) -> Path:
        return self.claude_dir / "settings.json"

    @property
    def command_file(self) -> Path:
        return self.claude_dir / "commands" / "weir.md"

    @property
    def undo_record(self) -> Path:
        return self.cache / UNDO_FILE


def weir_command() -> str:
    """How the settings start weir: this interpreter, `-m weir`, so the
    command works whatever PATH Claude Code runs it with."""
    return f"{shlex.quote(sys.executable)} -m weir"


def _inputs(paths: Paths) -> str:
    return " ".join(
        f"{flag} {shlex.quote(str(path.absolute()))}"
        for flag, path in (
            ("--inventory", paths.report), ("--store", paths.store), ("--key", paths.key),
        )
    )


def segment_command(paths: Paths, inner: str | None) -> str:
    command = (
        f"{weir_command()} statusline {_inputs(paths)}"
        f" --cache {shlex.quote(str(paths.cache.absolute()))}"
    )
    return command if inner is None else f"{command} --inner {shlex.quote(inner)}"


def report_command(paths: Paths) -> str:
    return (
        f"{weir_command()} statusline report {_inputs(paths)}"
        f" --claude-dir {shlex.quote(str(paths.claude_dir.absolute()))}"
    )


def command_file_text(paths: Paths) -> str:
    """The /weir command (docs/statusline.md, "The /weir report"). Claude
    Code puts the session id in for `${CLAUDE_SESSION_ID}` and runs the
    `!` line before the model sees the prompt."""
    report = report_command(paths)
    return (
        "---\n"
        "description: Weir session report - which of your credentials reached this session,"
        " with counts and places, never a value\n"
        f"allowed-tools: Bash({report} *)\n"
        "disable-model-invocation: true\n"
        "---\n"
        f"!`{report} --session ${{CLAUDE_SESSION_ID}}`\n"
        "\n"
        "The Weir report above lists which of the user's credentials entered this session's\n"
        "context or were sent out in a tool call, with counts and places, never a value.\n"
        "Show it to the user exactly as printed, in a code block, and stop. Do not run other\n"
        "commands and do not open the files it names.\n"
    )


# --- the change ------------------------------------------------------------------


@dataclass(frozen=True)
class Change:
    """One file setup writes: its bytes before (None: absent) and after."""

    path: Path
    before: bytes | None
    after: bytes


@dataclass(frozen=True)
class Plan:
    changes: list[Change]
    line_before: object
    line_after: dict[str, object]
    created_dirs: list[Path]


def _real(path: Path) -> Path:
    """A settings file that is a symbolic link (a dotfiles checkout, say)
    is changed where it points, so the link stays a link."""
    return Path(os.path.realpath(path)) if path.is_symlink() else path


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SetupError(f"{path}: cannot be read ({exc.strerror})", 2) from None


def check_shell() -> None:
    """Setup supports POSIX shells only for now: the segment runs the
    existing status line command through the system shell, and on Windows
    that is not the shell the command was written for. Checked before
    anything is read."""
    if os.name != "posix":
        raise SetupError(
            "weir statusline setup supports POSIX shells (Linux, macOS) only for now:"
            " on Windows it would run your status line command in a shell it was not"
            " written for; nothing changed", 2,
        )


def plan_setup(paths: Paths) -> Plan:
    if paths.undo_record.exists():
        raise SetupError(
            f"already set up (undo record {paths.undo_record}); run weir statusline undo first"
        )
    settings_path = _real(paths.settings)
    before = _read(settings_path)
    try:
        settings: object = json.loads(before) if before is not None and before.strip() else {}
    except (ValueError, UnicodeDecodeError):
        raise SetupError(f"{settings_path}: not JSON; nothing changed", 2) from None
    if not isinstance(settings, dict):
        raise SetupError(f"{settings_path}: not a JSON object; nothing changed", 2)
    current: dict[str, object] = settings  # type: ignore[assignment]
    old = current.get("statusLine")
    if old is not None and not isinstance(old, dict):
        raise SetupError(f"{settings_path}: statusLine is not an object; nothing changed", 2)
    old_line: dict[str, object] = old or {}  # type: ignore[assignment]
    inner = old_line.get("command")
    if inner is not None and not isinstance(inner, str):
        raise SetupError(f"{settings_path}: statusLine.command is not a string", 2)
    if inner and "weir statusline " in inner:
        raise SetupError(f"{settings_path}: the status line already runs weir")
    line = {**old_line, "type": "command", "command": segment_command(paths, inner or None)}
    after = json.dumps({**current, "statusLine": line}, indent=2, ensure_ascii=False) + "\n"
    changes = [Change(settings_path, before, after.encode())]

    text = command_file_text(paths).encode()
    existing = _read(paths.command_file)
    if existing is not None and existing != text:
        raise SetupError(f"{paths.command_file} exists; setup does not overwrite it")
    if existing is None:
        changes.append(Change(paths.command_file, None, text))
    created: list[Path] = []
    for change in changes:
        parent = change.path.parent
        while not parent.exists() and parent not in created:
            created.append(parent)
            parent = parent.parent
    return Plan(changes, None if old is None else old_line, line, created)


def describe_setup(plan: Plan, shown: Callable[[str], str]) -> list[str]:
    """The dry run: the exact change. `shown` withholds a string that holds
    an inventoried credential (an existing command with a token in it)."""
    settings = plan.changes[0]
    lines = [
        f"settings: {settings.path}" + (" (new file)" if settings.before is None else ""),
        "  statusLine before: " + (
            "none" if plan.line_before is None else shown(json.dumps(plan.line_before))
        ),
        "  statusLine after:  " + shown(json.dumps(plan.line_after)),
        "  every other setting is kept as it is; the file is written as indented JSON",
    ]
    if settings.before is not None:
        lines.append(f"  its bytes now are kept in {settings.path}{BACKUP_SUFFIX} for undo")
    for change in plan.changes[1:]:
        text = change.after.decode()
        lines.append(f"command file: {change.path} (new, {plural_lines(text)}), for /weir:")
        lines.extend("  | " + line for line in text.splitlines())
    if len(plan.changes) == 1:
        lines.append("command file: already installed")
    return lines


def plural_lines(text: str) -> str:
    count = len(text.splitlines())
    return f"{count} line" if count == 1 else f"{count} lines"


def _digest(key: bytes, data: bytes) -> str:
    message = b"weir-statusline undo\0" + data
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _missing_dirs(path: Path) -> list[Path]:
    """`path` and its parents that do not exist yet, deepest first."""
    out: list[Path] = []
    while not path.exists() and path != path.parent:
        out.append(path)
        path = path.parent
    return out


# The segment's checkpoint files, and the temporary files a killed run can
# leave beside them (weir.statusline.segment, weir.statusline.files).
_CHECKPOINT = re.compile(r"\.?[0-9a-f]{32}\.json(\..+)?")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def apply_setup(paths: Paths, plan: Plan, key: bytes) -> None:
    """Write the undo record first, then the backups, then the files.
    Refuses, writing nothing, when a file changed since the plan was shown
    (Claude Code saving a setting while the prompt waited, say)."""
    for change in plan.changes:
        if _read(change.path) != change.before:
            raise SetupError(f"{change.path} changed since the change was shown; nothing written")
    record = {
        "schema": UNDO_SCHEMA,
        "key": str(paths.key.absolute()),
        "files": [
            {
                "path": str(change.path.absolute()),
                "backup": None if change.before is None
                else str(change.path.absolute()) + BACKUP_SUFFIX,
                "written_mac": _digest(key, change.after),
                # The statusLine setup wrote, so undo can take back just that
                # key from a settings file changed since (keyed: the line
                # holds the old command, which may hold a credential).
                "line_mac": _digest(key, _canonical(plan.line_after)) if n == 0 else None,
            }
            for n, change in enumerate(plan.changes)
        ],
        "created_dirs": [str(d.absolute()) for d in plan.created_dirs],
        # The segment's checkpoints live here; undo removes them, and these
        # directories when setup created them and they are left empty.
        "cache": str(paths.cache.absolute()),
        "state_dirs": [str(d) for d in _missing_dirs(paths.cache.absolute())],
    }
    write_private(paths.undo_record, json.dumps(record, indent=2).encode() + b"\n")
    for d in sorted(plan.created_dirs, key=lambda d: len(d.parts)):
        d.mkdir(mode=0o700, exist_ok=True)
    for change in plan.changes:
        mode = 0o600
        if change.before is not None:
            mode = stat.S_IMODE(change.path.stat().st_mode)
            write_atomic(Path(str(change.path) + BACKUP_SUFFIX), change.before, 0o600)
        write_atomic(change.path, change.after, mode)


# --- undo -------------------------------------------------------------------------


@dataclass(frozen=True)
class Restore:
    path: Path
    # None: setup created the file; undo removes it
    backup: Path | None
    original: bytes | None
    # The file's bytes when undo planned, keyed: undo writes only over them
    planned_mac: str
    # The settings changed after setup but statusLine is still setup's: the
    # file with only statusLine taken back, every other change kept
    rewrite: bytes | None = None


@dataclass(frozen=True)
class UndoPlan:
    record: Path
    key: bytes
    restores: list[Restore]
    created_dirs: list[Path]
    cache: Path
    state_dirs: list[Path]


def _changed_after_setup(key: bytes, path: Path, written_mac: str) -> bool:
    current = _read(path)
    return current is None or not hmac.compare_digest(_digest(key, current), written_mac)


def _take_back_line(
    key: bytes, current: bytes | None, line_mac: str | None, original: bytes | None
) -> bytes | None:
    """The settings with only statusLine taken back to what it was before
    setup (removed, when there was none), when the file changed after setup
    but its statusLine is still exactly the one setup wrote. None otherwise.
    Empty bytes: nothing but setup's statusLine is left, in a file setup
    created, so the file goes."""
    if current is None or line_mac is None:
        return None
    try:
        settings: object = json.loads(current)
        before: object = (
            json.loads(original) if original is not None and original.strip() else {}
        )
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(settings, dict) or not isinstance(before, dict):
        return None
    now: dict[str, object] = settings  # type: ignore[assignment]
    if "statusLine" not in now or not hmac.compare_digest(
        _digest(key, _canonical(now["statusLine"])), line_mac
    ):
        return None
    old: object = before.get("statusLine")  # type: ignore[union-attr]
    if old is None:
        del now["statusLine"]
    else:
        now["statusLine"] = old
    if not now and original is None:
        return b""
    return json.dumps(now, indent=2, ensure_ascii=False).encode() + b"\n"


def _changed_error(path: Path, record_path: Path) -> SetupError:
    return SetupError(
        f"{path} changed after setup; nothing restored. Remove the weir part"
        " of it by hand, then delete " + str(record_path)
    )


def plan_undo(cache: Path) -> UndoPlan | None:
    record_path = cache / UNDO_FILE
    raw = _read(record_path)
    if raw is None:
        return None
    try:
        record = json.loads(raw)
        if record.get("schema") != UNDO_SCHEMA:
            raise ValueError(record_path)
        key_path = Path(record["key"])
        files = [
            (Path(e["path"]), e["backup"], str(e["written_mac"]), e.get("line_mac"))
            for e in record["files"]
        ]
        dirs = [Path(d) for d in record["created_dirs"]]
        cache_dir = Path(record.get("cache") or record_path.parent)
        state_dirs = [Path(d) for d in record.get("state_dirs", [])]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SetupError(f"{record_path}: not an undo record weir wrote", 2) from None
    try:
        key = read_key(key_path)
    except AuditInputError as exc:
        raise SetupError(f"{exc}; the undo record needs the key setup used", 2) from None
    restores: list[Restore] = []
    for path, backup_name, written_mac, line_mac in files:
        backup = None if backup_name is None else Path(backup_name)
        original = None if backup is None else _read(backup)
        if backup is not None and original is None:
            raise SetupError(f"{backup}: the backup setup kept is gone; nothing restored")
        if not _changed_after_setup(key, path, written_mac):
            restores.append(Restore(path, backup, original, written_mac))
            continue
        current = _read(path)
        rewrite = _take_back_line(key, current, line_mac, original)
        if rewrite is None or current is None:
            raise _changed_error(path, record_path)
        restores.append(Restore(path, backup, original, _digest(key, current), rewrite))
    return UndoPlan(record_path, key, restores, dirs, cache_dir, state_dirs)


def describe_undo(plan: UndoPlan) -> list[str]:
    lines: list[str] = []
    for r in plan.restores:
        if r.rewrite is not None:
            lines.append(
                f"{r.path} changed after setup, so its bytes are not restored whole: put back"
                " only its statusLine as it was before setup"
                + (" (there was none: remove it)" if r.original is None else ", from the backup")
                + ", and keep every other setting as it is now"
                + ("; nothing else is left, so remove the file" if r.rewrite == b"" else "")
            )
        elif r.backup is None:
            lines.append(f"remove {r.path} (setup created it)")
        else:
            lines.append(f"restore {r.path} to its bytes before setup, from {r.backup}")
    for d in plan.created_dirs:
        lines.append(f"remove the directory {d} if it is empty (setup created it)")
    lines.append(f"remove the status line's checkpoints in {plan.cache}")
    for d in plan.state_dirs:
        lines.append(f"remove the directory {d} if it is empty (setup created it)")
    return lines


def apply_undo(plan: UndoPlan) -> None:
    """Refuses, writing nothing, when a file changed since the plan was
    shown."""
    for r in plan.restores:
        if _changed_after_setup(plan.key, r.path, r.planned_mac):
            raise _changed_error(r.path, plan.record)
    for r in plan.restores:
        if r.rewrite:
            write_atomic(r.path, r.rewrite, stat.S_IMODE(r.path.stat().st_mode))
            if r.backup is not None:
                r.backup.unlink()
        elif r.original is None:
            r.path.unlink()
        else:
            mode = stat.S_IMODE(r.path.stat().st_mode)
            write_atomic(r.path, r.original, mode)
            assert r.backup is not None
            r.backup.unlink()
    for d in sorted(plan.created_dirs, key=lambda d: -len(d.parts)):
        try:
            d.rmdir()
        except OSError:
            pass  # not empty: something else lives there now
    plan.record.unlink()
    try:
        checkpoints = [p for p in plan.cache.iterdir() if _CHECKPOINT.fullmatch(p.name)]
    except OSError:
        checkpoints = []
    for p in checkpoints:
        p.unlink(missing_ok=True)
    for d in sorted(plan.state_dirs, key=lambda d: -len(d.parts)):
        try:
            d.rmdir()
        except OSError:
            pass  # not empty: something else lives there now


def confirmed(read_line: Callable[[], str]) -> bool:
    """An explicit yes: the line `yes`, lower-case, with nothing before or
    after it but the line end. Anything else (`y`, ` yes`, `yes `, an empty
    line, no input at all) is no."""
    return read_line().rstrip("\r\n") == "yes"

