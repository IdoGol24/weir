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
            }
            for change in plan.changes
        ],
        "created_dirs": [str(d.absolute()) for d in plan.created_dirs],
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
    # The bytes setup wrote, as the record keeps them: keyed
    written_mac: str


@dataclass(frozen=True)
class UndoPlan:
    record: Path
    key: bytes
    restores: list[Restore]
    created_dirs: list[Path]


def _changed_after_setup(key: bytes, path: Path, written_mac: str) -> bool:
    current = _read(path)
    return current is None or not hmac.compare_digest(_digest(key, current), written_mac)


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
        files = [(Path(e["path"]), e["backup"], str(e["written_mac"])) for e in record["files"]]
        dirs = [Path(d) for d in record["created_dirs"]]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SetupError(f"{record_path}: not an undo record weir wrote", 2) from None
    try:
        key = read_key(key_path)
    except AuditInputError as exc:
        raise SetupError(f"{exc}; the undo record needs the key setup used", 2) from None
    restores: list[Restore] = []
    for path, backup_name, written_mac in files:
        if _changed_after_setup(key, path, written_mac):
            raise _changed_error(path, record_path)
        backup = None if backup_name is None else Path(backup_name)
        original = None if backup is None else _read(backup)
        if backup is not None and original is None:
            raise SetupError(f"{backup}: the backup setup kept is gone; nothing restored")
        restores.append(Restore(path, backup, original, written_mac))
    return UndoPlan(record_path, key, restores, dirs)


def describe_undo(plan: UndoPlan) -> list[str]:
    lines: list[str] = []
    for r in plan.restores:
        if r.backup is None:
            lines.append(f"remove {r.path} (setup created it)")
        else:
            lines.append(f"restore {r.path} to its bytes before setup, from {r.backup}")
    for d in plan.created_dirs:
        lines.append(f"remove the directory {d} if it is empty (setup created it)")
    return lines


def apply_undo(plan: UndoPlan) -> None:
    """Refuses, writing nothing, when a file changed since the plan was
    shown."""
    for r in plan.restores:
        if _changed_after_setup(plan.key, r.path, r.written_mac):
            raise _changed_error(r.path, plan.record)
    for r in plan.restores:
        if r.original is None:
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


def confirmed(read_line: Callable[[], str]) -> bool:
    """An explicit yes: the answer `yes`, lower-case. Anything else, `y`,
    an empty line or no input at all, is no."""
    return read_line().strip() == "yes"

