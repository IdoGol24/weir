"""`weir statusline setup` and `undo` (docs/statusline.md, "Setup and undo").

Setup writes the backup (or, with no settings file, a marker that it
creates one), the command file, then `statusLine`; undo writes
`statusLine` back, removes the command file, then the backup or marker.
So an interrupted run leaves both usable.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from weir.statusline.files import write_atomic


class SetupError(Exception):
    """Setup or undo cannot go ahead; nothing was written."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def _q(path: Path) -> str:
    return shlex.quote(str(path.absolute()))


@dataclass(frozen=True)
class Paths:
    claude_dir: Path
    cache: Path
    report: Path = Path()
    store: Path = Path()
    key: Path = Path()

    @property
    def settings(self) -> Path:
        """Where a symbolic link points, so the link stays a link."""
        path = self.claude_dir / "settings.json"
        return Path(os.path.realpath(path)) if path.is_symlink() else path

    @property
    def backup(self) -> Path:
        """The settings file's bytes from before setup."""
        return Path(str(self.settings) + ".weir-backup")

    @property
    def created(self) -> Path:
        """Empty: there was no settings file before setup."""
        return Path(str(self.settings) + ".weir-created")

    def marker(self) -> Path | None:
        """The backup or the marker setup left, if any."""
        return next((p for p in (self.backup, self.created) if p.exists()), None)

    @property
    def command_file(self) -> Path:
        return self.claude_dir / "commands" / "weir.md"

    def command(self, *args: str) -> str:
        """`weir statusline ARGS` with the inventory files, run by this
        interpreter: it works whatever PATH Claude Code has."""
        inputs = f"--inventory {_q(self.report)} --store {_q(self.store)} --key {_q(self.key)}"
        return " ".join((shlex.quote(sys.executable), "-m weir statusline", *args, inputs))

    def segment(self, inner: str | None) -> str:
        command = self.command("--cache", _q(self.cache))
        return command if inner is None else f"{command} --inner {shlex.quote(inner)}"

    def command_file_text(self) -> str:
        """Claude Code runs the `!` line, with the session id put in, before
        the model sees the prompt."""
        report = self.command("report", "--claude-dir", _q(self.claude_dir))
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


def undo_command(claude_dir: Path | None) -> str:
    """The undo of a setup given this option, as it runs from any directory."""
    given = "" if claude_dir is None else f" --claude-dir {_q(claude_dir)}"
    return "weir statusline undo" + given


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SetupError(f"{path}: cannot be read ({exc.strerror})", 2) from None


def _settings(path: Path, data: bytes | None) -> dict[str, object]:
    try:
        settings: object = json.loads(data) if data and data.strip() else {}
    except (ValueError, UnicodeDecodeError):
        raise SetupError(f"{path}: not JSON; nothing changed", 2) from None
    if not isinstance(settings, dict):
        raise SetupError(f"{path}: not a JSON object; nothing changed", 2)
    return settings  # type: ignore[return-value]


def _json(settings: dict[str, object]) -> bytes:
    return (json.dumps(settings, indent=2, ensure_ascii=False) + "\n").encode()


def _command(line: object) -> object:
    return cast("dict[str, object]", line).get("command") if isinstance(line, dict) else None


def _runs_weir(line: object) -> bool:
    """A status line that runs the weir segment, whatever its options."""
    command = _command(line)
    return isinstance(command, str) and " -m weir statusline " in command


def _setups(line: object, inner: object) -> bool:
    """The status line setup writes: an interpreter running `-m weir
    statusline` with the four options it gives, any values, and `--inner`
    exactly `inner`, the command from before setup, when there was one."""
    command = _command(line)
    try:
        words = shlex.split(command) if isinstance(command, str) else []
    except ValueError:
        return False
    if len(words) % 2 or words[1:4] != ["-m", "weir", "statusline"]:
        return False
    options = dict(zip(words[4::2], words[5::2], strict=True))
    names = {"--cache", "--inventory", "--store", "--key", *(["--inner"] if inner else [])}
    return len(options) == len(words[4:]) // 2 and set(options) == names and (
        not inner or options["--inner"] == inner
    )


@dataclass(frozen=True)
class Plan:
    before: bytes | None  # None: there is no settings file
    after: bytes | None  # None: leave the settings as they are
    remove: bool = False  # undo: remove the settings file, there was none before setup
    beside: bool = False  # an existing status line command runs beside the segment
    command_text: str | None = None


def plan_setup(paths: Paths) -> Plan:
    if os.name != "posix":
        raise SetupError(
            "weir statusline setup supports POSIX shells (Linux, macOS) only for now: on"
            " Windows it would run your status line command in a shell it was not written"
            " for; nothing changed", 2,
        )
    marker = paths.marker()
    if marker is not None:
        raise SetupError(f"already set up ({marker} exists); run weir statusline undo first")
    before = _read(paths.settings)
    settings = _settings(paths.settings, before)
    old = settings.get("statusLine")
    if old is not None and not isinstance(old, dict):
        raise SetupError(f"{paths.settings}: statusLine is not an object; nothing changed", 2)
    old_line = cast("dict[str, object]", old or {})
    if _runs_weir(old_line):
        raise SetupError(f"{paths.settings}: the status line already runs weir")
    inner = old_line.get("command")
    if inner is not None and not isinstance(inner, str):
        raise SetupError(f"{paths.settings}: statusLine.command is not a string", 2)
    text = paths.command_file_text()
    existing = _read(paths.command_file)
    if existing is not None and existing != text.encode():
        raise SetupError(f"{paths.command_file} exists; setup does not overwrite it")
    line = {**old_line, "type": "command", "command": paths.segment(inner or None)}
    after = _json({**settings, "statusLine": line})
    return Plan(before, after, beside=bool(inner), command_text=None if existing else text)


def plan_undo(paths: Paths) -> Plan | None:
    marker = paths.marker()
    if marker is None:
        return None
    backup = _read(paths.backup) if marker == paths.backup else None
    current = _read(paths.settings)
    now, was = _settings(paths.settings, current), _settings(paths.backup, backup)
    line, old = now.get("statusLine"), was.get("statusLine")
    if line == old and (current is not None or backup is None):
        return Plan(current, None)  # setup never got to the settings, or undo already ran
    if not _setups(line, _command(old)):
        message = (
            f" {paths.backup} holds the settings from before setup, with any status line"
            " command you had: put back the status line you want by hand, then delete"
            if backup is not None else " There was no settings file before setup. Delete"
        )
        raise SetupError(
            f"{paths.settings}: its status line is no longer the one setup wrote (changed or"
            f" removed since); nothing changed.{message} {marker} and {paths.command_file}"
        )
    if current == _json({**was, "statusLine": line}):
        # Nothing else changed: the bytes before setup.
        return Plan(current, backup, remove=backup is None)
    if "statusLine" in was:
        return Plan(current, _json({**now, "statusLine": old}))
    return Plan(current, _json({k: v for k, v in now.items() if k != "statusLine"}))


def describe(paths: Paths, plan: Plan, *, undo: bool) -> list[str]:
    """Never the existing status line command: it may hold a credential."""
    new = not undo and plan.before is None
    lines = [f"settings: {paths.settings}" + (" (new file)" if new else "")]
    if plan.remove:
        lines.append("  there was none before setup and nothing else changed: remove it")
    elif plan.after is None:
        lines.append("  unchanged: its status line is already the one before setup")
    elif undo:
        lines.append("  put back the status line it had before setup, every other setting kept")
    else:
        lines.append(f"  statusLine runs the weir segment: {paths.segment(None)}")
        if plan.beside:
            lines.append("  your existing status line command is kept and runs beside it,"
                         " as --inner (not shown here)")
        lines.append("  there is no settings file yet; setup creates it" if new else
                     f"  every other setting is kept; its bytes now are kept in {paths.backup}")
    if undo:
        lines.append(f"remove {paths.command_file} and {paths.marker()}")
    elif plan.command_text is not None:
        lines.append(f"command file: {paths.command_file} (new), for /weir:")
        lines.extend("  | " + line for line in plan.command_text.splitlines())
    return lines


def apply(paths: Paths, plan: Plan, *, undo: bool) -> None:
    if _read(paths.settings) != plan.before:
        then = "nothing restored. Run weir statusline undo again" if undo else "nothing written"
        raise SetupError(f"{paths.settings} changed since the change was shown; {then}")
    if not undo:
        paths.backup.parent.mkdir(parents=True, exist_ok=True)
        if plan.before is None:
            write_atomic(paths.created, b"", 0o600)
        else:
            write_atomic(paths.backup, plan.before, 0o600)
        if plan.command_text is not None:
            paths.command_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_atomic(paths.command_file, plan.command_text.encode(), 0o600)
    if plan.remove:
        paths.settings.unlink()  # undo: there was none before setup
    elif plan.after is not None:
        mode = 0o600 if plan.before is None else stat.S_IMODE(paths.settings.stat().st_mode)
        write_atomic(paths.settings, plan.after, mode)
    if undo:
        text = _read(paths.command_file)
        if text is not None and b" -m weir statusline report " in text:
            paths.command_file.unlink()
            with contextlib.suppress(OSError):  # not empty: something else lives there
                paths.command_file.parent.rmdir()
        marker = paths.marker()
        if marker is not None:
            marker.unlink()


def confirmed(answer: str) -> bool:
    """The line `yes`, with nothing around it but the line end."""
    return answer.rstrip("\r\n") == "yes"
