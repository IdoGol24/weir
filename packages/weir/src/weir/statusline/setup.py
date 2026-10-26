"""`weir statusline setup` and `undo` (docs/statusline.md, "Setup and undo").

Setup writes a first inventory's files when it took one, the backup (or,
with no settings file, a marker that it creates one), the command file,
then `statusLine` and, when chosen, the redaction hook; undo writes
`statusLine` back and takes the hook out, removes the command file, then the
backup or marker. So an interrupted run leaves both usable.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shlex
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from weir.statusline import hook
from weir.statusline.files import write_atomic

# The question setup asks before it adds the redaction hook, and what it
# suggests when the hook cannot be added.
HOOK_QUESTION = "Add the redaction hook too?"
ANSWER_NO = f'answer no to "{HOOK_QUESTION}" to install the status line alone'


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

    @property
    def markers(self) -> Path:
        """The redaction hook's markers, a folder per Claude config dir, so
        undo for one never removes another's: `hook-` and the first 16 hex
        characters of the SHA-256 of its resolved path. Not keyed: setup
        with an existing inventory reads no key."""
        resolved = os.fsencode(os.path.realpath(self.claude_dir))
        return self.cache / f"hook-{hashlib.sha256(resolved).hexdigest()[:16]}"

    def command(self, *args: str) -> str:
        """`weir statusline ARGS` with the inventory files, run by this
        interpreter: it works whatever PATH Claude Code has."""
        inputs = f"--inventory {_q(self.report)} --store {_q(self.store)} --key {_q(self.key)}"
        return " ".join((shlex.quote(sys.executable), "-m weir statusline", *args, inputs))

    def _marked(self, with_hook: bool) -> tuple[str, ...]:
        return ("--markers", _q(self.markers)) if with_hook else ()

    def segment(self, inner: str | None, with_hook: bool = False) -> str:
        command = self.command("--cache", _q(self.cache), *self._marked(with_hook))
        return command if inner is None else f"{command} --inner {shlex.quote(inner)}"

    def hook_entry(self) -> dict[str, object]:
        """The `hooks.PostToolUse` entry for the redaction hook."""
        command = self.command("hook", *self._marked(True))
        return {"matcher": "|".join(hook.COVERED), "hooks": [
            {"type": "command", "command": command, "timeout": hook.TIMEOUT_S}]}

    def command_file_text(self, with_hook: bool = False) -> str:
        """Claude Code runs the `!` line, with the session id put in
        (code.claude.com/docs/en/slash-commands, "Available string
        substitutions"), before the model sees the prompt. The report reads
        the session's project folder from the record the status line keeps
        in the cache, so no folder name is ever part of the command."""
        report = self.command(
            "report", "--claude-dir", _q(self.claude_dir), "--cache", _q(self.cache),
            *self._marked(with_hook))
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


def holds_home(folder: str | Path, home: Path) -> bool:
    """Is `folder` the home or a folder that holds it, both resolved? Its
    walk as the project would read the whole home."""
    real_home, here = Path(os.path.realpath(home)), Path(os.path.realpath(folder))
    return here == real_home or here in real_home.parents


def inventory_command(
    project: str | None, report: str = "~/.weir/inventory.json",
    store: str = "~/.weir/store.json", key: str | None = None,
) -> str:
    """The `weir inventory` that takes the inventory again into these
    files, given as the shell reads them, with this project or none, run
    from the shell Claude Code starts from."""
    given = "--no-project" if project is None else f"--project {shlex.quote(project)}"
    keyed = "" if key is None else f" --key {key}"
    return f"weir inventory --home ~ {given} --process-env --json --store {store}{keyed} > {report}"


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
    statusline` with the four options it gives (and `--markers` with the
    hook), any values, and `--inner` exactly `inner`, the command from
    before setup, when there was one."""
    command = _command(line)
    try:
        words = shlex.split(command) if isinstance(command, str) else []
    except ValueError:
        return False
    if len(words) % 2 or words[1:4] != ["-m", "weir", "statusline"]:
        return False
    options = dict(zip(words[4::2], words[5::2], strict=True))
    names = {"--cache", "--inventory", "--store", "--key", *(["--inner"] if inner else [])}
    return len(options) == len(words[4:]) // 2 and set(options) - names <= {"--markers"} and (
        names <= set(options) and (not inner or options["--inner"] == inner)
    )


def _weir_hook(group: object) -> bool:
    """A `hooks.PostToolUse` entry that runs the redaction hook."""
    return " -m weir statusline hook " in json.dumps(group)


def _hooks(path: Path, settings: dict[str, object]) -> tuple[dict[str, object], list[object]]:
    hooks = settings.get("hooks", {})
    post = cast("dict[str, object]", hooks).get("PostToolUse", []) if isinstance(
        hooks, dict) else None
    if not isinstance(post, list):
        raise SetupError(f"{path}: hooks is not an object of lists; nothing changed", 2)
    return cast("dict[str, object]", hooks), cast("list[object]", post)


def _with_hook(path: Path, settings: dict[str, object], entry: object) -> dict[str, object]:
    """`settings` with `entry` last in `hooks.PostToolUse`."""
    hooks, post = _hooks(path, settings)
    if any(_weir_hook(group) for group in post):
        raise SetupError(f"{path}: hooks.PostToolUse already runs the weir redaction hook")
    return {**settings, "hooks": {**hooks, "PostToolUse": [*post, entry]}}


def _without_hook(
    path: Path, settings: dict[str, object], was: dict[str, object]
) -> dict[str, object]:
    """`settings` with the redaction hook taken out, and the `hooks` and
    `PostToolUse` setup added for it, when there were none before setup."""
    hooks, post = _hooks(path, settings)
    kept = [group for group in post if not _weir_hook(group)]
    rest = {k: v for k, v in hooks.items() if k != "PostToolUse"}
    if kept or "PostToolUse" in _hooks(path, was)[0]:
        rest = {**hooks, "PostToolUse": kept}
    if rest or "hooks" in was:
        return {**settings, "hooks": rest}
    return {k: v for k, v in settings.items() if k != "hooks"}


@dataclass(frozen=True)
class Plan:
    before: bytes | None  # None: there is no settings file
    after: bytes | None  # None: leave the settings as they are
    remove: bool = False  # undo: remove the settings file, there was none before setup
    beside: bool = False  # an existing status line command runs beside the segment
    command_text: str | None = None
    with_hook: bool = False  # setup adds the redaction hook; undo takes it out
    markers: Path | None = None  # undo: the hook's markers, removed with it


def refuse_windows() -> None:
    """Before anything else, a first inventory included."""
    if os.name != "posix":
        raise SetupError(
            "weir statusline setup supports POSIX shells (Linux, macOS) only for now: on"
            " Windows it would run your status line command in a shell it was not written"
            " for; nothing changed", 2,
        )


def plan_setup(paths: Paths, with_hook: bool = False) -> Plan:
    refuse_windows()
    for path in (Path(sys.executable), paths.claude_dir, paths.cache, paths.report, paths.store,
                 paths.key):
        if "$" in str(path.absolute()):
            raise SetupError(
                f"{path.absolute()}: the /weir command cannot hold a path with a $ in it, as"
                " Claude Code puts text in for $0 or $ARGUMENTS there, even inside quotes;"
                " nothing changed", 2,
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
    text = paths.command_file_text(with_hook)
    existing = _read(paths.command_file)
    if existing is not None and existing != text.encode():
        raise SetupError(f"{paths.command_file} exists; setup does not overwrite it")
    line = {**old_line, "type": "command", "command": paths.segment(inner or None, with_hook)}
    after = {**settings, "statusLine": line}
    if with_hook:
        after = _with_hook(paths.settings, after, paths.hook_entry())
    return Plan(
        before, _json(after), beside=bool(inner), command_text=None if existing else text,
        with_hook=with_hook,
    )


def plan_undo(paths: Paths) -> Plan | None:
    marker = paths.marker()
    if marker is None:
        return None
    backup = _read(paths.backup) if marker == paths.backup else None
    current = _read(paths.settings)
    now, was = _settings(paths.settings, current), _settings(paths.backup, backup)
    line, old = now.get("statusLine"), was.get("statusLine")
    try:  # a `hooks` value setup could not have added the hook to holds none
        entry = next((g for g in _hooks(paths.settings, now)[1] if _weir_hook(g)), None)
    except SetupError:
        entry = None
    try:  # nor do settings that ran it before setup: that one is left as it is
        if any(_weir_hook(g) for g in _hooks(paths.backup, was)[1]):
            entry = None
    except SetupError:
        pass
    if line == old and entry is None and (current is not None or backup is None):
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
    hooked = entry is not None
    handlers = cast("dict[str, list[object]]", entry or {}).get("hooks", [])
    markers = _markers_of([*handlers, line])
    written = {**was, "statusLine": line}
    if current == _json(_with_hook(paths.settings, written, entry) if hooked else written):
        # Nothing else changed: the bytes before setup.
        return Plan(current, backup, remove=backup is None, with_hook=hooked, markers=markers)
    restored = _without_hook(paths.settings, now, was) if hooked else now
    if "statusLine" not in was:
        restored = {k: v for k, v in restored.items() if k != "statusLine"}
    else:
        restored = {**restored, "statusLine": old}
    return Plan(current, _json(restored), with_hook=hooked, markers=markers)


def _markers_of(handlers: list[object]) -> Path | None:
    """The `--markers` folder the first of these commands names: the
    redaction hook's, or the status line's when the hook was taken out by
    hand."""
    for handler in handlers:
        command = _command(handler)
        try:
            words = shlex.split(command) if isinstance(command, str) else []
        except ValueError:
            continue
        if "--markers" in words[:-1]:
            return Path(words[words.index("--markers") + 1])
    return None


def describe(
    paths: Paths, plan: Plan, *, undo: bool, hook_problem: str | None = None
) -> list[str]:
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
        if plan.with_hook:
            lines.append("  this takes the weir redaction hook out of hooks.PostToolUse")
        lines.append(f"remove {paths.command_file} and {paths.marker()}")
        if plan.markers is not None:
            lines.append(f"remove the redaction hook's markers in {plan.markers}")
        return lines
    if plan.command_text is not None:
        lines.append(f"command file: {paths.command_file} (new), for /weir:")
        lines.extend("  | " + line for line in plan.command_text.splitlines())
    if hook_problem is not None:
        return [*lines, f"redaction hook: cannot be added: {hook_problem}",
                f"  {ANSWER_NO}"]
    entry = paths.hook_entry()
    tools = ", ".join(hook.COVERED[:-1]) + " and " + hook.COVERED[-1]
    hooked = paths.command_file_text(True).splitlines()
    allowed = next(line for line in hooked if line.startswith("allowed-tools:"))
    report = next(line for line in hooked if line.startswith("!"))
    return [
        *lines,
        f'redaction hook, added only when you also answer yes to "{HOOK_QUESTION}":',
        f"  hooks.PostToolUse, matcher {entry['matcher']}, timeout {hook.TIMEOUT_S} s:"
        f" {_command(cast('list[object]', entry['hooks'])[0])}",
        f"  it replaces each inventoried key in a {tools} result with [weir: NAME removed]"
        " before the model sees it",
        f"  with it, statusLine runs: {paths.segment(None, True)}"
        + (" (and your existing command as --inner, not shown)" if plan.beside else ""),
        f"  with it, {paths.command_file.name} has: {allowed}",
        f"  and runs: {report}",
    ]


def apply(
    paths: Paths, plan: Plan, *, undo: bool, first: Callable[[], None] | None = None
) -> None:
    """`first`, once the settings are known unchanged, writes what setup
    writes before the settings: a first inventory's files."""
    if _read(paths.settings) != plan.before:
        then = "nothing restored. Run weir statusline undo again" if undo else "nothing written"
        raise SetupError(f"{paths.settings} changed since the change was shown; {then}")
    if first is not None:
        first()
    target = paths.settings
    try:
        if not undo:
            target = paths.created if plan.before is None else paths.backup
            target.parent.mkdir(parents=True, exist_ok=True)
            write_atomic(target, b"" if plan.before is None else plan.before, 0o600)
            if plan.command_text is not None:
                target = paths.command_file
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                write_atomic(target, plan.command_text.encode(), 0o600)
        if undo and plan.markers is not None:
            target = plan.markers
            hook.remove_markers(plan.markers)
        target = paths.settings
        if plan.remove:
            target.unlink()  # undo: there was none before setup
        elif plan.after is not None:
            mode = 0o600 if plan.before is None else stat.S_IMODE(target.stat().st_mode)
            write_atomic(target, plan.after, mode)
        if undo:
            target = paths.command_file
            text = _read(target)
            if text is not None and b" -m weir statusline report " in text:
                target.unlink()
                with contextlib.suppress(OSError):  # not empty: something else lives there
                    target.parent.rmdir()
            marker = paths.marker()
            if marker is not None:
                target = marker
                marker.unlink()
    except OSError as exc:
        then = _finish(paths, undo)
        raise SetupError(f"cannot write {target} ({exc.strerror}); {then}", 2) from exc


def _finish(paths: Paths, undo: bool) -> str:
    """How to finish after a write failed part way: the settings file
    itself is always whole, as before or as written."""
    if undo:
        return "run weir statusline undo again once it can be written"
    if paths.marker() is not None:
        return (f"{paths.settings} is unchanged. Run weir statusline undo to finish,"
                " then weir statusline setup again once it can be written")
    return f"{paths.settings} is unchanged. Run weir statusline setup again once it can be written"


def confirmed(answer: str) -> bool:
    """The line `yes`, with nothing around it but the line end."""
    return answer.rstrip("\r\n") == "yes"
