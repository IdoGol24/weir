"""Source 3: the agent's launch environment, and the shell startup files that
re-export a variable into it.

Blocking a variable in the agent's environment is undone by a startup file
the agent can read, which is why each exported assignment in a startup file
is its own record with its own location.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from weir.inventory._scan import Hit
from weir.inventory._types import Reason, ValueState
from weir.inventory.classify import EnvVerdict, classify_env, is_dynamic, not_secret_kind

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"


@dataclass
class EnvEntry:
    """One variable assignment. `value` is None when it is not literal."""

    name: str
    value: str | None
    span: tuple[int, int] | None  # character span of the value in its text
    line: int | None
    # The unexpanded text of a non-literal value (`$HOME/bin:$PATH`), kept
    # only so a PATH-style expansion can still be judged a path.
    expansion: str | None = None
    # False for a startup-file assignment nothing exports: not part of the
    # launch environment, but a value in a file the agent can read.
    exported: bool = True


@dataclass
class Judged:
    entry: EnvEntry
    verdict: EnvVerdict
    why: str | None


def judge(entry: EnvEntry) -> Judged:
    if entry.value is None and entry.expansion is not None:
        kind = not_secret_kind(entry.expansion)
        if kind is not None:
            return Judged(entry, EnvVerdict.NOT_SECRET, kind)
    verdict, why = classify_env(entry.name, entry.value)
    return Judged(entry, verdict, why)


def to_hit(judged: Judged, detector: str) -> Hit:
    entry = judged.entry
    reason = Reason.NAME if judged.why == "name" else Reason.SHAPE
    return Hit(
        name=entry.name, reason=reason, detectors={detector}, value=entry.value,
        spans=[entry.span] if entry.span is not None and entry.value is not None else [],
        line=entry.line, missing=ValueState.DYNAMIC,
    )


# --- launch environment ----------------------------------------------------


def _unquote(value: str, start: int) -> tuple[str, int]:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1], start + 1
    return value, start


def parse_env_file(text: str) -> list[EnvEntry]:
    """`NAME=value` per line (dotenv style: `export ` and one level of
    matching quotes are stripped, `#` lines skipped), or NUL-separated
    `env -0` output. The value is taken literally: an env file holds what
    the process had, after the shell expanded it."""
    entries: list[EnvEntry] = []
    nul = "\0" in text
    offset = 0
    for number, record in enumerate(
        text.split("\0") if nul else text.splitlines(keepends=True), start=1
    ):
        body = record if nul else record.rstrip("\r\n")
        stripped = body.lstrip()
        lead = len(body) - len(stripped)
        if stripped.startswith("export ") and not nul:
            lead += len("export ")
            stripped = stripped[len("export "):]
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name, raw = stripped.split("=", 1)
            if re.fullmatch(_NAME, name):
                vstart = lead + len(name) + 1
                value, vstart = (raw, vstart) if nul else _unquote(raw, vstart)
                start = offset + vstart
                line = None if nul else number
                entries.append(EnvEntry(name, value, (start, start + len(value)), line))
        offset += len(record) + (1 if nul else 0)
    return entries


def process_env_entries(env: Mapping[str, str]) -> list[EnvEntry]:
    return [EnvEntry(name, env[name], None, None) for name in sorted(env)]


# --- shell startup files ---------------------------------------------------

# A command may follow a reserved word on its line: `if x; then export A=1; fi`.
_LEAD = r"^\s*(?:(?:then|else|do|\{|!)\s+)*"
_EXPORT = re.compile(
    _LEAD
    + r"(?:export|declare\s+-[A-Za-z]*x[A-Za-z]*|typeset\s+-[A-Za-z]*x[A-Za-z]*)\s+(.*)$"
)
_ASSIGN = re.compile(rf"{_LEAD}({_NAME})=(.*)$")
_SETENV = re.compile(rf"{_LEAD}setenv\s+({_NAME})\s+(.*)$")
_FISH_SET = re.compile(rf"{_LEAD}set\s+((?:-\S+\s+)+)({_NAME})\s+(.*)$")


def _commands(line: str) -> Iterator[tuple[int, str]]:
    """The simple commands on one line, as (start, text): split at unquoted
    `;`, `&` and `|` (so `&&` and `||` too), ending at an unquoted comment.
    A parenthesized group or `$(...)` is not split."""
    start = 0
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            if ch == "\\" and quote != "'":
                i += 1
            elif ch == quote:
                quote = None
        elif ch == "\\":
            i += 1
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif ch == "#" and (i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|"):
            break
        elif ch in ";&|" and depth == 0:
            yield start, line[start:i]
            start = i + 1
        i += 1
    yield start, line[start:min(i, len(line))]


def _shell_word(text: str, start: int) -> tuple[str | None, int, int, str]:
    """The shell word at text[start:]: (literal value or None when it
    expands, value start, end of word, the word's text with quotes removed).
    Single quotes are literal; double quotes and bare words expand `$` and
    backticks."""
    i = start
    out: list[str] = []
    dynamic = False
    value_start = start
    while i < len(text) and not text[i].isspace() and text[i] not in ";&|":
        ch = text[i]
        if ch == "'":
            end = text.find("'", i + 1)
            end = len(text) if end == -1 else end
            if i == start:
                value_start = i + 1
            out.append(text[i + 1:end])
            i = end + 1
        elif ch == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            chunk = text[i + 1:min(j, len(text))]
            if is_dynamic(chunk):
                dynamic = True
            if i == start:
                value_start = i + 1
            out.append(re.sub(r"\\(.)", r"\1", chunk))
            i = j + 1
        elif ch == "#" and i == start:
            break
        else:
            j = i
            while j < len(text) and not text[j].isspace() and text[j] not in ";&|'\"":
                j += 1
            chunk = text[i:j]
            if is_dynamic(chunk):
                dynamic = True
            out.append(chunk)
            i = j
    value = "".join(out)
    return (None if dynamic else value), value_start, i, value


def _assignments(rest: str, base: int) -> Iterator[tuple[str, str | None, int, int, str]]:
    """`A=1 B="2"` after `export`: (name, value, start, end, text) per
    assignment; a bare name (`export A`) yields value None with start -1."""
    i = 0
    while i < len(rest):
        while i < len(rest) and rest[i].isspace():
            i += 1
        match = re.match(rf"({_NAME})(=?)", rest[i:])
        if match is None:
            return
        name = match.group(1)
        i += match.end()
        if match.group(2):
            value, vstart, end, raw = _shell_word(rest, i)
            literal_len = len(value) if value is not None else 0
            yield name, value, base + vstart, base + vstart + literal_len, raw
            i = end
        else:
            yield name, None, -1, -1, ""


def _entry(name: str, value: str | None, start: int, raw: str, number: int) -> EnvEntry:
    span = (start, start + len(value)) if value is not None else None
    return EnvEntry(name, value, span, number, None if value is not None else raw)


def _verify_span(text: str, entry: EnvEntry) -> None:
    """A word that mixes quoting (`A=abc"def"`) has a value that is not one
    contiguous run of the file: never record an offset that does not hold
    the value. Fall back to the value's first occurrence on its line."""
    if entry.span is None or entry.value is None:
        return
    start, end = entry.span
    if text[start:end] == entry.value:
        return
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    found = text.find(entry.value, line_start, len(text) if line_end == -1 else line_end)
    entry.span = (found, found + len(entry.value)) if entry.value and found != -1 else None


def parse_startup_file(text: str) -> list[EnvEntry]:
    """Assignments in every simple command (`a && export NAME=v; b`):
    `export NAME=v`, `declare -x`, `typeset -x`, csh `setenv NAME v`, fish
    `set -x NAME v`, and plain `NAME=v`, which is `exported` when an
    `export NAME` anywhere in the file exports it."""
    exported: list[EnvEntry] = []
    plain: list[EnvEntry] = []
    exported_names: set[str] = set()
    offset = 0
    for number, raw_line in enumerate(text.splitlines(keepends=True), start=1):
        for start, command in _commands(raw_line.rstrip("\r\n")):
            base = offset + start
            if (m := _EXPORT.match(command)) is not None:
                for name, value, vstart, _, raw in _assignments(m.group(1), m.start(1)):
                    if vstart >= 0:
                        exported.append(_entry(name, value, base + vstart, raw, number))
                    else:
                        exported_names.add(name)
            elif (m := _SETENV.match(command)) is not None:
                value, vstart, _, raw = _shell_word(command, m.start(2))
                exported.append(_entry(m.group(1), value, base + vstart, raw, number))
            elif (m := _FISH_SET.match(command)) is not None:
                value, vstart, _, raw = _shell_word(command, m.start(3))
                entry = _entry(m.group(2), value, base + vstart, raw, number)
                if re.search(r"(?:^|\s)(?:-[A-Za-z]*x[A-Za-z]*|--export)(?=\s)", m.group(1)):
                    exported.append(entry)
                else:
                    plain.append(entry)
            elif (m := _ASSIGN.match(command)) is not None:
                value, vstart, _, raw = _shell_word(command, m.start(2))
                plain.append(_entry(m.group(1), value, base + vstart, raw, number))
        offset += len(raw_line)
    for entry in plain:
        entry.exported = entry.name in exported_names
    for entry in (*exported, *plain):
        _verify_span(text, entry)
    return sorted([*exported, *plain], key=lambda e: (e.line or 0, e.name))
