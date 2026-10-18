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

from weir.inventory._scan import Hit, line_of
from weir.inventory._types import Reason
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
        line=entry.line, dynamic=entry.value is None,
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
    for record in text.split("\0") if nul else text.splitlines(keepends=True):
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
                line = None if nul else line_of(text, offset)
                entries.append(EnvEntry(name, value, (start, start + len(value)), line))
        offset += len(record) + (1 if nul else 0)
    return entries


def process_env_entries(env: Mapping[str, str]) -> list[EnvEntry]:
    return [EnvEntry(name, env[name], None, None) for name in sorted(env)]


# --- shell startup files ---------------------------------------------------

_EXPORT = re.compile(
    r"^\s*(?:export|declare\s+-[A-Za-z]*x[A-Za-z]*|typeset\s+-[A-Za-z]*x[A-Za-z]*)\s+(.*)$"
)
_ASSIGN = re.compile(rf"^\s*({_NAME})=(.*)$")
_SETENV = re.compile(rf"^\s*setenv\s+({_NAME})\s+(.*)$")
_FISH_SET = re.compile(rf"^\s*set\s+((?:-\S+\s+)+)({_NAME})\s+(.*)$")


def _shell_word(text: str, start: int) -> tuple[str | None, int, int, str]:
    """The shell word at text[start:]: (literal value or None when it
    expands, value start, end of word). Quotes are removed; single quotes are
    literal, double quotes and bare words expand `$` and backticks. The
    fourth item is the word's text with quotes removed, expanded or not."""
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


_EXPORTED_NAMES = re.compile(rf"(?:^|[;&|])\s*export\s+((?:{_NAME}[ \t]*)+)(?=$|[;&|#])", re.M)


def _entry(name: str, value: str | None, start: int, raw: str, number: int) -> EnvEntry:
    span = (start, start + len(value)) if value is not None else None
    return EnvEntry(name, value, span, number, None if value is not None else raw)


def parse_startup_file(text: str) -> list[EnvEntry]:
    """Assignments: `export NAME=v`, `declare -x`, `typeset -x`, csh
    `setenv NAME v`, fish `set -x NAME v`, and plain `NAME=v`, which is
    `exported` when an `export NAME` anywhere in the file exports it."""
    exported: list[EnvEntry] = []
    plain: list[EnvEntry] = []
    exported_names = {
        name for m in _EXPORTED_NAMES.finditer(text) for name in m.group(1).split()
    }
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        number = line_of(text, offset)
        if (m := _EXPORT.match(line)) is not None:
            for name, value, start, _, raw in _assignments(m.group(1), m.start(1)):
                if start >= 0:
                    exported.append(_entry(name, value, offset + start, raw, number))
        elif (m := _SETENV.match(line)) is not None:
            value, vstart, _, raw = _shell_word(line, m.start(2))
            exported.append(_entry(m.group(1), value, offset + vstart, raw, number))
        elif (m := _FISH_SET.match(line)) is not None:
            value, vstart, _, raw = _shell_word(line, m.start(3))
            entry = _entry(m.group(2), value, offset + vstart, raw, number)
            if re.search(r"(?:^|\s)(?:-[A-Za-z]*x[A-Za-z]*|--export)(?=\s)", m.group(1)):
                exported.append(entry)
            else:
                plain.append(entry)
        elif (m := _ASSIGN.match(line)) is not None:
            value, vstart, _, raw = _shell_word(line, m.start(2))
            plain.append(_entry(m.group(1), value, offset + vstart, raw, number))
        offset += len(raw_line)
    for entry in plain:
        entry.exported = entry.name in exported_names
    return sorted([*exported, *plain], key=lambda e: (e.line or 0, e.name))
