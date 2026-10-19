"""Source 3: the agent's launch environment, and the shell startup files that
re-export a variable into it.

Blocking a variable in the agent's environment is undone by a startup file
the agent can read, which is why each exported assignment in a startup file
is its own record with its own location.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace

from weir.inventory._scan import Hit, line_of
from weir.inventory._types import PartlyReadReason, Reason, ValueState
from weir.inventory.classify import EnvVerdict, classify_env, is_dynamic, not_secret_kind
from weir.inventory.project import scan_shapes

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"


@dataclass
class EnvEntry:
    """One variable assignment. `value` is None when it is not literal."""

    name: str
    value: str | None
    # Character span of the value in its text; for a partial value, of the
    # part its first line holds.
    span: tuple[int, int] | None
    line: int | None
    # The unexpanded text of a non-literal value (`$HOME/bin:$PATH`), kept
    # only so a PATH-style expansion can still be judged a path.
    expansion: str | None = None
    # False for a startup-file assignment nothing exports: not part of the
    # launch environment, but a value in a file the agent can read.
    exported: bool = True
    # True for a startup-file value weir did not fully read (a quoted value
    # its line leaves open, a PEM block with no END line): value None.
    partial: bool = False
    # A credential shape found inside the value's span: the record carries
    # this shape's value and offsets under the variable's name.
    shape: Hit | None = None


@dataclass
class Judged:
    entry: EnvEntry
    verdict: EnvVerdict
    why: str | None


# A PEM armor line opening a value: `-----BEGIN PRIVATE KEY-----`.
_ARMOR = re.compile(r"-----BEGIN ([^\r\n-]+)-----")


def judge(entry: EnvEntry) -> Judged:
    if entry.shape is not None:
        return Judged(entry, EnvVerdict.SECRET, "shape")
    if entry.value is not None and (armor := _ARMOR.match(entry.value)) is not None:
        if f"-----END {armor.group(1)}-----" not in entry.value:
            return Judged(entry, EnvVerdict.SECRET, "pem_block")
    if entry.value is None and entry.expansion is not None:
        kind = not_secret_kind(entry.expansion)
        if kind is not None:
            return Judged(entry, EnvVerdict.NOT_SECRET, kind)
    verdict, why = classify_env(entry.name, entry.value)
    return Judged(entry, verdict, why)


def to_hit(judged: Judged, detector: str) -> Hit:
    entry = judged.entry
    if entry.shape is not None:
        return Hit(
            name=entry.name, reason=Reason.SHAPE, detectors={detector, *entry.shape.detectors},
            value=entry.shape.value, spans=list(entry.shape.spans), line=entry.line,
        )
    reason = Reason.NAME if judged.why == "name" else Reason.SHAPE
    return Hit(
        name=entry.name, reason=reason, detectors={detector}, value=entry.value,
        spans=[entry.span] if entry.span is not None and entry.value is not None else [],
        line=entry.line, missing=ValueState.PARTIAL if entry.partial else ValueState.DYNAMIC,
    )


# --- launch environment ----------------------------------------------------


def _closing_quote(text: str, start: int, quote: str) -> int:
    """Index of the quote that closes a value opened just before `start`,
    or -1. Inside double quotes a backslash escapes the next character."""
    i = start
    while i < len(text):
        if text[i] == "\\" and quote == '"':
            i += 2
        elif text[i] == quote:
            return i
        else:
            i += 1
    return -1


def parse_env_file(text: str) -> list[EnvEntry]:
    """`NAME=value` per line (dotenv style: `export ` and one level of
    quotes are stripped, `#` lines skipped; a quoted value runs to its
    closing quote, across lines; an unquoted value that opens a PEM block,
    `-----BEGIN <label>-----`, runs to its `-----END <label>-----` line, or
    to the end of the file when nothing closes it; any other unquoted value
    ends before a ` #` comment and trailing blanks), or NUL-separated
    `env -0` output. The
    value is taken literally: an env file holds what the process had,
    after the shell expanded it."""
    if "\0" in text:
        return _parse_env_records(text)
    entries: list[EnvEntry] = []
    pos = 0
    number = 1
    while pos < len(text):
        eol = text.find("\n", pos)
        eol = len(text) if eol == -1 else eol
        after = eol + 1
        body = text[pos:eol].rstrip("\r")
        stripped = body.lstrip()
        lead = len(body) - len(stripped)
        if stripped.startswith("export "):
            lead += len("export ")
            stripped = stripped[len("export "):]
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name, raw = stripped.split("=", 1)
            if re.fullmatch(_NAME, name):
                start = pos + lead + len(name) + 1
                value = re.split(r"\s+#", raw, maxsplit=1)[0].rstrip()
                if raw[:1] in ("'", '"'):
                    close = _closing_quote(text, start + 1, raw[0])
                    if close != -1:
                        start += 1
                        value = text[start:close]
                        if close > eol:
                            end = text.find("\n", close)
                            after = len(text) if end == -1 else end + 1
                elif (armor := _ARMOR.match(raw)) is not None:
                    marker = f"-----END {armor.group(1)}-----"
                    end = text.find(marker, start)
                    stop = len(text) if end == -1 else end + len(marker)
                    value = text[start:stop].rstrip()
                    end = text.find("\n", stop)
                    after = len(text) if end == -1 else end + 1
                entries.append(EnvEntry(name, value, (start, start + len(value)), number))
        number += text.count("\n", pos, after)
        pos = after
    return entries


def _parse_env_records(text: str) -> list[EnvEntry]:
    """NUL-separated `env -0` output: each record is `NAME=value`, taken
    whole, newlines included."""
    entries: list[EnvEntry] = []
    offset = 0
    for record in text.split("\0"):
        stripped = record.lstrip()
        lead = len(record) - len(stripped)
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name, raw = stripped.split("=", 1)
            if re.fullmatch(_NAME, name):
                start = offset + lead + len(name) + 1
                entries.append(EnvEntry(name, raw, (start, start + len(raw)), None))
        offset += len(record) + 1
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
_NAME_EQ = re.compile(rf"({_NAME})(=?)")
_HEREDOC = re.compile(r"<<-?[ \t]*\\?([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
# A line inside a PEM block: base64, or a header such as `Proc-Type: 4,ENCRYPTED`.
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]*|[A-Za-z][A-Za-z0-9-]*:.*")


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


def _shell_word(text: str, start: int) -> tuple[str | None, int, int, str, bool]:
    """The shell word at text[start:]: (literal value or None when it
    expands, value start, end of word, the word's text with quotes removed,
    False when a quote it opens is still open at the end of text). Single
    quotes are literal; double quotes and bare words expand `$` and
    backticks."""
    i = start
    out: list[str] = []
    dynamic = False
    closed = True
    value_start = start
    while i < len(text) and not text[i].isspace() and text[i] not in ";&|":
        ch = text[i]
        if ch == "'":
            end = text.find("'", i + 1)
            if end == -1:
                end, closed = len(text), False
            if i == start:
                value_start = i + 1
            out.append(text[i + 1:end])
            i = end + 1
        elif ch == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            closed = closed and j < len(text)
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
    return (None if dynamic else value), value_start, min(i, len(text)), value, closed


def _assignments(command: str, i: int) -> Iterator[tuple[str, int]]:
    """`A=1 B="2"` after `export`: (name, where its value starts in the
    command) per assignment; a bare name (`export A`) yields -1."""
    while i < len(command):
        while i < len(command) and command[i].isspace():
            i += 1
        match = _NAME_EQ.match(command, i)
        if match is None:
            return
        i = match.end()
        if match.group(2):
            yield match.group(1), i
            i = _shell_word(command, i)[2]
        else:
            yield match.group(1), -1


def _heredocs(line: str) -> list[str]:
    """The delimiter of every here-document the line opens (`<<EOF`,
    `<<-'EOF'`), read outside quotes and before a comment. `<<<` is a
    here-string, not one."""
    delimiters: list[str] = []
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
        elif ch == "#" and (i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|"):
            break
        elif line.startswith("<<<", i):
            i += 3
            continue
        elif (m := _HEREDOC.match(line, i)) is not None:
            delimiters.append(m.group(2))
            i = m.end()
            continue
        i += 1
    return delimiters


def _read_value(
    text: str, line: tuple[int, int], pos: int, name: str, number: int
) -> tuple[EnvEntry, int, PartlyReadReason | None]:
    """The assignment of `name` whose value starts at text[pos:], on the
    line text[line[0]:line[1]]: (entry, end of what it covers, why it was
    not fully read). A quoted value its
    line leaves open after a PEM BEGIN line runs to its END line while
    every line between reads as a PEM body line; at any other line it
    stops there, not read. Any other quote its line leaves open is not
    read either."""
    first, last = line
    value, vstart, end, raw, closed = _shell_word(text[first:last], pos - first)
    vstart += first
    end += first
    if not closed and vstart > pos and (armor := _ARMOR.match(text, vstart, last)) is not None:
        marker = f"-----END {armor.group(1)}-----"
        newline = text.find("\n", last)
        at = len(text) if newline == -1 else newline + 1
        while at < len(text):
            newline = text.find("\n", at)
            body = text[at:len(text) if newline == -1 else newline].rstrip("\r")
            if (close := body.find(marker)) != -1:
                stop = at + close + len(marker)
                quoted = text.startswith(text[vstart - 1], stop)
                value = text[vstart:stop]
                return EnvEntry(name, value, (vstart, stop), number), stop + quoted, None
            if _PEM_BODY.fullmatch(body.strip()) is None:
                break
            at = len(text) if newline == -1 else newline + 1
        partial = EnvEntry(name, None, (vstart, last), number, partial=True)
        return partial, at, PartlyReadReason.UNCLOSED_PEM
    if not closed:
        partial = EnvEntry(name, None, (vstart, last), number, partial=True)
        return partial, end, PartlyReadReason.MULTI_LINE_QUOTE
    return _entry(name, value, vstart, raw, number), end, None


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


@dataclass
class StartupFile:
    entries: list[EnvEntry]
    # (1-based line, why) for each place the file was not fully read.
    not_fully_read: list[tuple[int, PartlyReadReason]]
    # Credential shapes outside every assignment's value, each at its line.
    shapes: list[Hit]


def parse_startup_file(text: str) -> StartupFile:
    """Assignments in every simple command (`a && export NAME=v; b`):
    `export NAME=v`, `declare -x`, `typeset -x`, csh `setenv NAME v`, fish
    `set -x NAME v`, and plain `NAME=v`, which is `exported` when an
    `export NAME` anywhere in the file exports it.

    Each line is read on its own: no quote carries to the next line, except
    that a quoted value its line leaves open after `-----BEGIN <label>-----`
    runs to its `-----END <label>-----` line through PEM body lines.
    What is not fully read is reported, never skipped silently: a
    here-document (its body skipped to its delimiter line), a quoted value
    its line leaves open, a PEM block with no END line. Credential shapes
    are searched for over the whole file all the same."""
    exported: list[EnvEntry] = []
    plain: list[EnvEntry] = []
    exported_names: set[str] = set()
    partly: set[tuple[int, PartlyReadReason]] = set()
    lines = text.splitlines(keepends=True)
    starts = [0]
    for raw_line in lines:
        starts.append(starts[-1] + len(raw_line))
    consumed = 0
    for index, raw_line in enumerate(lines):
        number = index + 1
        first = starts[index]
        line = raw_line.rstrip("\r\n")
        if line and first + len(line) <= consumed:
            continue
        skip = max(consumed - first, 0)
        rest = line[skip:]
        assigned: list[tuple[str, int, bool]] = []
        for start, command in _commands(rest):
            base = first + skip + start
            if (m := _EXPORT.match(command)) is not None:
                for name, at in _assignments(command, m.start(1)):
                    if at < 0:
                        exported_names.add(name)
                    else:
                        assigned.append((name, base + at, True))
            elif (m := _SETENV.match(command)) is not None:
                assigned.append((m.group(1), base + m.start(2), True))
            elif (m := _FISH_SET.match(command)) is not None:
                flags = m.group(1)
                exports = re.search(r"(?:^|\s)(?:-[A-Za-z]*x[A-Za-z]*|--export)(?=\s)", flags)
                assigned.append((m.group(2), base + m.start(3), exports is not None))
            elif (m := _ASSIGN.match(command)) is not None:
                assigned.append((m.group(1), base + m.start(2), False))
        for name, at, is_export in assigned:
            entry, end, why = _read_value(text, (first, first + len(line)), at, name, number)
            (exported if is_export else plain).append(entry)
            consumed = max(consumed, end)
            if why is not None:
                partly.add((number, why))
        body = index + 1
        for delimiter in _heredocs(rest):
            partly.add((number, PartlyReadReason.HEREDOC))
            close = next(
                (j for j in range(body, len(lines)) if lines[j].strip() == delimiter), None
            )
            if close is None:
                break
            consumed = max(consumed, starts[close + 1])
            body = close + 1
    for entry in plain:
        entry.exported = entry.name in exported_names
    for entry in (*exported, *plain):
        _verify_span(text, entry)
    entries = sorted([*exported, *plain], key=lambda e: (e.line or 0, e.name))
    return StartupFile(
        entries=entries, not_fully_read=sorted(partly), shapes=_shapes(text, entries),
    )


def _shapes(text: str, entries: list[EnvEntry]) -> list[Hit]:
    """Credential shapes anywhere in the file, read without assignment
    parsing, one per occurrence. A shape inside an assignment's value is
    that assignment's (one secret, one record), clipped to the value's span:
    the value's own bytes of the shape, so the same secret elsewhere links.
    A value not fully read keeps a complete PEM private key whole, and takes
    no part of an incomplete one, so it never holds an armor line alone. Any
    other shape, in a here-document or a continuation line or a comment, is
    returned."""
    loose: list[Hit] = []
    for found in scan_shapes(text):
        for start, end in found.spans:
            hit = replace(found, spans=[(start, end)], line=line_of(text, start))
            owner = next((
                e for e in entries
                if e.shape is None and e.span is not None
                and e.span[0] < end and start < e.span[1]
            ), None)
            if owner is None or owner.span is None:
                loose.append(hit)
            elif owner.value is None and (armor := _ARMOR.match(text, start, end)) is not None:
                if f"-----END {armor.group(1)}-----" in text[start:end]:
                    owner.shape = hit
            else:
                first, last = max(start, owner.span[0]), min(end, owner.span[1])
                owner.shape = replace(hit, value=text[first:last], spans=[(first, last)])
    return loose
