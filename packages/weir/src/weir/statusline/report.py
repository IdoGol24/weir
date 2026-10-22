"""The /weir session report (docs/statusline.md, "The /weir report").

A full `weir audit` of one Claude Code session's files, read per
credential: where the credential comes from, the turn and tool call that
put it in the context or sent it out, where it now sits, and what to do.
Every string it prints came out of the audit report, which already applied
the audit's printing rule, or is a number, a fixed word or a session line
number. It never prints a value.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

from weir._text_safety import plural
from weir.audit import (
    CredentialResult,
    Form,
    Format,
    Hit,
    Inputs,
    Kind,
    Report,
    State,
    audit_files,
)
from weir.audit.formats import json_lines
from weir.audit.text import label
from weir.canary.walk import Json
from weir.statusline.segment import counted, segment_text, tally, value_groups

_SOURCES = {
    "environment": "the environment Claude Code starts with",
    "standard_location": "a standard credential file",
    "project_scan": "a project file",
    "map": "a location the project's map names",
}
_STATE_ORDER = {
    State.IN_TOOL_CALL: 0, State.IN_CONTEXT: 1, State.UNKNOWN: 2, State.STORED: 3,
}


@dataclass(frozen=True)
class Turns:
    """The turn of each line of the main transcript, and the turn of the
    tool call that started each subagent (docs/statusline.md, "Turns")."""

    transcript: str
    by_line: dict[int, int]
    by_tool_use: dict[str, int]

    def of(self, hit: Hit) -> tuple[int | None, bool]:
        """(turn, in a subagent) of a hit."""
        if hit.file == self.transcript:
            return self.by_line.get(hit.line), False
        path = PurePath(hit.file)
        if path.parent.name != "subagents" or path.suffix != ".jsonl":
            return None, False
        meta = path.with_name(path.stem + ".meta.json")
        try:
            sidecar: Json = json.loads(Path(meta).read_bytes())
        except (OSError, ValueError):
            return None, True
        tool_use = sidecar.get("toolUseId") if isinstance(sidecar, dict) else None
        return self.by_tool_use.get(tool_use) if isinstance(tool_use, str) else None, True


def _is_prompt(record: dict[str, Json]) -> bool:
    """A prompt the person typed: a `user` record, not `isMeta`, whose
    content is a string or holds a text block and no tool result."""
    if record.get("type") != "user" or record.get("isMeta") is True:
        return False
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return True
    if not isinstance(content, list):
        return False
    types = {str(b.get("type")) for b in content if isinstance(b, dict)}
    return "text" in types and "tool_result" not in types


def read_turns(transcript: str) -> Turns:
    by_line: dict[int, int] = {}
    by_tool_use: dict[str, int] = {}
    try:
        data = Path(transcript).read_bytes()
    except OSError:
        return Turns(transcript, by_line, by_tool_use)
    turn = 0
    for line in json_lines(data):
        record = line.parsed
        if record is not None and _is_prompt(record):
            turn += 1
        by_line[line.number] = turn
        message = record.get("message") if record is not None else None
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_id = block.get("id")
                if isinstance(tool_id, str):
                    by_tool_use[tool_id] = turn
    return Turns(transcript, by_line, by_tool_use)


def _how(hit: Hit) -> str:
    """What the hit sat in, in words."""
    tool = hit.tool or "a"
    if hit.format is Format.CLAUDE_CODE_MEMORY:
        return "CLAUDE.md or memory file Claude Code loaded"
    if hit.format is Format.CLAUDE_CODE_TOOL_RESULTS:
        return "saved tool output"
    if hit.kind is Kind.TOOL_CALL:
        argument = f", argument {hit.argument}" if hit.argument else ""
        return f"{tool} tool call{argument}"
    if hit.record == "user":
        if hit.tool is not None:
            return f"{tool} tool result"
        return "prompt" if hit.location == "message.content" else "user message"
    if hit.record == "assistant":
        return "model's own text"
    if hit.record in ("attachment", "summary"):
        return hit.record
    return f"{hit.record or hit.format.value} record"


def _where(hit: Hit, turns: Turns) -> str:
    turn, sub = turns.of(hit)
    when = f"turn {turn}" if turn is not None else "an unknown turn"
    return f"{when}{', in a subagent' if sub else ''}: the {_how(hit)}, {hit.file}:{hit.line}"


def _first(hits: Sequence[Hit], turns: Turns) -> Hit:
    def order(hit: Hit) -> tuple[int, bool, str, int]:
        turn, sub = turns.of(hit)
        return (turn if turn is not None else 1 << 30, sub, hit.file, hit.line)

    return min(hits, key=order)


def _times(count: int) -> str:
    return plural(count, "time")


def _advice(
    members: Sequence[CredentialResult], state: State, reached: bool, value_files: Sequence[str]
) -> str:
    if not reached:
        if state is State.UNKNOWN:
            return "open the place named above: the audit cannot tell whether the agent read it"
        return "nothing reached the agent; Claude Code keeps it in the bookkeeping named above"
    parts = ["rotate it at its issuer"]
    for c in members:
        if c.source == "environment":
            parts.append(f"remove {c.name} from the environment Claude Code starts with")
        else:
            parts.append(f"take it out of {c.display}, or deny the agent read access to that file")
    if value_files:
        parts.append("delete the session files above once it is rotated")
    return "; ".join(dict.fromkeys(parts))


def _heading(members: Sequence[CredentialResult]) -> str:
    """One record: the audit's label. Several: each name once, with every
    place it was found."""
    if len(members) == 1:
        return label(members[0])
    places: dict[str, list[str]] = {}
    for c in members:
        where = c.display if c.scope is None else f"{c.display} {c.scope}"
        places.setdefault(c.name, []).append(where)
    return ", ".join(f"{name} ({', '.join(where)})" for name, where in places.items())


def _source(c: CredentialResult) -> str:
    scope = "" if c.scope is None else f" ({c.scope})"
    return f"{c.display}{scope}, {_SOURCES.get(c.source, c.source)}"


def _one_per_place(hits: Sequence[Hit]) -> list[Hit]:
    """One hit per place in the session: every record of one credential can
    match the same string (a `$NAME` that names both, say). A hit by value
    there wins over one by name."""
    out: dict[tuple[object, ...], Hit] = {}
    for hit in hits:
        place = (
            hit.kind, hit.file, hit.line, hit.location, hit.tool, hit.argument, hit.span_id,
            hit.log_record,
        )
        if place not in out or out[place].form is Form.NAME:
            out[place] = hit
    return list(out.values())


def _block(
    members: Sequence[CredentialResult], state: State, all_hits: Sequence[Hit], turns: Turns
) -> Iterator[str]:
    hits = _one_per_place(all_hits)
    yield _heading(members)
    yield "  source: " + "; ".join(dict.fromkeys(_source(c) for c in members))
    entered = [
        h for h in hits
        if h.kind is Kind.CONTEXT or (h.kind is Kind.TOOL_CALL and h.form is not Form.NAME)
    ]
    sent = [h for h in hits if h.kind is Kind.TOOL_CALL]
    unknown = [h for h in hits if h.kind is Kind.UNKNOWN]
    if entered:
        yield (
            f"  entered the context: {_times(len(entered))}, first at"
            f" {_where(_first(entered, turns), turns)}"
        )
    if sent:
        named = sum(h.form is Form.NAME for h in sent)
        by = " by name" if named == len(sent) else " by value" if not named else (
            " by value and by name"
        )
        yield (
            f"  sent in a tool call: {_times(len(sent))}{by}, first at"
            f" {_where(_first(sent, turns), turns)}"
        )
    if unknown:
        yield (
            f"  unknown: {plural(len(unknown), 'place')} the audit cannot classify, first at"
            f" {_where(_first(unknown, turns), turns)}"
        )
    value_files = list(dict.fromkeys(h.file for h in hits if h.form is not Form.NAME))
    sits = ", ".join(value_files) if value_files else "no session file holds the value"
    if entered:
        sits += "; and in the conversation the model received"
    tools = list(dict.fromkeys(h.tool or "a" for h in sent))
    if tools:
        sits += "; and wherever the " + ", ".join(tools) + " tool call sent it"
    yield f"  now sits in: {sits}"
    yield f"  advice: {_advice(members, state, bool(entered or sent), value_files)}"


def report_lines(
    inputs: Inputs, transcript: str, session_id: str, claude_config_dirs: Sequence[str]
) -> list[str]:
    """The report for one session. Raises `AuditInputError` on a file the
    audit refuses (a FIFO in the session's directory, say)."""
    paths = [transcript]
    parent, stem = os.path.dirname(transcript), PurePath(transcript).stem
    for name in dict.fromkeys((stem, session_id)):
        if name and os.path.isdir(os.path.join(parent, name)):
            paths.append(os.path.join(parent, name))
    report: Report = audit_files(
        inputs.credentials, inputs.key, inputs.by_fingerprint, paths, claude_config_dirs
    )
    found = tally(report)
    groups = value_groups(inputs)
    context, sent = counted(found, groups)
    lines = [segment_text(context, sent, unknown=found.unknown)]
    shown = next((f.file for f in report.files if f.file == transcript), "[withheld]")
    lines.append(f"session: {shown} ({plural(report.coverage.files, 'file')} read)")
    turns = read_turns(transcript)
    by_credential: dict[str, list[Hit]] = {}
    for hit in report.hits:
        by_credential.setdefault(hit.credential, []).append(hit)
    # One block per credential as the segment counts them: the records of
    # one value or one variable together, in the audit's order.
    members: dict[str, list[CredentialResult]] = {}
    for c in report.credentials:
        members.setdefault(groups.get(c.id, c.id), []).append(c)
    reached = [m for m in members.values() if any(c.state in _STATE_ORDER for c in m)]
    blocks: list[tuple[list[CredentialResult], State]] = []
    for m in reached:
        state = min((c.state for c in m if c.state in _STATE_ORDER), key=_STATE_ORDER.__getitem__)
        blocks.append((m, state))
    blocks.sort(key=lambda block: _STATE_ORDER[block[1]])
    for m, state in blocks:
        lines.append("")
        hits = [h for c in m for h in by_credential.get(c.id, [])]
        lines.extend(_block(m, state, hits, turns))
    rest = [m for m in members.values() if m not in reached]
    not_checkable = sum(all(c.state is State.NOT_CHECKABLE for c in m) for m in rest)
    not_found = len(rest) - not_checkable
    lines.append("")
    lines.append(
        f"not found in this session: {plural(not_found, 'credential')};"
        f" not checkable: {plural(not_checkable, 'credential')}"
    )
    for unknown in report.unknown:
        subject = "" if unknown.subject is None else f" {unknown.subject}"
        lines.append(f"unknown: {unknown.reason.value}{subject}")
    return lines
