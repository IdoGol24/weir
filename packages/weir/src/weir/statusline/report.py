"""The /weir session report (docs/statusline.md, "The /weir report").

A full `weir audit` of one Claude Code session's files, read per
credential: where the credential comes from, the turn and tool call that
put it in the context or sent it out, where it now sits, and what to do.
Every string it prints came out of the audit report, which already applied
the audit's printing rule, or is a number, a fixed word, a session line
number, or a folder or inventory path it was given or the inventory
names, under the audit's printing rule for a path with a key's shape
looked for in each segment. It never prints a value.
"""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from weir._text_safety import plural
from weir.audit import (
    CredentialResult,
    Format,
    Hit,
    Inputs,
    Kind,
    State,
    audit_naming,
)
from weir.audit.formats import json_lines
from weir.audit.text import label
from weir.canary.walk import Json
from weir.statusline.segment import (
    NOTHING_TO_CHECK,
    counted,
    inventoried,
    note,
    segment_text,
    tally,
    value_groups,
)
from weir.statusline.setup import holds_home, inventory_command

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
    # A subagent transcript's path -> the turn its sidecar's tool call is in
    subagents: dict[str, int | None] = field(default_factory=dict[str, "int | None"])

    def of(self, hit: Hit) -> tuple[int | None, bool]:
        """(turn, in a subagent) of a hit."""
        if hit.file == self.transcript:
            return self.by_line.get(hit.line), False
        path = PurePath(hit.file)
        if path.parent.name != "subagents" or path.suffix != ".jsonl":
            return None, False
        if hit.file not in self.subagents:  # each sidecar read once
            tool_use: Json = None
            try:
                sidecar: Json = json.loads(Path(path.with_suffix(".meta.json")).read_bytes())
                tool_use = sidecar.get("toolUseId") if isinstance(sidecar, dict) else None
            except (OSError, ValueError):
                pass
            turn = self.by_tool_use.get(tool_use) if isinstance(tool_use, str) else None
            self.subagents[hit.file] = turn
        return self.subagents[hit.file], True


# Records Claude Code writes as `user` records that the person did not type
# as a prompt: a local slash command (`/model`, say), a shell command run
# with `!`, their output, and the note that the person interrupted the agent.
_NOT_TYPED_STARTS = (
    "<command-name>", "<command-message>", "<command-args>", "<local-command-stdout>",
    "<local-command-stderr>", "<local-command-caveat>", "<bash-input>", "<bash-stdout>",
    "<bash-stderr>", "[Request interrupted by user",
)
# Flags that mark a `user` record as not a prompt: meta records, the summary
# that compaction writes, and records shown in the transcript view only.
_NOT_A_PROMPT_FLAGS = ("isMeta", "isCompactSummary", "isVisibleInTranscriptOnly")


def _is_prompt(record: dict[str, Json]) -> bool:
    """A prompt the person typed: a `user` record with none of the flags
    above, whose content is a string or holds a text, image or document
    block and no tool result, and whose text is not a record above."""
    if record.get("type") != "user":
        return False
    if any(record.get(flag) is True for flag in _NOT_A_PROMPT_FLAGS):
        return False
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        texts = [content]
    elif isinstance(content, list):
        blocks = [b for b in content if isinstance(b, dict)]
        if any(b.get("type") == "tool_result" for b in blocks):
            return False
        texts = [str(b.get("text", "")) for b in blocks if b.get("type") == "text"]
        if not texts:
            return any(b.get("type") in ("image", "document") for b in blocks)
    else:
        return False
    return not any(text.lstrip().startswith(_NOT_TYPED_STARTS) for text in texts)


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


def _in_startup_file(c: CredentialResult) -> bool:
    """An environment credential a shell startup file exports, not the
    launch environment itself."""
    return c.source == "environment" and c.display != "launch env"


def _advice(
    members: Sequence[CredentialResult], state: State, reached: bool, value_files: Sequence[str],
) -> str:
    if not reached:
        if state is State.UNKNOWN:
            return "open the place named above: the audit cannot tell whether the agent read it"
        return "nothing reached the agent; Claude Code keeps it in the bookkeeping named above"
    parts = ["rotate it at its issuer"]
    for c in members:
        if _in_startup_file(c):
            # Removing it from the environment alone: the next shell the
            # startup file runs puts it straight back.
            parts.append(f"take it out of {c.display}, which exports it into the environment")
        elif c.source == "environment":
            parts.append(f"remove {c.name} from the environment Claude Code starts with")
        else:
            parts.append(f"take it out of {c.display}, or deny the agent read access to that file")
    if value_files:
        parts.append("delete the session files above once it is rotated")
    return "; ".join(dict.fromkeys(parts))


def _heading_and_source(members: Sequence[CredentialResult]) -> tuple[str, str]:
    """The heading: the audit's label for one record, or each name once with
    every place it was found; and where each record comes from."""
    places: dict[str, list[str]] = {}
    sources: list[str] = []
    for c in members:
        places.setdefault(c.name, []).append(
            c.display if c.scope is None else f"{c.display} {c.scope}"
        )
        how = _SOURCES.get(c.source, c.source)
        if _in_startup_file(c):
            how = "a shell startup file that exports it into the environment"
        scope = "" if c.scope is None else f" ({c.scope})"
        sources.append(f"{c.display}{scope}, {how}")
    heading = label(members[0]) if len(members) == 1 else ", ".join(
        f"{name} ({', '.join(where)})" for name, where in places.items()
    )
    return heading, "; ".join(dict.fromkeys(sources))


def _block(
    members: Sequence[CredentialResult], state: State, all_hits: Sequence[Hit], turns: Turns,
) -> Iterator[str]:
    # Records of one value match the same strings: one hit per place.
    hits = list({(h.kind, h.file, h.line, h.location, h.tool, h.argument): h
                 for h in all_hits}.values())
    heading, source = _heading_and_source(members)
    yield heading
    yield f"  source: {source}"
    entered = [h for h in hits if h.kind in (Kind.CONTEXT, Kind.TOOL_CALL)]
    sent = [h for h in hits if h.kind is Kind.TOOL_CALL]
    unknown = [h for h in hits if h.kind is Kind.UNKNOWN]
    for what, found, count in (
        ("entered the context", entered, plural(len(entered), "time")),
        ("sent in a tool call", sent, plural(len(sent), "time")),
        ("unknown", unknown, plural(len(unknown), "place") + " the audit cannot classify"),
    ):
        if found:
            yield f"  {what}: {count}, first at {_where(_first(found, turns), turns)}"
    value_files = list(dict.fromkeys(h.file for h in hits))
    sits = ", ".join(value_files)
    if entered:
        sits += "; and in the conversation the model received"
    tools = list(dict.fromkeys(h.tool or "a" for h in sent))
    if tools:
        sits += "; and wherever the " + ", ".join(tools) + " tool call sent it"
    yield f"  now sits in: {sits}"
    yield f"  advice: {_advice(members, state, bool(entered or sent), value_files)}"


def _not_inventoried(
    inputs: Inputs, folder: str | None, here: str | None, files: Sequence[str],
    shown: Mapping[str, str],
) -> list[str]:
    """Why a session outside the inventory's project, or whose project
    folder the status line has not recorded, is never green, and how to
    switch the inventory (`files`: its report, store and key, absolute) to
    its folder, else to `here`, the current folder (None: it cannot be
    read). None when `here` is in the project already, and never a folder
    that holds the home: its walk would read the whole home. Each folder
    and file is printed as `shown` maps it; the command for a folder printed
    otherwise is run in it, and one for a file printed otherwise is shown
    with a placeholder for each inventory path."""
    project = "none" if inputs.project is None else shown[inputs.project]
    target = here if folder is None else folder
    lines = [
        "",
        f"project: {shown[folder]} is not the inventoried project ({project}),"
        " so keys in its files are not known"
        if folder is not None else
        "project: the session's project folder is not known yet (the status line records it"
        f" on its first refresh), so it is not known to be the inventoried project ({project})",
    ]
    if target is None:
        return [*lines, "  no switch command: the current folder cannot be read"]
    if folder is None and inventoried(inputs.project, here):
        return lines
    name = shown[target]
    if holds_home(target, Path.home()):
        return [*lines, f"  no switch command: {name} is or holds your home, and walking it"
                        " as the project would read the whole home"]
    switch_to = "this folder" if folder is not None else f"the current folder, {name}"
    if any(shown[path] != path for path in files):
        report, store, key = (f"<the inventory's {part}>" for part in ("report", "store", "key"))
        how = [
            "  no switch command shown: a path in it holds part of a key, reads like one, or holds"
            f" a character the report does not print. To switch the inventory to {switch_to}, run"
            " this in it from the shell Claude Code starts from, with the inventory's own paths in"
            " place of the <...> parts:",
            f"    {inventory_command('.', report, store, key)}",
        ]
    else:
        report, store, key = (shlex.quote(path) for path in files)
        withheld = name != target
        how = [
            f"  to switch the inventory to {switch_to}, run{' in it' if withheld else ''} from"
            " the shell Claude Code starts from:",
            f"    {inventory_command('.' if withheld else target, report, store, key)}",
        ]
    return [
        *lines, *how,
        *([] if inputs.project is None
          else ["  the earlier project's keys then stop being counted"]),
    ]


def report_lines(
    inputs: Inputs, transcript: str, session_id: str, folder: str | None, here: str | None,
    files: Sequence[Path], claude_config_dirs: Sequence[str],
) -> list[str]:
    """The report for one session, whose project folder is `folder` (None:
    unknown), run in the folder `here` (None: it cannot be read) with the
    inventory `files` (its report, store and key). Raises `AuditInputError` on a file the audit
    refuses (a FIFO in the session's directory, say)."""
    paths = [transcript]
    if os.path.isdir(os.path.join(os.path.dirname(transcript), session_id)):
        paths.append(os.path.join(os.path.dirname(transcript), session_id))
    inside = inventoried(inputs.project, folder)
    given = [str(path.absolute()) for path in files]
    named = [] if inside else [
        n for n in (inputs.project, folder, here, *given) if n is not None
    ]
    report, printed = audit_naming(
        inputs.credentials, inputs.key, inputs.by_fingerprint, paths, claude_config_dirs, named
    )
    shown_names = dict(zip(named, printed, strict=True))
    found = tally(report)
    groups = value_groups(inputs)
    context, sent = counted(found, inputs)
    lines = [
        segment_text(context, sent, unknown=found.unknown, inventoried=inside, pointer=False)
        if inputs.by_fingerprint else note(NOTHING_TO_CHECK, colour=False)
    ]
    shown = next((f.file for f in report.files if f.file == transcript), "[withheld]")
    lines.append(f"session: {shown} ({plural(report.coverage.files, 'file')} read)")
    turns = read_turns(transcript)
    by_credential: dict[str, list[Hit]] = {}
    for hit in report.hits:
        by_credential.setdefault(hit.credential, []).append(hit)
    # One block per value, the records that hold it together, in the audit's order.
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
    if not inside:
        lines.extend(_not_inventoried(inputs, folder, here, given, shown_names))
    return lines
