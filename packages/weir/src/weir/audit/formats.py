"""Reading the files the audit is given (docs/audit.md, "Files and formats"
and "What a hit means").

A file's format is recognised from its bytes and its path. Each format
turns its records into **sites**: a string to search, its location, and
the **place** that decides a hit's kind (and the tool and argument of a
tool call). Classification is by record type and location only; the
strings themselves never decide where a hit is.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import PurePath

from weir.audit._types import Format, Kind
from weir.canary import Signal
from weir.canary.walk import Json, Record, Segment, walk_request

Path_ = tuple[Segment, ...]


@dataclass(frozen=True)
class Place:
    kind: Kind
    tool: str | None = None
    argument: Path_ | None = None


@dataclass(frozen=True)
class Site:
    string: str
    location: Path_ | None
    place: Place
    # A Claude Code record's `type` (any JSON value, printed only if a string)
    record_type: str | None = None
    otlp: Record | None = None
    # The OTLP signal a string sits under, a resource or scope string included
    signal: Signal | None = None


@dataclass
class Line:
    """One line of a JSON Lines file: its 1-based number, and the parsed
    object, or None when the line is not a JSON object."""

    number: int
    text: str
    parsed: dict[str, Json] | None


def _text(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def json_lines(data: bytes) -> list[Line]:
    """Split at `\\n`. A last line without its `\\n` is a line when it parses;
    otherwise it is a truncated line, unparsed."""
    chunks = data.split(b"\n")
    if chunks and chunks[-1] == b"":
        chunks.pop()
    lines: list[Line] = []
    for number, chunk in enumerate(chunks, 1):
        text = _text(chunk)
        parsed: Json = None
        try:
            parsed = json.loads(text.removesuffix("\r"))
        except (ValueError, RecursionError):
            parsed = None
        lines.append(Line(number, text, parsed if isinstance(parsed, dict) else None))
    return lines


def strings(node: Json, path: Path_ = ()) -> Iterator[tuple[str, Path_]]:
    """Every string value and object key, with its location. Iterative: a
    record can nest deeper than Python's stack."""
    stack: list[tuple[Json, Path_]] = [(node, path)]
    while stack:
        node, path = stack.pop()
        if isinstance(node, str):
            yield node, path
        elif isinstance(node, list):
            stack.extend((item, (*path, index)) for index, item in enumerate(node))
        elif isinstance(node, dict):
            for key, child in node.items():
                here = (*path, key)
                yield key, here
                stack.append((child, here))


def text_sites(text: str, place: Place) -> Iterator[tuple[int, Site]]:
    """A text file: each line, with no location."""
    for number, line in enumerate(text.split("\n"), 1):
        line = line.removesuffix("\r")
        if line:
            yield number, Site(line, None, place)


def unparsed_sites(line: Line, place: Place) -> Iterator[Site]:
    """An unparsed line or a line of an unknown file: a JSON value is walked
    as one, anything else is searched as text."""
    try:
        value: Json = json.loads(line.text)
    except (ValueError, RecursionError):
        value = None
    if isinstance(value, (dict, list)):
        for string, path in strings(value):
            yield Site(string, path, place)
    elif line.text.removesuffix("\r"):
        yield Site(line.text.removesuffix("\r"), None, place)


# --- recognising a format ----------------------------------------------------


def _is_claude_code(obj: dict[str, Json]) -> bool:
    return obj.get("type") in ("user", "assistant") and isinstance(obj.get("sessionId"), str)


def _in_claude_projects(where: PurePath, projects_dirs: Sequence[PurePath]) -> bool:
    """Inside a `.claude/projects` directory, or inside the `projects`
    directory of a Claude config directory given with `--claude-config-dir`."""
    if (".claude", "projects") in pairwise(where.parent.parts):
        return True
    return any(where.is_relative_to(projects) for projects in projects_dirs)


def _is_session(where: PurePath, lines: list[Line], projects_dirs: Sequence[PurePath]) -> bool:
    """A record with a session id, or, inside a Claude Code projects
    directory, records whose types are all bookkeeping types."""
    records = [line.parsed for line in lines if line.parsed is not None]
    if any(_is_claude_code(record) for record in records):
        return True
    return (
        bool(records) and all(_str(r.get("type")) in _BOOKKEEPING_TYPES for r in records)
        and _in_claude_projects(where, projects_dirs)
    )


_SIGNAL_LISTS = frozenset({"resourceSpans", "resourceLogs", "resourceMetrics"})


def is_otlp(obj: Json) -> bool:
    """An OTLP/JSON export request (docs/canary.md, "The capture")."""
    return isinstance(obj, dict) and any(key in obj for key in _SIGNAL_LISTS)


def _is_claude_code_memory(path: PurePath) -> bool:
    """A CLAUDE.md file, or a memory file `projects/<project>/memory/*.md`."""
    if path.name == "CLAUDE.md":
        return True
    parts = path.parts
    return (
        path.suffix == ".md" and path.parent.name == "memory"
        and len(parts) >= 4 and parts[-4] == "projects"
    )


def recognise(
    path: str, data: bytes, lines: list[Line], projects_dirs: Sequence[PurePath] = ()
) -> Format:
    """`projects_dirs`: the `projects` directories of the Claude config
    directories given, as absolute paths."""
    where = PurePath(os.path.abspath(path))
    if _is_session(where, lines, projects_dirs):
        return Format.CLAUDE_CODE
    if where.parent.name == "tool-results":
        return Format.CLAUDE_CODE_TOOL_RESULTS
    if _is_claude_code_memory(where):
        return Format.CLAUDE_CODE_MEMORY
    if where.parent.name == "subagents" and where.name.endswith(".meta.json"):
        return Format.CLAUDE_CODE_SUBAGENT_META
    if any(is_otlp(line.parsed) for line in lines):
        return Format.OTLP
    if whole_otlp(data, lines) is not None:
        return Format.OTLP
    return Format.UNKNOWN


def whole_otlp(data: bytes, lines: list[Line]) -> dict[str, Json] | None:
    """A whole file that is one export request (pretty-printed, say), when
    no line is an export request of its own."""
    if any(is_otlp(line.parsed) for line in lines):
        return None
    try:
        value: Json = json.loads(_text(data))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) and is_otlp(value) else None


# --- Claude Code session files ----------------------------------------------

_STORED_TYPES = frozenset({
    "queue-operation", "last-prompt", "cost-state", "atis-latch", "file-history-snapshot",
    "custom-title", "agent-name", "tag", "permission-mode", "pr-link", "worktree-state",
})
_MESSAGE_TYPES = frozenset({"user", "assistant", "attachment", "summary"})
# The types of a file of bookkeeping records beside a session, with no session id
_BOOKKEEPING_TYPES = _STORED_TYPES | {"summary"}
_RECOGNISED_TYPES = _MESSAGE_TYPES | _STORED_TYPES
_USER_BLOCKS = frozenset({"text", "image", "document", "tool_result"})
_ASSISTANT_BLOCKS = frozenset({"text", "thinking", "redacted_thinking"})
_TOOL_BLOCKS = frozenset({"tool_use", "server_tool_use"})

_CONTEXT = Place(Kind.CONTEXT)
_STORED = Place(Kind.STORED)
_UNKNOWN = Place(Kind.UNKNOWN)


def _str(value: Json) -> str | None:
    return value if isinstance(value, str) else None


# docs/audit.md, "Claude Code session files": the keys of the sidecar Claude
# Code keeps beside a subagent's transcript. Bookkeeping: none of it is sent
# to the model as it is written there.
_SUBAGENT_META_KEYS = frozenset({
    "agentType", "description", "finished", "launchedWithDefaults", "requestNonInteractive",
    "requestShape", "spawnDepth", "toolUseId",
})


def subagent_meta_sites(meta: dict[str, Json]) -> Iterator[Site]:
    """A subagent sidecar: stored under its known keys, unknown under any other."""
    for string, path in strings(meta):
        known = path[0] in _SUBAGENT_META_KEYS
        yield Site(string, path, _STORED if known else _UNKNOWN)


def whole_json(data: bytes) -> dict[str, Json] | None:
    """A whole file that is one JSON object."""
    try:
        value: Json = json.loads(_text(data))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def recognised(record: dict[str, Json]) -> bool:
    """A record whose `type` is one the Claude Code table names."""
    return _str(record.get("type")) in _RECOGNISED_TYPES


def _content_place(
    record_type: str, content: Json, path: Path_, tools: dict[str, str]
) -> Place:
    if isinstance(content, str):
        return _CONTEXT
    if len(path) < 3 or not isinstance(path[2], int) or not isinstance(content, list):
        return _STORED
    block = content[path[2]]
    btype = _str(block.get("type")) if isinstance(block, dict) else None
    if not isinstance(block, dict):
        return _UNKNOWN
    if record_type == "user" and btype in _USER_BLOCKS:
        tool = tools.get(_str(block.get("tool_use_id")) or "") if btype == "tool_result" else None
        return Place(Kind.CONTEXT, tool=tool)
    if record_type == "assistant" and btype in _ASSISTANT_BLOCKS:
        return _CONTEXT
    if record_type == "assistant" and btype in _TOOL_BLOCKS:
        name = _str(block.get("name"))
        if len(path) >= 4 and path[3] == "input":
            return Place(Kind.TOOL_CALL, tool=name, argument=path[4:] or None)
        return Place(Kind.CONTEXT, tool=name)
    return _UNKNOWN


def claude_code_place(record: dict[str, Json], path: Path_, tools: dict[str, str]) -> Place:
    """docs/audit.md, "Claude Code session files"."""
    record_type = record.get("type")
    if not isinstance(record_type, str) or record_type not in _RECOGNISED_TYPES:
        return _UNKNOWN
    if record_type in _STORED_TYPES:
        return _STORED
    if record_type == "attachment":
        if "rendered" not in record:
            return _UNKNOWN
        return _CONTEXT if path[:1] == ("rendered",) else _STORED
    if record_type == "summary":
        return _CONTEXT if path[:1] == ("summary",) else _STORED
    message = record.get("message")
    if path[:2] == ("message", "content") and isinstance(message, dict) and len(path) >= 2:
        content = message.get("content")
        if len(path) == 2 and not isinstance(content, str):
            return _STORED
        return _content_place(record_type, content, path, tools)
    return _STORED


def note_tools(record: dict[str, Json], tools: dict[str, str]) -> None:
    """Remember each tool_use's name by id, for the tool_result that follows."""
    if record.get("type") != "assistant":
        return
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return
    for block in content:
        if isinstance(block, dict) and _str(block.get("type")) in _TOOL_BLOCKS:
            tool_id, name = _str(block.get("id")), _str(block.get("name"))
            if tool_id is not None and name is not None:
                tools[tool_id] = name


def claude_code_sites(record: dict[str, Json], tools: dict[str, str]) -> Iterator[Site]:
    record_type = record.get("type")
    shown = record_type if isinstance(record_type, str) else None
    for string, path in strings(record):
        yield Site(string, path, claude_code_place(record, path, tools), record_type=shown)


# --- OTLP telemetry ------------------------------------------------------------

_ARGUMENTS = "gen_ai.tool.call.arguments"
_RESULT = "gen_ai.tool.call.result"
_OUTPUT = "gen_ai.output.messages"
_CONTEXT_ATTRIBUTES = frozenset({"gen_ai.input.messages", "gen_ai.system_instructions"})
_GENAI = frozenset({_ARGUMENTS, _RESULT, _OUTPUT}) | _CONTEXT_ATTRIBUTES
# Claude Code's own log events (`claude_code.tool_result`, `claude_code.user_prompt`)
_PARAMETERS = "tool_parameters"
_PROMPT = "prompt"
_LOG_ATTRIBUTES = _GENAI | {_PARAMETERS, _PROMPT}
# The attribute that names the tool of each attribute that has one
_TOOL_NAMES = {
    _ARGUMENTS: "gen_ai.tool.name", _RESULT: "gen_ai.tool.name", _PARAMETERS: "tool_name",
}

# The string at a location within an attribute's value, or None
Lookup = Callable[[Path_], str | None]


def _attribute_index(location: Path_, names: frozenset[str]) -> int | None:
    for index in range(1, len(location)):
        if location[index] in names and location[index - 1] == "attributes":
            return index
    return None


def _otlp_place(attribute: str, sub: Path_, tool: str | None, at: Lookup) -> Place:
    if attribute in (_ARGUMENTS, _PARAMETERS):
        return Place(Kind.TOOL_CALL, tool=tool, argument=sub or None)
    if attribute == _RESULT:
        return Place(Kind.CONTEXT, tool=tool)
    if (
        attribute == _OUTPUT and len(sub) >= 4 and isinstance(sub[0], int)
        and sub[1] == "parts" and isinstance(sub[2], int) and sub[3] == "arguments"
        and at((*sub[:3], "type")) == "tool_call"
    ):
        return Place(Kind.TOOL_CALL, tool=at((*sub[:3], "name")), argument=sub[4:] or None)
    return _CONTEXT


def _json_document(text: str) -> Json:
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        value: Json = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _in_document(doc: Json) -> Lookup:
    def at(path: Path_) -> str | None:
        node = doc
        for segment in path:
            if isinstance(node, list) and isinstance(segment, int) and segment < len(node):
                node = node[segment]
            elif isinstance(node, dict) and isinstance(segment, str):
                node = node.get(segment)
            else:
                return None
        return _str(node)

    return at


def otlp_sites(request: dict[str, Json]) -> list[Site]:
    """The sites of one export request."""
    walk = walk_request(request)
    assert walk is not None
    # The strings a place is read from: a tool's name, a message part's
    # `type` and `name`. A key-value's key comes before its value, so the
    # last string at a location is its value, or the key when there is none.
    named: dict[tuple[Record, Path_], str] = {}
    for site in walk.sites:
        if site.record is not None and site.location and site.location[-1] in (
            "type", "name", *_TOOL_NAMES.values()
        ):
            named[(site.record, site.location)] = _text(site.data)

    def in_record(record: Record, location: Path_) -> str | None:
        value = named.get((record, location))
        return value if value != location[-1] else None

    def in_value(record: Record, head: Path_) -> Lookup:
        return lambda path: in_record(record, (*head, *path))

    out: list[Site] = []
    for site in walk.sites:
        string = _text(site.data)
        record, signal = site.record, site.signal
        names = _LOG_ATTRIBUTES if signal is Signal.LOGS else _GENAI
        index = _attribute_index(site.location, names) if record is not None else None
        if record is None or index is None:
            out.append(Site(string, site.location, _UNKNOWN, otlp=record, signal=signal))
            continue
        attribute = str(site.location[index])
        tool_name = _TOOL_NAMES.get(attribute)
        tool = in_record(record, ("attributes", tool_name)) if tool_name else None
        head, sub = site.location[: index + 1], site.location[index + 1 :]
        doc = _json_document(string) if not sub else None
        if doc is None:
            pieces = [(string, sub, _otlp_place(attribute, sub, tool, in_value(record, head)))]
        else:
            at = _in_document(doc)
            pieces = [(inner, path, _otlp_place(attribute, path, tool, at))
                      for inner, path in strings(doc)]
        for inner, path, place in pieces:
            in_part = place.kind is Kind.TOOL_CALL and attribute == _OUTPUT
            arguments = _json_document(inner) if in_part else None
            if arguments is None:
                out.append(Site(inner, (*head, *path), place, otlp=record, signal=signal))
                continue
            # A tool_call part's arguments written as a JSON string: walk it,
            # so `argument` is the location within the arguments.
            for leaf, within in strings(arguments):
                argument = (*path[4:], *within)
                deeper = Place(Kind.TOOL_CALL, tool=place.tool, argument=argument)
                location = (*head, *path, *within)
                out.append(Site(leaf, location, deeper, otlp=record, signal=signal))
    # The members the structured walk leaves out: searched, kind unknown.
    rest = {key: value for key, value in request.items() if key not in _SIGNAL_LISTS}
    out.extend(Site(string, path, _UNKNOWN) for string, path in strings(rest))
    return out
