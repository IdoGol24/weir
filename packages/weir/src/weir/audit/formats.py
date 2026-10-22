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
from collections.abc import Iterator
from dataclasses import dataclass

from weir.audit._types import Format, Kind
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


def is_otlp(obj: Json) -> bool:
    """An OTLP/JSON export request (docs/canary.md, "The capture")."""
    return isinstance(obj, dict) and any(
        key in obj for key in ("resourceSpans", "resourceLogs", "resourceMetrics")
    )


def recognise(path: str, data: bytes, lines: list[Line]) -> Format:
    if any(line.parsed is not None and _is_claude_code(line.parsed) for line in lines):
        return Format.CLAUDE_CODE
    if os.path.basename(os.path.dirname(path)) == "tool-results":
        return Format.CLAUDE_CODE_TOOL_RESULTS
    if any(is_otlp(line.parsed) for line in lines):
        return Format.OTLP
    if whole_otlp(data) is not None:
        return Format.OTLP
    return Format.UNKNOWN


def whole_otlp(data: bytes) -> dict[str, Json] | None:
    """A whole file that is one export request (pretty-printed, say)."""
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
RECOGNISED_TYPES = _MESSAGE_TYPES | _STORED_TYPES
_USER_BLOCKS = frozenset({"text", "image", "document", "tool_result"})
_ASSISTANT_BLOCKS = frozenset({"text", "thinking", "redacted_thinking"})
_TOOL_BLOCKS = frozenset({"tool_use", "server_tool_use"})

_CONTEXT = Place(Kind.CONTEXT)
_STORED = Place(Kind.STORED)
_UNKNOWN = Place(Kind.UNKNOWN)


def _str(value: Json) -> str | None:
    return value if isinstance(value, str) else None


def _content_place(
    record_type: str, content: Json, path: Path_, tools: dict[str, str]
) -> Place:
    if isinstance(content, str):
        return _CONTEXT
    if len(path) < 3 or not isinstance(path[2], int) or not isinstance(content, list):
        return _STORED
    block = content[path[2]]
    btype = block.get("type") if isinstance(block, dict) else None
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
    if not isinstance(record_type, str) or record_type not in RECOGNISED_TYPES:
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
        if isinstance(block, dict) and block.get("type") in _TOOL_BLOCKS:
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
_TOOL_NAME = "gen_ai.tool.name"


def _attribute_index(location: Path_) -> int | None:
    for index in range(1, len(location)):
        if location[index] in _GENAI and location[index - 1] == "attributes":
            return index
    return None


def _otlp_place(attribute: str, doc: Json, sub: Path_, tool: str | None) -> Place:
    if attribute == _ARGUMENTS:
        return Place(Kind.TOOL_CALL, tool=tool, argument=sub or None)
    if attribute == _RESULT:
        return Place(Kind.CONTEXT, tool=tool)
    if attribute == _OUTPUT and len(sub) >= 4 and sub[1] == "parts" and sub[3] == "arguments":
        message = doc[sub[0]] if isinstance(doc, list) and isinstance(sub[0], int) else None
        parts = message.get("parts") if isinstance(message, dict) else None
        part = parts[sub[2]] if isinstance(parts, list) and isinstance(sub[2], int) else None
        if isinstance(part, dict) and part.get("type") == "tool_call":
            return Place(Kind.TOOL_CALL, tool=_str(part.get("name")), argument=sub[4:] or None)
    return _CONTEXT


def _json_document(text: str) -> Json:
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        value: Json = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def otlp_sites(request: dict[str, Json]) -> list[Site]:
    """The sites of one export request."""
    walk = walk_request(request)
    assert walk is not None
    tools: dict[Record, str] = {}
    for site in walk.sites:
        if site.record is not None and site.location == ("attributes", _TOOL_NAME):
            name = _text(site.data)
            if name != _TOOL_NAME:
                tools[site.record] = name
    out: list[Site] = []
    for site in walk.sites:
        string = _text(site.data)
        index = _attribute_index(site.location) if site.record is not None else None
        if index is None:
            out.append(Site(string, site.location, _UNKNOWN, otlp=site.record))
            continue
        attribute = str(site.location[index])
        tool = tools.get(site.record) if site.record is not None else None
        sub = site.location[index + 1 :]
        doc = _json_document(string) if not sub else None
        if doc is None:
            out.append(Site(string, site.location, _otlp_place(attribute, None, sub, tool),
                            otlp=site.record))
            continue
        for inner, path in strings(doc):
            out.append(Site(inner, (*site.location, *path),
                            _otlp_place(attribute, doc, path, tool), otlp=site.record))
    return out

