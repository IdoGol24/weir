"""A permission prompt the program asks instead of a person: a Model
Context Protocol server, over HTTP, with one tool that answers no.

A program run headless that would ask its user before a tool call can be
told to ask a tool instead (Claude Code's `--permission-prompt-tool`). This
endpoint is that tool. It answers every request with a denial and keeps
each one, so the run can tell a call the user's rules denied from one the
user would have been asked about: only the second reaches the prompt.

It speaks the protocol's streamable HTTP transport with JSON replies only:
`initialize`, `ping`, `tools/list` and `tools/call` as JSON-RPC requests,
notifications acknowledged with 202, batches answered as batches. A GET for
a server-sent event stream is refused with 405, which the transport allows.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, cast

TOOL = "prompt"
PROTOCOL_VERSION = "2025-06-18"
DENIAL = "The check answered no: a person would have been asked to allow this."
_SCHEMA = {
    "type": "object",
    "properties": {
        "tool_name": {"type": "string"},
        "input": {"type": "object"},
        "tool_use_id": {"type": "string"},
    },
    "required": ["tool_name", "input"],
}

type Json = dict[str, Any]


@dataclass(frozen=True)
class Asked:
    """One permission request the program sent to the prompt."""

    tool_name: str
    tool_use_id: str
    input: Json


def _obj(value: object) -> Json:
    return cast(Json, value) if isinstance(value, dict) else {}


class PermissionPrompt:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._asked: list[Asked] = []

    @property
    def asked(self) -> list[Asked]:
        with self._lock:
            return list(self._asked)

    def handle(self, method: str, body: bytes) -> tuple[int, bytes, str]:
        """(status, body, content type) for one HTTP request."""
        if method != "POST":
            return 405, b"", "text/plain"
        try:
            doc: object = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, _encode(_error(None, -32700, "parse error")), "application/json"
        if isinstance(doc, list):
            replies = [r for r in (self._one(_obj(m)) for m in cast(list[object], doc)) if r]
            if not replies:
                return 202, b"", "text/plain"
            return 200, _encode(replies), "application/json"
        reply = self._one(_obj(doc))
        if reply is None:
            return 202, b"", "text/plain"
        return 200, _encode(reply), "application/json"

    def _one(self, message: Json) -> Json | None:
        """The reply to one JSON-RPC message; None for a notification or a
        response, which take none."""
        if "id" not in message or "method" not in message:
            return None
        request_id, method = message["id"], message["method"]
        params = _obj(message.get("params"))
        if method == "initialize":
            version = params.get("protocolVersion")
            return _result(
                request_id,
                {
                    "protocolVersion": version if isinstance(version, str) else PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "weir-run permission prompt", "version": "1"},
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            tool = {
                "name": TOOL,
                "description": "Answers a permission prompt.",
                "inputSchema": _SCHEMA,
            }
            return _result(request_id, {"tools": [tool]})
        if method == "tools/call":
            if params.get("name") != TOOL:
                return _error(request_id, -32602, "unknown tool")
            arguments = _obj(params.get("arguments"))
            asked = Asked(
                str(arguments.get("tool_name", "")),
                str(arguments.get("tool_use_id", "")),
                _obj(arguments.get("input")),
            )
            with self._lock:
                self._asked.append(asked)
            answer = json.dumps({"behavior": "deny", "message": DENIAL})
            return _result(request_id, {"content": [{"type": "text", "text": answer}]})
        return _error(request_id, -32601, "method not found")


def _result(request_id: object, result: Json) -> Json:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> Json:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _encode(doc: object) -> bytes:
    return json.dumps(doc).encode("utf-8")
