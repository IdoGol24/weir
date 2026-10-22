"""The mock's model API, scripted.

OpenAI-compatible Chat Completions (plain and streaming), Responses (plain
and streaming), Embeddings and Models, and the Anthropic Messages API
(plain and streaming), served under `{mock}/v1`. No model decides
anything: with `tool_calls = "each-offered-tool-once"` the first turn
calls every offered tool once with a minimal schema-valid argument, so the
program exercises each tool's credentials, and once tool results are in
the conversation the reply is the configured text. Timestamps are fixed
constants; the runner never reads the wall clock.
"""

from __future__ import annotations

import base64
import itertools
import json
import re
import struct
import threading
from collections.abc import Sequence
from typing import Any, cast

from weir_run.spec import ScriptStep

CREATED = 1_700_000_000
# A scripted step's tool_use id names its step, so the script needs no
# state between requests: the conversation says how far it has got.
_STEP_ID = re.compile(r"toolu_mock_step(\d+)_\d+")
MODEL = "mock-model"
EMBEDDING_DIMENSIONS = 8

type Json = dict[str, Any]


def _obj(value: object) -> Json:
    return cast(Json, value) if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return cast(list[Any], value) if isinstance(value, list) else []


def minimal(schema: object, defs: Json, depth: int = 0) -> object:
    """The smallest value a JSON Schema plausibly accepts."""
    node = _obj(schema)
    if depth > 8:
        return None
    ref = node.get("$ref")
    if isinstance(ref, str):
        name = ref.rsplit("/", 1)[-1]
        return minimal(defs.get(name, {}), defs, depth + 1)
    for key in ("default", "const"):
        if key in node:
            return node[key]
    enum = _list(node.get("enum"))
    if enum:
        return enum[0]
    for key in ("anyOf", "oneOf", "allOf"):
        options = [o for o in _list(node.get(key)) if _obj(o).get("type") != "null"]
        if options:
            return minimal(options[0], defs, depth + 1)
    kind = node.get("type")
    if isinstance(kind, list):
        kinds = [k for k in cast(list[object], kind) if k != "null"]
        kind = kinds[0] if kinds else "null"
    if kind is None:
        kind = "object" if "properties" in node else "string"
    if kind == "object":
        props = _obj(node.get("properties"))
        return {
            k: minimal(props.get(k, {}), defs, depth + 1)
            for k in _list(node.get("required"))
            if isinstance(k, str)
        }
    if kind == "array":
        count = node.get("minItems", 0)
        count = count if isinstance(count, int) else 0
        return [minimal(node.get("items", {}), defs, depth + 1) for _ in range(count)]
    if kind in ("integer", "number"):
        low = node.get("minimum", 1)
        return low if isinstance(low, int | float) else 1
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    fmt = node.get("format")
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "email":
        return "user@localhost"
    if fmt in ("uri", "url"):
        return "http://127.0.0.1/"
    length = node.get("minLength", 1)
    return "a" * (length if isinstance(length, int) and length > 0 else 1)


def _input(parameters: object) -> object:
    schema = _obj(parameters)
    defs = {**_obj(schema.get("definitions")), **_obj(schema.get("$defs"))}
    return minimal(schema, defs) if schema else {}


def _arguments(parameters: object) -> str:
    return json.dumps(_input(parameters))


def _sse(events: list[tuple[str | None, object]]) -> bytes:
    out: list[str] = []
    for name, data in events:
        if name is not None:
            out.append(f"event: {name}\n")
        payload = data if isinstance(data, str) else json.dumps(data)
        out.append(f"data: {payload}\n\n")
    return "".join(out).encode()


class ModelApi:
    def __init__(self, reply: str, tool_calls: str, script: Sequence[ScriptStep] = ()) -> None:
        self.reply = reply
        self.call_tools = tool_calls == "each-offered-tool-once"
        self.script = tuple(script)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def _next(self) -> int:
        with self._lock:
            return next(self._ids)

    # -- Chat Completions ----------------------------------------------

    def chat(self, request: Json) -> tuple[bytes, str]:
        n = self._next()
        model = request.get("model") if isinstance(request.get("model"), str) else MODEL
        messages = [_obj(m) for m in _list(request.get("messages"))]
        last_user = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
        answered = any(m.get("role") == "tool" for m in messages[last_user + 1 :])
        tools = [
            _obj(_obj(t).get("function"))
            for t in _list(request.get("tools"))
            if _obj(t).get("type", "function") == "function"
        ]
        calls: list[Json] = []
        if self.call_tools and tools and not answered and request.get("tool_choice") != "none":
            calls = [
                {
                    "id": f"call_{n}_{i}",
                    "type": "function",
                    "function": {
                        "name": str(t.get("name", "")),
                        "arguments": _arguments(t.get("parameters")),
                    },
                }
                for i, t in enumerate(tools)
            ]
        finish = "tool_calls" if calls else "stop"
        base: Json = {"id": f"chatcmpl-mock-{n}", "created": CREATED, "model": model}
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        if not request.get("stream"):
            message: Json = {"role": "assistant", "content": None if calls else self.reply}
            if calls:
                message["tool_calls"] = calls
            body = {
                **base,
                "object": "chat.completion",
                "choices": [
                    {"index": 0, "message": message, "finish_reason": finish, "logprobs": None}
                ],
                "usage": usage,
            }
            return json.dumps(body).encode(), "application/json"
        chunk = {**base, "object": "chat.completion.chunk"}

        def delta(d: Json, finish_reason: str | None = None) -> Json:
            choice = {"index": 0, "delta": d, "finish_reason": finish_reason, "logprobs": None}
            return {**chunk, "choices": [choice]}

        events: list[tuple[str | None, object]] = [
            (None, delta({"role": "assistant", "content": ""}))
        ]
        if calls:
            events += [
                (None, delta({"tool_calls": [{"index": i, **c}]})) for i, c in enumerate(calls)
            ]
        else:
            events.append((None, delta({"content": self.reply})))
        events.append((None, delta({}, finish)))
        if _obj(request.get("stream_options")).get("include_usage"):
            events.append((None, {**chunk, "choices": [], "usage": usage}))
        events.append((None, "[DONE]"))
        return _sse(events), "text/event-stream"

    # -- Responses -----------------------------------------------------

    def responses(self, request: Json) -> tuple[bytes, str]:
        n = self._next()
        model = request.get("model") if isinstance(request.get("model"), str) else MODEL
        items = [_obj(i) for i in _list(request.get("input"))]
        last_user = max((i for i, m in enumerate(items) if m.get("role") == "user"), default=-1)
        answered = any(i.get("type") == "function_call_output" for i in items[last_user + 1 :])
        tools = [_obj(t) for t in _list(request.get("tools")) if _obj(t).get("type") == "function"]
        output: list[Json]
        if self.call_tools and tools and not answered and request.get("tool_choice") != "none":
            output = [
                {
                    "type": "function_call",
                    "id": f"fc_{n}_{i}",
                    "call_id": f"call_{n}_{i}",
                    "name": str(t.get("name", "")),
                    "arguments": _arguments(t.get("parameters")),
                    "status": "completed",
                }
                for i, t in enumerate(tools)
            ]
        else:
            output = [
                {
                    "type": "message",
                    "id": f"msg_{n}",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": self.reply, "annotations": []}],
                }
            ]
        response: Json = {
            "id": f"resp_mock_{n}",
            "object": "response",
            "created_at": CREATED,
            "status": "completed",
            "model": model,
            "output": output,
            "parallel_tool_calls": True,
            "tool_choice": request.get("tool_choice", "auto"),
            "tools": request.get("tools", []),
            "usage": {
                "input_tokens": 1,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 1,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 2,
            },
        }
        if not request.get("stream"):
            return json.dumps(response).encode(), "application/json"
        events: list[tuple[str | None, object]] = []

        def emit(kind: str, **fields: object) -> None:
            events.append((kind, {"type": kind, "sequence_number": len(events), **fields}))

        emit("response.created", response={**response, "status": "in_progress", "output": []})
        for index, item in enumerate(output):
            if item["type"] == "function_call":
                emit(
                    "response.output_item.added", output_index=index, item={**item, "arguments": ""}
                )
                emit(
                    "response.function_call_arguments.delta",
                    output_index=index,
                    item_id=item["id"],
                    delta=item["arguments"],
                )
                emit(
                    "response.function_call_arguments.done",
                    output_index=index,
                    item_id=item["id"],
                    arguments=item["arguments"],
                )
            else:
                emit(
                    "response.output_item.added",
                    output_index=index,
                    item={**item, "status": "in_progress", "content": []},
                )
                part: Json = {"type": "output_text", "text": "", "annotations": []}
                ids: Json = {"output_index": index, "item_id": item["id"], "content_index": 0}
                emit("response.content_part.added", **ids, part=part)
                emit("response.output_text.delta", **ids, delta=self.reply)
                emit("response.output_text.done", **ids, text=self.reply)
                emit("response.content_part.done", **ids, part={**part, "text": self.reply})
            emit("response.output_item.done", output_index=index, item=item)
        emit("response.completed", response=response)
        return _sse(events), "text/event-stream"

    # -- Anthropic Messages --------------------------------------------

    def messages(self, request: Json) -> tuple[bytes, str]:
        n = self._next()
        model = request.get("model") if isinstance(request.get("model"), str) else MODEL
        messages = [_obj(m) for m in _list(request.get("messages"))]

        def answers(message: Json) -> bool:
            return any(_obj(b).get("type") == "tool_result" for b in _list(message.get("content")))

        # Tool results come back in a user message, so a turn starts at the
        # last user message that answers no tool call.
        last_user = max(
            (i for i, m in enumerate(messages) if m.get("role") == "user" and not answers(m)),
            default=-1,
        )
        answered = any(answers(m) for m in messages[last_user + 1 :])
        # Only the program's own tools: a server tool has a versioned type.
        tools = [
            _obj(t)
            for t in _list(request.get("tools"))
            if _obj(t).get("type", "custom") == "custom"
        ]
        choice = _obj(request.get("tool_choice")).get("type")
        content: list[Json]
        if self.script:
            step = self._next_step(messages, tools) if choice != "none" else None
            if step is None:
                content = [{"type": "text", "text": self.reply}]
            else:
                index, chosen = step
                content = [
                    {
                        "type": "tool_use",
                        "id": f"toolu_mock_step{index}_{n}",
                        "name": chosen.tool,
                        "input": dict(chosen.input),
                    }
                ]
        elif self.call_tools and tools and not answered and choice != "none":
            content = []
            for i, t in enumerate(tools):
                value = _input(t.get("input_schema"))
                content.append(
                    {
                        "type": "tool_use",
                        "id": f"toolu_mock_{n}_{i}",
                        "name": str(t.get("name", "")),
                        "input": value if isinstance(value, dict) else {},
                    }
                )
        else:
            content = [{"type": "text", "text": self.reply}]
        stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        usage = {"input_tokens": 1, "output_tokens": 1}
        message: Json = {
            "id": f"msg_mock_{n}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": content,
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": usage,
        }
        if not request.get("stream"):
            return json.dumps(message).encode(), "application/json"
        events: list[tuple[str | None, object]] = []

        def emit(kind: str, **fields: object) -> None:
            events.append((kind, {"type": kind, **fields}))

        emit("message_start", message={**message, "content": [], "stop_reason": None})
        emit("ping")
        for index, block in enumerate(content):
            if block["type"] == "tool_use":
                start: Json = {**block, "input": {}}
                delta: Json = {
                    "type": "input_json_delta",
                    "partial_json": json.dumps(block["input"]),
                }
            else:
                start = {"type": "text", "text": ""}
                delta = {"type": "text_delta", "text": block["text"]}
            emit("content_block_start", index=index, content_block=start)
            emit("content_block_delta", index=index, delta=delta)
            emit("content_block_stop", index=index)
        emit("message_delta", delta={"stop_reason": stop, "stop_sequence": None}, usage=usage)
        emit("message_stop")
        return _sse(events), "text/event-stream"

    def _next_step(self, messages: list[Json], tools: list[Json]) -> tuple[int, ScriptStep] | None:
        """The first step after the last one the conversation already asked
        for whose tool is offered. A step whose tool is not offered is
        skipped: the program does not have it, so it is never asked."""
        asked = -1
        for message in messages:
            if message.get("role") != "assistant":
                continue
            for block in _list(message.get("content")):
                match = _STEP_ID.fullmatch(str(_obj(block).get("id", "")))
                if _obj(block).get("type") == "tool_use" and match:
                    asked = max(asked, int(match.group(1)))
        offered = {str(t.get("name", "")) for t in tools}
        for index in range(asked + 1, len(self.script)):
            if self.script[index].tool in offered:
                return index, self.script[index]
        return None

    # -- Embeddings and Models -----------------------------------------

    def embeddings(self, request: Json) -> tuple[bytes, str]:
        raw = request.get("input", "")
        inputs = cast(list[Any], raw) if isinstance(raw, list) else [raw]
        as_base64 = request.get("encoding_format") == "base64"
        data: list[Json] = []
        for i, _ in enumerate(inputs):
            vector = [round(0.1 * (i + 1), 1)] * EMBEDDING_DIMENSIONS
            embedding: object = (
                base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode()
                if as_base64
                else vector
            )
            data.append({"object": "embedding", "index": i, "embedding": embedding})
        model = request.get("model") if isinstance(request.get("model"), str) else MODEL
        body = {
            "object": "list",
            "data": data,
            "model": model,
            "usage": {"prompt_tokens": 1, "total_tokens": 1},
        }
        return json.dumps(body).encode(), "application/json"

    def model(self, name: str) -> tuple[bytes, str]:
        body = {"id": name, "object": "model", "created": CREATED, "owned_by": "mock"}
        return json.dumps(body).encode(), "application/json"

    def models(self) -> tuple[bytes, str]:
        body = {"object": "list", "data": [json.loads(self.model(MODEL)[0])]}
        return json.dumps(body).encode(), "application/json"
