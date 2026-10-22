"""A Claude-shaped probe flow for the Anthropic Messages tests: plain
urllib against ANTHROPIC_BASE_URL, the way the Anthropic SDKs and Claude
Code reach the API, with ANTHROPIC_API_KEY in the `x-api-key` header.

Every mode runs one coding-task turn. The first request offers a
`read_file` tool, which the scripted model calls; the flow answers with a
tool_result, streams the final reply and exports one clean span, so the
telemetry capture is not empty. MODE decides what else the conversation
holds:

- `own`: nothing more; the key is only in `x-api-key`;
- `tool-result`: the tool result holds ANTHROPIC_API_KEY, as a read of a
  project `.env` would;
- `prompt`: the user's message holds ANTHROPIC_API_KEY.

It writes the key to SIDE_FILE so the test can check the output against
it, and exits non-zero if a reply breaks the Messages API shape.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

MODEL = "claude-probe"
READ_FILE = {
    "name": "read_file",
    "description": "Read a file in the project.",
    "input_schema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}


def export_span() -> None:
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "claude turn"}]}]}]}
    request = urllib.request.Request(
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def post(key: str, body: dict[str, Any]) -> bytes:
    request = urllib.request.Request(
        os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages",
        data=json.dumps(body).encode(),
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def streamed(body: bytes) -> tuple[str, str | None]:
    """The text and stop reason of a Messages event stream."""
    text, stop = "", None
    for block in body.decode().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "data" not in fields:
            continue
        data = json.loads(fields["data"])
        if fields.get("event") != data["type"]:
            raise SystemExit("an event's name is not its data's type")
        if data["type"] == "content_block_delta" and data["delta"]["type"] == "text_delta":
            text += data["delta"]["text"]
        elif data["type"] == "message_delta":
            stop = data["delta"]["stop_reason"]
    return text, stop


def main() -> None:
    key = os.environ["ANTHROPIC_API_KEY"]
    with open(os.environ["SIDE_FILE"], "w", encoding="utf-8") as side:
        json.dump([key], side)
    mode = os.environ["MODE"]
    if mode not in ("own", "tool-result", "prompt"):
        raise SystemExit(f"unknown MODE {mode!r}")

    prompt = "Which log level does the project's .env set?"
    if mode == "prompt":
        prompt += f" My key is {key}."
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    turn = {"model": MODEL, "max_tokens": 256, "tools": [READ_FILE]}

    first = json.loads(post(key, {**turn, "messages": messages}))
    uses = [b for b in first["content"] if b["type"] == "tool_use"]
    if first["stop_reason"] != "tool_use" or [u["name"] for u in uses] != ["read_file"]:
        raise SystemExit("expected the model to call read_file")
    contents = "LOG_LEVEL=info\n"
    if mode == "tool-result":
        contents += f"ANTHROPIC_API_KEY={key}\n"
    messages += [
        {"role": "assistant", "content": first["content"]},
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": uses[0]["id"], "content": contents}],
        },
    ]

    text, stop = streamed(post(key, {**turn, "messages": messages, "stream": True}))
    if stop != "end_turn" or not text:
        raise SystemExit("expected a final text reply")
    export_span()
    print(text)


if __name__ == "__main__":
    main()
