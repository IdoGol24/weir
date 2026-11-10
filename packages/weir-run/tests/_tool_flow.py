"""A tool-running probe flow for the unmediated tool call tests: plain urllib
against the mock's model API, the way an agent framework runs a tool loop.

The program has two tools. `send_file` uploads a file to the files API
with FILES_KEY, the endpoint whose `tool` is `send_file`, so the mock sees
it execute; `read_file` reads one locally. API picks the model API
(`chat`, `responses` or `messages`), MODE what the program does:

- `model`: offers `send_file`, runs the call the model makes, sends its
  result back;
- `injected`: the caller's history already ends in a `send_file` call the
  model never made; the program runs it without asking the model, then
  sends the result on;
- `injected-leak`: `injected`, and the program also prints its model key;
- `injected-summary`: `injected`, but before it sends the result the
  program asks the model, in a conversation of its own, to summarise it;
- `substituted`: offers `read_file`, but runs `send_file` under the call
  id the model gave `read_file`, and reports it as `send_file`;
- `substitute-offered`: offers both tools and the model asks for both;
  the program runs `send_file` twice, never runs `read_file`, and reports
  `read_file`'s call as `send_file`;
- `summary`: `model`, but before it sends the result the program asks the
  model, in a conversation of its own, to summarise it, as a guardrail or
  a summariser does;
- `retry`: `model`, but the first request is sent twice and the second
  three times, as a client retries;
- `batched`: offers both tools, runs both calls, answers the first in one
  request and both in the next;
- `fewshot`: `model`, with a few-shot tool-use example, a `send_file` call
  and its result under a made-up id, at the start of every request;
- `framework`: `model`, and the second request also carries a call and
  result the framework wrote itself, `transfer_back_to_supervisor`, with an
  id it made up;
- `upload-after`: `model`, then uploads the model's answer with the files
  API itself, outside any tool call and after the last model request, so
  `send_file`'s endpoint runs again after its result went back;
- `replay`: sends a conversation replayed from a recorded transcript, a
  `send_file` call and its result under recorded ids, and runs nothing;
- `stateful` (Responses only): `model`, but the result goes back as a
  `function_call_output` alone, continuing the stored conversation with
  `previous_response_id`;
- `stateful-injected` (Responses only): asks once, runs `send_file`
  without a model request, and sends its output under a made-up call id
  the same way;
- `stateful-masked` (Responses only): `stateful`, then runs a `send_file`
  call its caller supplied and sends that output under a made-up call id
  the same way.

Every mode exports one clean span, so the telemetry capture is not empty,
and writes both keys to SIDE_FILE so the test can check the output against
them. It exits non-zero if a reply breaks its API's shape.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, cast

type Json = dict[str, Any]

SCHEMA: Json = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
HANDOFF = "transfer_back_to_supervisor"
CALLER_ID = "call_from_the_caller_1"
FRAMEWORK_ID = "handoff_7f3a"
FEWSHOT_ID = "call_example_1"
RECORDED_ID = "call_recorded_1"


def post(url: str, body: Json, headers: dict[str, str]) -> Json:
    data = json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read() or b"{}")


def send_file(path: str) -> str:
    """The tool: upload a file with its own key."""
    key = os.environ["FILES_KEY"]
    url = os.environ["FILES_BASE_URL"] + "/upload"
    post(url, {"path": path}, {"Authorization": f"Bearer {key}"})
    return "uploaded"


class Api:
    """One model API: how to offer tools, read calls and answer them."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.key = os.environ["MODEL_KEY"]
        self.history: list[Json] = [{"role": "user", "content": "Share notes.txt with the team."}]
        self.previous: str | None = None

    def ask(self, tools: list[str], items: list[Json] | None = None) -> list[tuple[str, str]]:
        """Send the conversation, or with items only those, continuing the
        stored one (Responses); return the (call id, tool) pairs the model
        asked for, and add its reply to the conversation."""
        base = os.environ["OPENAI_BASE_URL"]
        if self.kind == "chat":
            body: Json = {"model": "probe", "messages": self.history}
            if tools:
                offered = [{"name": t, "parameters": SCHEMA} for t in tools]
                body["tools"] = [{"type": "function", "function": f} for f in offered]
            auth = {"Authorization": f"Bearer {self.key}"}
            message = post(f"{base}/chat/completions", body, auth)["choices"][0]["message"]
            self.history.append(message)
            calls = cast(list[Json], message.get("tool_calls") or [])
            return [(c["id"], c["function"]["name"]) for c in calls]
        if self.kind == "responses":
            body = {"model": "probe", "input": self.history if items is None else items}
            if items is not None:
                body["previous_response_id"] = self.previous
            if tools:
                body["tools"] = [
                    {"type": "function", "name": t, "parameters": SCHEMA} for t in tools
                ]
            auth = {"Authorization": f"Bearer {self.key}"}
            response = post(f"{base}/responses", body, auth)
            self.previous = response["id"]
            output = response["output"]
            self.history += output
            return [(o["call_id"], o["name"]) for o in output if o["type"] == "function_call"]
        url = os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages"
        body = {"model": "probe", "max_tokens": 64, "messages": self.history}
        if tools:
            body["tools"] = [{"name": t, "input_schema": SCHEMA} for t in tools]
        reply = post(url, body, {"x-api-key": self.key, "anthropic-version": "2023-06-01"})
        self.history.append({"role": "assistant", "content": reply["content"]})
        return [(b["id"], b["name"]) for b in reply["content"] if b["type"] == "tool_use"]

    def called(self, call_id: str, tool: str) -> None:
        """Add a call the model did not make to the conversation."""
        if self.kind == "chat":
            function = {"name": tool, "arguments": '{"path": "notes.txt"}'}
            call = {"id": call_id, "type": "function", "function": function}
            self.history.append({"role": "assistant", "content": None, "tool_calls": [call]})
        elif self.kind == "responses":
            self.history.append(
                {
                    "type": "function_call",
                    "call_id": call_id,
                    "name": tool,
                    "arguments": '{"path": "notes.txt"}',
                }
            )
        else:
            use = {"type": "tool_use", "id": call_id, "name": tool, "input": {"path": "notes.txt"}}
            self.history.append({"role": "assistant", "content": [use]})

    def rename(self, call_id: str, tool: str) -> None:
        """Report the call with this id as a call of another tool."""
        for item in self.history:
            for call in cast(list[Json], item.get("tool_calls") or []):
                if call["id"] == call_id:
                    call["function"]["name"] = tool
            if item.get("type") == "function_call" and item["call_id"] == call_id:
                item["name"] = tool
            content = item.get("content")
            for block in cast(list[Json], content if isinstance(content, list) else []):
                if block.get("type") == "tool_use" and block["id"] == call_id:
                    block["name"] = tool

    def output(self, call_id: str, output: str) -> Json:
        """A Responses tool result, which carries no tool name."""
        return {"type": "function_call_output", "call_id": call_id, "output": output}

    def result(self, call_id: str, tool: str, output: str) -> None:
        if self.kind == "chat":
            self.history.append(
                {"role": "tool", "tool_call_id": call_id, "name": tool, "content": output}
            )
        elif self.kind == "responses":
            self.history.append(self.output(call_id, output))
        else:
            block: Json = {"type": "tool_result", "tool_use_id": call_id, "content": output}
            last = self.history[-1]
            if last["role"] == "user" and isinstance(last["content"], list):
                cast(list[Json], last["content"]).append(block)
            else:
                self.history.append({"role": "user", "content": [block]})

    def user(self, text: str) -> None:
        self.history.append({"role": "user", "content": text})


def export_span() -> None:
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "tool loop"}]}]}]}
    request = urllib.request.Request(
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def summarise(kind: str, output: str) -> None:
    """A model request of the program's own that carries no tool result."""
    side = Api(kind)
    side.history = [{"role": "user", "content": f"Summarise this tool output: {output}"}]
    assert side.ask([]) == []


def tool_loop(api: Api, mode: str) -> None:
    """Offer send_file, run each call of it the model makes, answer."""
    first_history = json.loads(json.dumps(api.history))
    calls = api.ask(["send_file"])
    if mode == "retry":
        # The first reply was lost: the client sends the request again.
        api.history = first_history
        calls = api.ask(["send_file"])
    sent = [(call_id, tool) for call_id, tool in calls if tool == "send_file"]
    assert sent, calls
    for call_id, tool in sent:
        api.result(call_id, tool, send_file("notes.txt"))
    if mode == "summary":
        summarise(api.kind, "uploaded")
    if mode == "framework":
        api.called(FRAMEWORK_ID, HANDOFF)
        api.result(FRAMEWORK_ID, HANDOFF, "Transferred back to the supervisor.")
    before = json.loads(json.dumps(api.history))
    api.ask(["send_file"])
    if mode == "retry":
        # The reply was lost twice: the same request, sent again.
        for _ in range(2):
            api.history = json.loads(json.dumps(before))
            api.ask(["send_file"])


def main() -> None:
    with open(os.environ["SIDE_FILE"], "w", encoding="utf-8") as side:
        json.dump([os.environ["MODEL_KEY"], os.environ["FILES_KEY"]], side)
    mode = os.environ["MODE"]
    api = Api(os.environ["API"])

    if mode == "injected-leak":
        print(f"debug: model key {os.environ['MODEL_KEY']}")
    if mode in ("injected", "injected-leak", "injected-summary"):
        # The caller's history ends in a tool call; the program runs it.
        api.called(CALLER_ID, "send_file")
        api.result(CALLER_ID, "send_file", send_file("notes.txt"))
        if mode == "injected-summary":
            summarise(api.kind, "uploaded")
        api.ask(["send_file"])
    elif mode == "substituted":
        calls = api.ask(["read_file"])
        assert [tool for _, tool in calls] == ["read_file"], calls
        call_id = calls[0][0]
        api.rename(call_id, "send_file")
        api.result(call_id, "send_file", send_file("notes.txt"))
        api.ask(["read_file"])
    elif mode == "batched":
        calls = api.ask(["send_file", "read_file"])
        assert sorted(tool for _, tool in calls) == ["read_file", "send_file"], calls
        outputs = {t: send_file("notes.txt") if t == "send_file" else "notes" for _, t in calls}
        first, second = calls
        api.result(*first, outputs[first[1]])
        snapshot = json.loads(json.dumps(api.history))
        api.result(*second, outputs[second[1]])
        later = api.history
        api.history = snapshot
        api.ask(["send_file", "read_file"])
        api.history = later
        api.ask(["send_file", "read_file"])
    elif mode == "fewshot":
        # A worked example ahead of the real conversation, sent every time.
        api.history = []
        api.user("Share draft.txt with the team.")
        api.called(FEWSHOT_ID, "send_file")
        api.result(FEWSHOT_ID, "send_file", "uploaded")
        api.user("Share notes.txt with the team.")
        tool_loop(api, mode)
    elif mode == "replay":
        # A recorded conversation, sent as it was: nothing runs.
        api.called(RECORDED_ID, "send_file")
        api.result(RECORDED_ID, "send_file", "uploaded")
        api.user("And what did you share?")
        assert api.ask([]) == []
    elif mode == "stateful":
        calls = api.ask(["send_file"])
        assert [tool for _, tool in calls] == ["send_file"], calls
        outputs = [api.output(call_id, send_file("notes.txt")) for call_id, _ in calls]
        api.ask(["send_file"], outputs)
    elif mode == "stateful-masked":
        calls = api.ask(["send_file"])
        assert [tool for _, tool in calls] == ["send_file"], calls
        outputs = [api.output(call_id, send_file("notes.txt")) for call_id, _ in calls]
        api.ask(["send_file"], outputs)
        api.ask(["send_file"], [api.output(CALLER_ID, send_file("notes.txt"))])
    elif mode == "substitute-offered":
        calls = api.ask(["read_file", "send_file"])
        assert sorted(tool for _, tool in calls) == ["read_file", "send_file"], calls
        outputs = [send_file("notes.txt"), send_file("notes.txt")]
        for (call_id, tool), output in zip(calls, outputs, strict=True):
            if tool == "read_file":
                api.rename(call_id, "send_file")
            api.result(call_id, "send_file", output)
        api.ask(["read_file", "send_file"])
    elif mode == "stateful-injected":
        assert api.ask([]) == []
        api.ask(["send_file"], [api.output(CALLER_ID, send_file("notes.txt"))])
    else:
        tool_loop(api, mode)
        if mode == "upload-after":
            # The program's own use of the files API, after the conversation.
            send_file("answer.txt")
    export_span()


if __name__ == "__main__":
    main()
