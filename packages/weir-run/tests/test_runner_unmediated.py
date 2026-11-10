"""Unmediated tool calls (docs/canary.md, "Tool calls").

Two layers. The mock over real HTTP: its tool ledger keeps every tool call
it issues, the ids read back from its own replies, and judges every
request served at a tool's endpoint when it happens, against the calls
issued in the flow; a later tool result only gives a finding its reason.
Every test that expects a finding performs the execution, and has a twin
that sends the same requests without it, or with the call it answers,
and expects none. Then `weir-run run` end to end with
`_tool_flow.py`, judged by the real `weir canary judge` of the weir-scan
this workspace ships: a tool the program ran without a model request
fails the run with exit 1 and a line on execution, never a leak; a
legitimate tool loop, a retry, a batch, a few-shot example, a replayed
transcript and a framework's own call stay clean.

Every expected line and reason is read from the contract's text, and every
call id from the mock's own reply.
"""

from __future__ import annotations

import http.client
import json
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner, Result

from weir_run import cli
from weir_run import judge as judge_cli
from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock import HOST, Mock
from weir_run.shapes import ByteSource, shaped
from weir_run.spec import EndpointSpec, MockSpec

type Json = dict[str, Any]

DOC = (Path(__file__).resolve().parents[3] / "docs" / "canary.md").read_text(encoding="utf-8")
SECTION = DOC.split("\n## Tool calls\n", 1)[1].split("\n## ", 1)[0]
FLOW = Path(__file__).parent / "_tool_flow.py"
SCHEMA: Json = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
APIS = ("chat", "responses", "messages")
FRAGMENT = 6


def _line(reason: str, tool: str, issued: str | None = None) -> str:
    """The contract's text-report line for one group of reason."""
    bullets = re.findall(r"`(unmediated tool call: [^`]+)` for\s+`(\w+)`", SECTION)
    template = {r: t.replace("\n  ", " ") for t, r in bullets}[reason]
    line = template.replace("<tool>", tool)
    return line if issued is None else line.replace("<issued tool>", issued)


def _reasons() -> list[str]:
    """The judgement table's reasons, row by row."""
    return re.findall(r"^\| `(\w+)` \| ", SECTION, re.MULTILINE)


ROWS = _reasons()
NOT_ISSUED, MISMATCH = ROWS


def test_the_contract_has_two_reasons() -> None:
    assert sorted(ROWS) == ["not_issued", "tool_mismatch"]


# -- the mock, over real HTTP --------------------------------------------------

FILES = EndpointSpec("files", tool="send_file")
READER = EndpointSpec("reader", tool="read_file")
PATHS = {"chat": "/v1/chat/completions", "responses": "/v1/responses", "messages": "/v1/messages"}
USER: Json = {"role": "user", "content": "go"}


class Rig:
    def __init__(self, mock: Mock) -> None:
        self.mock = mock

    def _post(self, path: str, doc: Json) -> bytes:
        conn = http.client.HTTPConnection(HOST, self.mock.port, timeout=10)
        try:
            body = json.dumps(doc).encode()
            conn.request("POST", path, body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            assert response.status == 200
            return response.read()
        finally:
            conn.close()

    def ask(self, api: str, tools: list[str], history: list[Json], stream: bool = False) -> bytes:
        return self._post(PATHS[api], _request(api, tools, history, stream))

    def run(self, endpoint: EndpointSpec) -> None:
        """The tool executes: a request to its endpoint."""
        self._post(f"/ep/{endpoint.id}/x", {"path": "notes.txt"})

    def post(self, path: str, doc: Json) -> bytes:
        return self._post(path, doc)

    def unmediated(self) -> list[tuple[str, str, str | None, int]]:
        return [(u.tool, u.reason, u.issued_tool, n) for u, n in self.mock.tools.unmediated()]


def _rig(tmp_path: Path, spec: MockSpec) -> Generator[Rig]:
    source = ByteSource()
    ledger = Ledger(tmp_path / "ledger.jsonl", source, ["send_file", "read_file"])
    ledger.plant("env.MODEL_KEY", "env", shaped(source, "generic"))
    mock = Mock(spec, ledger, Capture(tmp_path / "capture"), source)
    mock.start()
    try:
        yield Rig(mock)
    finally:
        mock.stop()
        ledger.close()


@pytest.fixture
def rig(tmp_path: Path) -> Generator[Rig]:
    yield from _rig(tmp_path, MockSpec(endpoints=(FILES,)))


@pytest.fixture
def two_tool_rig(tmp_path: Path) -> Generator[Rig]:
    yield from _rig(tmp_path, MockSpec(endpoints=(FILES, READER)))


@pytest.fixture
def silent_rig(tmp_path: Path) -> Generator[Rig]:
    yield from _rig(tmp_path, MockSpec(tool_calls="none", endpoints=(FILES,)))


def _sse_data(raw: bytes) -> list[Json]:
    return [
        json.loads(line[6:])
        for line in raw.decode().splitlines()
        if line.startswith("data: ") and line != "data: [DONE]"
    ]


def _issued(api: str, raw: bytes) -> list[tuple[str, str]]:
    """(call id, tool) of every call in a model API reply, streamed or not."""
    if raw.startswith(b"event:") or raw.startswith(b"data:"):
        found: list[tuple[str, str]] = []
        for event in _sse_data(raw):
            for choice in cast(list[Json], event.get("choices", [])):
                for c in cast(list[Json], choice["delta"].get("tool_calls", [])):
                    found.append((c["id"], c["function"]["name"]))
            item = cast(Json, event.get("item") or {})
            if event.get("type") == "response.output_item.done" and item["type"] == "function_call":
                found.append((item["call_id"], item["name"]))
            block = cast(Json, event.get("content_block") or {})
            if block.get("type") == "tool_use":
                found.append((block["id"], block["name"]))
        return found
    doc = json.loads(raw)
    if api == "chat":
        calls = cast(list[Json], doc["choices"][0]["message"].get("tool_calls") or [])
        return [(c["id"], c["function"]["name"]) for c in calls]
    if api == "responses":
        return [(o["call_id"], o["name"]) for o in doc["output"] if o["type"] == "function_call"]
    return [(b["id"], b["name"]) for b in doc["content"] if b["type"] == "tool_use"]


def _request(api: str, tools: list[str], history: list[Json], stream: bool = False) -> Json:
    if api == "chat":
        offered = [
            {"type": "function", "function": {"name": t, "parameters": SCHEMA}} for t in tools
        ]
        return {"model": "m", "messages": history, "tools": offered, "stream": stream}
    if api == "responses":
        offered = [{"type": "function", "name": t, "parameters": SCHEMA} for t in tools]
        return {"model": "m", "input": history, "tools": offered, "stream": stream}
    offered = [{"name": t, "input_schema": SCHEMA} for t in tools]
    return {"model": "m", "max_tokens": 8, "messages": history, "tools": offered, "stream": stream}


def _call(api: str, call_id: str, tool: str) -> list[Json]:
    """The conversation items that repeat one call."""
    if api == "chat":
        fn = {"name": tool, "arguments": "{}"}
        return [{"role": "assistant", "tool_calls": [{"id": call_id, "function": fn}]}]
    if api == "responses":
        return [{"type": "function_call", "call_id": call_id, "name": tool, "arguments": "{}"}]
    return [{"role": "assistant", "content": [{"type": "tool_use", "id": call_id, "name": tool}]}]


def _result(api: str, call_id: str) -> list[Json]:
    """The conversation items that answer one call, naming no tool."""
    if api == "chat":
        return [{"role": "tool", "tool_call_id": call_id, "content": "ok"}]
    if api == "responses":
        return [{"type": "function_call_output", "call_id": call_id, "output": "ok"}]
    block = {"type": "tool_result", "tool_use_id": call_id, "content": "ok"}
    return [{"role": "user", "content": [block]}]


def _answered(api: str, calls: list[tuple[str, str]]) -> list[Json]:
    history = [USER]
    for call_id, tool in calls:
        history += _call(api, call_id, tool) + _result(api, call_id)
    return history


@pytest.mark.parametrize("stream", [False, True], ids=["plain", "stream"])
@pytest.mark.parametrize("api", APIS)
def test_every_issued_call_is_ledgered_and_running_it_is_no_finding(
    rig: Rig, api: str, stream: bool
) -> None:
    issued = _issued(api, rig.ask(api, ["read_file", "send_file"], [USER], stream))
    assert sorted(tool for _, tool in issued) == ["read_file", "send_file"]
    stem = "toolu_mock_" if api == "messages" else "call_mock_"
    assert all(call_id.startswith(stem) for call_id, _ in issued)
    rig.run(FILES)
    rig.ask(api, ["read_file", "send_file"], _answered(api, issued), stream)
    assert rig.unmediated() == []


@pytest.mark.parametrize("executed", [True, False], ids=["executed", "nothing-ran"])
@pytest.mark.parametrize("api", APIS)
def test_a_tool_run_reported_under_an_id_no_reply_issued_is_not_issued(
    rig: Rig, api: str, executed: bool
) -> None:
    if executed:
        rig.run(FILES)
    rig.ask(api, ["send_file"], _answered(api, [("call_from_the_caller", "send_file")]))
    assert rig.unmediated() == ([("send_file", NOT_ISSUED, None, 1)] if executed else [])


@pytest.mark.parametrize("api", APIS)
def test_an_execution_is_judged_when_it_happens(rig: Rig, api: str) -> None:
    """No model request has to follow: a run with no call to answer is
    already a finding."""
    rig.ask(api, [], [USER])
    rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


@pytest.mark.parametrize("executed", [True, False], ids=["executed", "nothing-ran"])
@pytest.mark.parametrize("api", APIS)
def test_a_tool_run_under_another_tools_call_and_name_is_tool_mismatch(
    rig: Rig, api: str, executed: bool
) -> None:
    [(call_id, tool)] = _issued(api, rig.ask(api, ["read_file"], [USER]))
    assert tool == "read_file"
    if executed:
        rig.run(FILES)
    rig.ask(api, ["read_file"], _answered(api, [(call_id, "send_file")]))
    expected = [("send_file", MISMATCH, "read_file", 1)]
    assert rig.unmediated() == (expected if executed else [])


@pytest.mark.parametrize("api", APIS)
def test_a_call_for_another_tool_mediates_no_run_of_this_one(two_tool_rig: Rig, api: str) -> None:
    """The model asked for read_file only; send_file ran too. The result
    reports read_file as read_file, so the reason stays not_issued."""
    rig = two_tool_rig
    [(call_id, _)] = _issued(api, rig.ask(api, ["read_file"], [USER]))
    rig.run(FILES)
    rig.run(READER)
    rig.ask(api, ["read_file"], _answered(api, [(call_id, "read_file")]))
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


def _stateful(call_id: str) -> Json:
    """A Responses request that continues a stored conversation: the
    output alone, with a call id and no tool name."""
    body = _request("responses", ["send_file"], _result("responses", call_id))
    return {**body, "previous_response_id": "resp_mock_1"}


@pytest.mark.parametrize("executed", [True, False], ids=["executed", "nothing-ran"])
def test_a_stateful_responses_output_no_reply_issued_is_never_clean(
    rig: Rig, executed: bool
) -> None:
    rig.ask("responses", [], [USER])
    if executed:
        rig.run(FILES)
    rig.post(PATHS["responses"], _stateful("call_from_the_caller"))
    assert rig.unmediated() == ([("send_file", NOT_ISSUED, None, 1)] if executed else [])


def test_a_stateful_responses_output_for_the_issued_call_is_clean(rig: Rig) -> None:
    [(call_id, _)] = _issued("responses", rig.ask("responses", ["send_file"], [USER]))
    rig.run(FILES)
    rig.post(PATHS["responses"], _stateful(call_id))
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_few_shot_example_is_no_finding(rig: Rig, api: str) -> None:
    """A made-up send_file call and its result, sent with every request,
    while the model is offered send_file and calls it for real."""
    example = [*_call(api, "call_example_1", "send_file"), *_result(api, "call_example_1")]
    history = [*example, USER]
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], history))
    rig.run(FILES)
    history += _call(api, call_id, "send_file") + _result(api, call_id)
    rig.ask(api, ["send_file"], history)
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_replayed_transcript_is_no_finding_in_a_later_flow(rig: Rig, api: str) -> None:
    """The first flow runs a mediated send_file; the second replays a
    recorded send_file call and result and runs nothing."""
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    rig.ask(api, ["send_file"], _answered(api, [(call_id, "send_file")]))
    rig.mock.tools.start_flow()
    rig.ask(api, ["send_file"], _answered(api, [("call_recorded_1", "send_file")]))
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_run_after_every_call_of_the_tool_had_its_result_is_not_issued(
    rig: Rig, api: str
) -> None:
    """A mediated send_file whose result went back, then send_file runs
    again with no model request: that run is no retry."""
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    rig.ask(api, ["send_file"], _answered(api, [(call_id, "send_file")]))
    assert rig.unmediated() == []
    rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


@pytest.mark.parametrize("api", APIS)
def test_a_run_after_its_calls_result_went_back_unrun_is_not_issued(rig: Rig, api: str) -> None:
    """The model asks for send_file; the program answers the call without
    running it, as a denied approval or a local error does, then runs
    send_file with no model request: the answered call mediates nothing."""
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.ask(api, ["send_file"], _answered(api, [(call_id, "send_file")]))
    assert rig.unmediated() == []
    rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


def test_a_stateful_responses_run_after_its_calls_output_went_back_unrun_is_never_clean(
    rig: Rig,
) -> None:
    [(call_id, _)] = _issued("responses", rig.ask("responses", ["send_file"], [USER]))
    rig.post(PATHS["responses"], _stateful(call_id))
    rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


def test_a_stateful_responses_run_after_a_mediated_loop_is_never_clean(rig: Rig) -> None:
    """A mediated loop continued with `previous_response_id`, then a run
    of send_file the caller supplied, reported the same way under an id
    no reply issued."""
    [(call_id, _)] = _issued("responses", rig.ask("responses", ["send_file"], [USER]))
    rig.run(FILES)
    rig.post(PATHS["responses"], _stateful(call_id))
    rig.run(FILES)
    rig.post(PATHS["responses"], _stateful("call_from_the_caller"))
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


@pytest.mark.parametrize("api", APIS)
def test_a_substitution_among_offered_tools_is_tool_mismatch(rig: Rig, api: str) -> None:
    """The model asks for read_file and send_file. The program runs
    send_file twice, never runs read_file, and reports read_file's call as
    send_file: one substitution, however often the history repeats it."""
    calls = _issued(api, rig.ask(api, ["read_file", "send_file"], [USER]))
    read = next(call_id for call_id, tool in calls if tool == "read_file")
    rig.run(FILES)
    rig.run(FILES)
    reported = [(call_id, "send_file") for call_id, _ in calls]
    assert any(call_id == read for call_id, _ in reported)
    for _ in range(2):
        rig.ask(api, ["read_file", "send_file"], _answered(api, reported))
    assert rig.unmediated() == [("send_file", MISMATCH, "read_file", 1)]


@pytest.mark.parametrize("api", APIS)
def test_an_offered_call_answered_without_running_its_tool_is_clean(rig: Rig, api: str) -> None:
    """The model asks for read_file and send_file; the program runs only
    send_file and reports each call under its own tool."""
    calls = _issued(api, rig.ask(api, ["read_file", "send_file"], [USER]))
    rig.run(FILES)
    rig.ask(api, ["read_file", "send_file"], _answered(api, calls))
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_result_naming_another_tool_when_both_ran_is_clean(two_tool_rig: Rig, api: str) -> None:
    """The model asks for read_file and send_file and both run; the result
    of read_file's call also names send_file. The asked tool ran, so this
    is no substitution."""
    rig = two_tool_rig
    calls = _issued(api, rig.ask(api, ["read_file", "send_file"], [USER]))
    rig.run(READER)
    rig.run(FILES)
    reported = [(call_id, "send_file") for call_id, _ in calls]
    rig.ask(api, ["read_file", "send_file"], _answered(api, reported))
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_call_issued_in_an_earlier_flow_gives_no_tool_mismatch(rig: Rig, api: str) -> None:
    """A later flow replays an earlier flow's read_file call as send_file,
    beside a mediated send_file of its own: only ids issued in this flow
    count."""
    [(earlier, _)] = _issued(api, rig.ask(api, ["read_file"], [USER]))
    rig.mock.tools.start_flow()
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    reported = [(earlier, "send_file"), (call_id, "send_file")]
    rig.ask(api, ["send_file"], _answered(api, reported))
    assert rig.unmediated() == []


@pytest.mark.parametrize("new_flow", [True, False], ids=["next-flow", "same-flow"])
def test_a_call_is_answered_only_in_the_flow_that_was_issued_it(rig: Rig, new_flow: bool) -> None:
    """A flow that is issued a call and never runs it leaves nothing for
    the next flow's run, even one reported under that call's id."""
    [(call_id, _)] = _issued("chat", rig.ask("chat", ["send_file"], [USER]))
    if new_flow:
        rig.mock.tools.start_flow()
    rig.run(FILES)
    rig.ask("chat", ["send_file"], _answered("chat", [(call_id, "send_file")]))
    assert rig.unmediated() == ([("send_file", NOT_ISSUED, None, 1)] if new_flow else [])


@pytest.mark.parametrize("api", APIS)
def test_a_framework_hand_off_is_no_finding(rig: Rig, api: str) -> None:
    """A call and result the framework writes itself, under an id it made
    up, beside a real call: no list of framework tools is needed."""
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    calls = [(call_id, "send_file"), ("handoff_7f3a", "transfer_back_to_supervisor")]
    rig.ask(api, ["send_file"], _answered(api, calls))
    assert rig.unmediated() == []


SUMMARY: Json = {"role": "user", "content": "Summarise this tool output: uploaded"}


@pytest.mark.parametrize("executed", [True, False], ids=["executed", "nothing-ran"])
@pytest.mark.parametrize("api", APIS)
def test_a_summary_request_between_the_run_and_its_result_hides_nothing(
    rig: Rig, api: str, executed: bool
) -> None:
    if executed:
        rig.run(FILES)
    rig.ask(api, [], [SUMMARY])
    rig.ask(api, ["send_file"], _answered(api, [("call_from_the_caller", "send_file")]))
    assert rig.unmediated() == ([("send_file", NOT_ISSUED, None, 1)] if executed else [])


@pytest.mark.parametrize("api", APIS)
def test_a_mediated_run_with_an_unrelated_request_in_between_is_clean(rig: Rig, api: str) -> None:
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    rig.ask(api, [], [SUMMARY])
    rig.ask(api, ["send_file"], _answered(api, [(call_id, "send_file")]))
    assert rig.unmediated() == []


@pytest.mark.parametrize("api", APIS)
def test_a_sub_agents_own_tool_loop_hides_no_unmediated_run(rig: Rig, api: str) -> None:
    """The main agent runs a send_file call its caller planted; in the same
    flow a sub-agent runs its own mediated lookup loop before the main
    agent reports the send_file result."""
    rig.run(FILES)
    sub = [{"role": "user", "content": "look it up"}]
    [(lookup_id, _)] = _issued(api, rig.ask(api, ["lookup"], sub))
    rig.ask(api, ["lookup"], [*sub, *_call(api, lookup_id, "lookup"), *_result(api, lookup_id)])
    rig.ask(api, ["send_file"], _answered(api, [("call_from_the_caller", "send_file")]))
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


@pytest.mark.parametrize("api", APIS)
def test_a_sub_agents_few_shot_makes_no_finding_of_a_mediated_run(rig: Rig, api: str) -> None:
    """The reverse: a mediated send_file, then a sub-agent request whose
    few-shot example names send_file under an id no reply issued, before
    the main agent reports the real call."""
    [(call_id, _)] = _issued(api, rig.ask(api, ["send_file"], [USER]))
    rig.run(FILES)
    example = [*_call(api, "call_example_1", "send_file"), *_result(api, "call_example_1")]
    rig.ask(api, ["lookup"], [*example, {"role": "user", "content": "look it up"}])
    rig.ask(api, ["send_file"], _answered(api, [(call_id, "send_file")]))
    assert rig.unmediated() == []


def test_a_chat_results_own_name_counts(rig: Rig) -> None:
    [(call_id, _)] = _issued("chat", rig.ask("chat", ["read_file"], [USER]))
    rig.run(FILES)
    result = {"role": "tool", "tool_call_id": call_id, "name": "send_file", "content": "ok"}
    rig.ask("chat", ["read_file"], [USER, result])
    assert rig.unmediated() == [("send_file", MISMATCH, "read_file", 1)]


def test_any_responses_call_output_is_a_result(rig: Rig) -> None:
    [(call_id, _)] = _issued("responses", rig.ask("responses", ["read_file"], [USER]))
    rig.run(FILES)
    call = {"type": "custom_tool_call", "call_id": call_id, "name": "send_file", "input": ""}
    output = {"type": "custom_tool_call_output", "call_id": call_id, "output": "ok"}
    rig.ask("responses", ["read_file"], [USER, call, output])
    assert rig.unmediated() == [("send_file", MISMATCH, "read_file", 1)]


def test_a_later_call_and_result_never_clear_a_finding(rig: Rig) -> None:
    """send_file ran unasked; the model asks for it only afterwards, and the
    program answers that call without running it again."""
    rig.run(FILES)
    [(call_id, _)] = _issued("chat", rig.ask("chat", ["send_file"], [USER]))
    rig.ask("chat", ["send_file"], _answered("chat", [(call_id, "send_file")]))
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


def test_a_tools_later_requests_in_the_flow_repeat_its_execution(rig: Rig) -> None:
    """A retry, and every later request of the same tool in the flow, is
    judged with its first execution: one unmediated run, counted once."""
    for _ in range(3):
        rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


def test_each_flows_unmediated_run_is_counted(rig: Rig) -> None:
    for _ in range(2):
        rig.mock.tools.start_flow()
        rig.run(FILES)
    assert rig.unmediated() == [("send_file", NOT_ISSUED, None, 2)]


def test_a_tool_that_makes_several_requests_runs_once(rig: Rig) -> None:
    [(call_id, _)] = _issued("chat", rig.ask("chat", ["send_file"], [USER]))
    rig.run(FILES)
    rig.run(FILES)
    rig.ask("chat", ["send_file"], _answered("chat", [(call_id, "send_file")]))
    assert rig.unmediated() == []


def test_a_call_issued_again_on_a_retried_request_is_model_issued(rig: Rig) -> None:
    first = _issued("chat", rig.ask("chat", ["send_file"], [USER]))
    second = _issued("chat", rig.ask("chat", ["send_file"], [USER]))
    assert first != second
    rig.run(FILES)
    rig.ask("chat", ["send_file"], _answered("chat", second))
    rig.ask("chat", ["send_file"], _answered("chat", first + second))
    assert rig.unmediated() == []


def test_a_batch_answered_one_per_request_is_clean(two_tool_rig: Rig) -> None:
    rig = two_tool_rig
    calls = _issued("chat", rig.ask("chat", ["send_file", "read_file"], [USER]))
    rig.run(FILES)
    rig.run(READER)
    rig.ask("chat", ["send_file", "read_file"], _answered("chat", calls[:1]))
    rig.ask("chat", ["send_file", "read_file"], _answered("chat", calls))
    assert rig.unmediated() == []


def test_two_tools_run_unasked_are_each_reported(two_tool_rig: Rig) -> None:
    rig = two_tool_rig
    rig.ask("responses", [], [USER])
    rig.run(FILES)
    rig.run(READER)
    rig.post(PATHS["responses"], _stateful("call_from_the_caller"))
    assert rig.unmediated() == [
        ("read_file", NOT_ISSUED, None, 1),
        ("send_file", NOT_ISSUED, None, 1),
    ]


def test_with_tool_calls_none_every_run_is_not_issued(silent_rig: Rig) -> None:
    assert _issued("chat", silent_rig.ask("chat", ["send_file"], [USER])) == []
    silent_rig.run(FILES)
    silent_rig.ask("chat", ["send_file"], _answered("chat", [("call_mock_1_0", "send_file")]))
    assert silent_rig.unmediated() == [("send_file", NOT_ISSUED, None, 1)]


# -- weir-run run, end to end --------------------------------------------------

CONFIG = """
[[mock.endpoint]]
id = "files"
reply = '{"ok": true}'
tool = "send_file"

[[placement]]
id = "env.MODEL_KEY"
kind = "env"
provider = "model"

[[placement]]
id = "env.FILES_KEY"
kind = "env"
provider = "files"
"""

FLOW_TABLE = """
[[flow]]
id = {id}
command = ["{{python}}", {flow}]
timeout_seconds = 60
env = {{ {env} }}
"""


class Run:
    def __init__(self, result: Result, report: Json) -> None:
        self.result = result
        self.report = report

    @property
    def lines(self) -> list[str]:
        return [x for x in self.result.stdout.splitlines() if x.startswith("unmediated tool call")]


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    judge: list[str],
    api: str,
    *modes: str,
    extra: str = "",
) -> Run:
    """One flow per mode, in order, in one run."""
    config = tmp_path / "canary.toml"
    text = CONFIG + extra
    sides: list[Path] = []
    for i, mode in enumerate(modes):
        sides.append(tmp_path / f"side-{i}.json")
        env = {
            "API": api,
            "MODE": mode,
            "FILES_BASE_URL": "{mock}/ep/files",
            "SIDE_FILE": sides[-1].as_posix(),
        }
        text += FLOW_TABLE.format(
            id=json.dumps(f"{i}-{mode}"),
            flow=json.dumps(FLOW.as_posix()),
            env=", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items()),
        )
    config.write_text(text, encoding="utf-8")
    report = tmp_path / "report.json"

    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config), "--report", str(report)])
    assert report.exists(), result.output
    text = result.output + report.read_text(encoding="utf-8")
    for side in sides:
        for key in json.loads(side.read_text(encoding="utf-8")):
            for i in range(len(key) - FRAGMENT + 1):
                assert key[i : i + FRAGMENT] not in text, "output holds a fragment of a canary"
    return Run(result, json.loads(report.read_text(encoding="utf-8")))


def _exercised(run: Run) -> None:
    """The tool really ran: its key reached its own API."""
    files = next(p for p in run.report["judge"]["placements"] if p["id"] == "env.FILES_KEY")
    assert files["state"] == "exercised"


def _clean(run: Run) -> None:
    assert run.result.exit_code == 0, run.result.output
    report = run.report
    assert (report["result"], report["exit_code"], report["findings"]) == ("clean", 0, [])
    assert report["unmediated"] == [] and run.lines == []
    assert report["judge"]["result"] == "clean"
    assert run.result.stdout.splitlines()[-1] == "result: clean"
    _exercised(run)


def _failed(run: Run, reason: str, issued: str | None = None) -> None:
    """One unmediated tool call of send_file: exit 1, nothing leaked, and
    nothing says it did."""
    assert run.result.exit_code == 1, run.result.output
    assert run.lines == [_line(reason, "send_file", issued)]
    report = run.report
    # The run's verdict at the top: never clean, exit 1.
    assert (report["result"], report["exit_code"]) == ("unmediated-tool-call", 1)
    assert report["findings"] == ["unmediated-tool-call"]
    assert report["unmediated"] == [
        {"tool": "send_file", "reason": reason, "issued_tool": issued, "count": 1}
    ]
    # The judge's own report, kept as it is: it saw nothing leak.
    judged = report["judge"]
    assert (judged["result"], judged["exit_code"], judged["hits"]) == ("clean", 0, [])
    stdout = run.result.stdout.splitlines()
    assert "LEAK" not in run.result.stdout and "leak" not in "\n".join(run.lines).lower()
    assert stdout[-1] == "result: unmediated-tool-call"
    assert stdout.count("result: clean") == 0
    coverage = next(i for i, x in enumerate(stdout) if x.startswith("coverage: "))
    assert stdout[coverage - 1] == run.lines[-1]
    _exercised(run)


@pytest.mark.parametrize("api", APIS)
def test_a_tool_the_model_asked_for_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    _clean(_run(tmp_path, monkeypatch, judge, api, "model"))


@pytest.mark.parametrize("api", APIS)
def test_a_tool_run_without_a_model_request_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    _failed(_run(tmp_path, monkeypatch, judge, api, "injected"), NOT_ISSUED)


@pytest.mark.parametrize("api", APIS)
def test_a_tool_run_under_another_tools_call_is_tool_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    _failed(_run(tmp_path, monkeypatch, judge, api, "substituted"), MISMATCH, "read_file")


@pytest.mark.parametrize("api", APIS)
def test_a_summary_before_the_result_still_fails_an_unmediated_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    """A model request of the program's own between the run and its result
    carries no result, so it never turns the orphan run clean."""
    _failed(_run(tmp_path, monkeypatch, judge, api, "injected-summary"), NOT_ISSUED)


def test_a_stateful_responses_tool_run_without_a_model_request_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _failed(_run(tmp_path, monkeypatch, judge, "responses", "stateful-injected"), NOT_ISSUED)


def test_a_stateful_responses_tool_loop_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _clean(_run(tmp_path, monkeypatch, judge, "responses", "stateful"))


@pytest.mark.parametrize("mode", ["retry", "batched", "fewshot", "framework", "summary"])
@pytest.mark.parametrize("api", APIS)
def test_legitimate_tool_loops_stay_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str, mode: str
) -> None:
    _clean(_run(tmp_path, monkeypatch, judge, api, mode))


@pytest.mark.parametrize("api", APIS)
def test_a_replayed_transcript_in_a_later_flow_stays_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    """The first flow runs a mediated tool loop; the second replays a
    recorded send_file call and runs nothing."""
    run = _run(tmp_path, monkeypatch, judge, api, "model", "replay")
    _clean(run)
    assert [f["status"] for f in run.report["judge"]["flows"]] == ["ok", "ok"]


@pytest.mark.parametrize("api", APIS)
def test_a_tool_run_again_after_its_result_went_back_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    """The flow uses the files API itself after its conversation, with no
    model request; a later flow replaying a transcript adds nothing."""
    run = _run(tmp_path, monkeypatch, judge, api, "upload-after", "replay")
    _failed(run, NOT_ISSUED)
    assert [f["status"] for f in run.report["judge"]["flows"]] == ["ok", "ok"]


def test_a_stateful_responses_run_after_a_mediated_loop_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    _failed(_run(tmp_path, monkeypatch, judge, "responses", "stateful-masked"), NOT_ISSUED)


@pytest.mark.parametrize("api", APIS)
def test_a_substitution_among_offered_tools_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str], api: str
) -> None:
    run = _run(tmp_path, monkeypatch, judge, api, "substitute-offered")
    _failed(run, MISMATCH, "read_file")


def test_a_finding_beside_a_leak_is_both_and_the_result_is_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    """Any finding fails the run, a leak first; both types are data."""
    run = _run(tmp_path, monkeypatch, judge, "chat", "injected-leak")
    assert run.result.exit_code == 1, run.result.output
    assert run.report["findings"] == ["leak", "unmediated-tool-call"]
    assert (run.report["result"], run.report["judge"]["result"]) == ("leak", "leak")
    assert run.lines == [_line(NOT_ISSUED, "send_file")]
    assert any(x.startswith("LEAK env.MODEL_KEY ") for x in run.result.stdout.splitlines())
    assert run.result.stdout.splitlines()[-1] == "result: leak"


def test_a_finding_outranks_an_incomplete_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    """A required placement no flow reads makes the judge's verdict
    incomplete; the unmediated tool call still fails the run."""
    unused = '\n[[placement]]\nid = "env.UNUSED_KEY"\nkind = "env"\nprovider = "files"\n'
    run = _run(tmp_path, monkeypatch, judge, "chat", "injected", extra=unused)
    assert run.result.exit_code == 1, run.result.output
    assert run.report["judge"]["result"] == "incomplete"
    assert (run.report["result"], run.report["findings"]) == (
        "unmediated-tool-call",
        ["unmediated-tool-call"],
    )
    assert "incomplete: required_not_exercised env.UNUSED_KEY" in run.result.stdout
    assert run.result.stdout.splitlines()[-1] == "result: unmediated-tool-call"


def test_a_tool_name_must_be_a_tool_name(tmp_path: Path) -> None:
    config = tmp_path / "canary.toml"
    config.write_text(
        '[[mock.endpoint]]\nid = "files"\ntool = "two words"\n'
        '[[flow]]\nid = "a"\ncommand = ["x"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config)])
    assert result.exit_code == 2
    assert "tool 'two words' is not a tool name" in result.output


def test_no_two_endpoints_may_name_one_tool(tmp_path: Path) -> None:
    config = tmp_path / "canary.toml"
    config.write_text(
        '[[mock.endpoint]]\nid = "a"\ntool = "send_file"\n'
        '[[mock.endpoint]]\nid = "b"\ntool = "send_file"\n'
        '[[flow]]\nid = "a"\ncommand = ["x"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli.main, ["run", "--config", str(config)])
    assert result.exit_code == 2
    assert "tool send_file is named by two endpoints" in result.output
