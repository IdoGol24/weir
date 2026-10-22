"""The repository's Claude Code deny rules hold: an agent working in this
repository cannot read the user's agent data under ~/.claude.

The committed `.claude/settings.json` denies Claude Code's file tools the
user's home configuration and agent data. These tests run the real Claude
Code, headless, in a scratch copy of the repository, and let weir-run's
Anthropic Messages mock play the model: its scripted first turn asks for
a fake session file under `~/.claude`, through the Read tool and through
the Bash file commands Claude Code checks against Read rules. The tool
results Claude Code sends back must be refusals, and the fake session
value must never reach the mock.

Nothing real is involved. Claude Code runs under bubblewrap with the home
directory replaced by an empty tmpfs that holds only a fake `.claude`
directory and with only its own binary bound in, under an empty
environment with a fake key, inside weir-run's loopback-only network
namespace, where the mock is the only thing listening. Every run is in
bypassPermissions mode, where nothing but a deny rule stops a read, and
the control run without the settings file shows the same reads
succeeding, so a refusal can only come from the committed rules.

The last test pins what deny rules do not cover: a program that opens the
file itself. Only the Bash sandbox stops that (CONTRIBUTING.md, "Agents
working in this repository").

They skip where Claude Code (on PATH, or at WEIR_TEST_CLAUDE), bubblewrap
or the network namespace is unavailable, as on CI.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from weir_run import isolation
from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock.model import ModelApi
from weir_run.mock.server import Mock
from weir_run.shapes import ByteSource
from weir_run.spec import MockSpec

REPO = Path(__file__).resolve().parents[3]
SETTINGS = Path(".claude/settings.json")
SESSION = "projects/fake/session.jsonl"
FAKE_PREFIX = "FAKE-SESSION-VALUE-"
REPLY = "Done."
PROMPT = "Summarise my last Claude Code session."
CLAUDE = "/opt/claude/bin/claude"
WORK = "/work/weir"
TIMEOUT_SECONDS = 300

type Json = dict[str, Any]
type Call = tuple[str, Json]


def _claude() -> Path | None:
    found = os.environ.get("WEIR_TEST_CLAUDE") or shutil.which("claude")
    return Path(found).resolve() if found else None


class ScriptedModel(ModelApi):
    """The mock's Messages API, with a first turn that makes the given
    tool calls. Each call is the mock's own each-offered-tool-once answer
    for a tool whose schema admits only that input, so everything else
    about the reply is the mock's."""

    def __init__(self, calls: list[Call]) -> None:
        super().__init__(REPLY, "each-offered-tool-once")
        self.calls = calls

    def messages(self, request: Json) -> tuple[bytes, str]:
        offered = {str(t.get("name")) for t in cast(list[Json], request.get("tools") or [])}
        if offered and not {name for name, _ in self.calls} <= offered:
            raise AssertionError(f"a scripted tool is not offered: {sorted(offered)}")
        tools = [
            {
                "name": name,
                "input_schema": {
                    "type": "object",
                    "properties": {k: {"const": v} for k, v in args.items()},
                    "required": list(args),
                },
            }
            for name, args in self.calls
            if name in offered
        ]
        return super().messages({**request, "tools": tools})


class Session:
    def __init__(
        self, done: subprocess.CompletedProcess[str], requests: list[Json], dot_claude: Path
    ) -> None:
        self.done = done
        self.requests = requests
        self.dot_claude = dot_claude

    def seen(self, value: str) -> bool:
        """Whether value reached the mock anywhere in any request."""
        for r in self.requests:
            body = base64.b64decode(r["body"]) if r.get("body") else b""
            text = json.dumps([r["path"], r["query"], r["headers"]])
            if value in text + body.decode("utf-8", "replace"):
                return True
        return False

    def results(self) -> list[Json]:
        """The tool results Claude Code sent back to the model, in the
        order of the scripted calls they answer."""
        found: dict[str, Json] = {}
        for r in self.requests:
            if r.get("path") != "/v1/messages" or not r.get("body"):
                continue
            for message in json.loads(base64.b64decode(r["body"])).get("messages", []):
                content = message.get("content")
                for block in cast(list[Json], content if isinstance(content, list) else []):
                    if block.get("type") == "tool_result":
                        # Every later request repeats the conversation.
                        found[block["tool_use_id"]] = block
        return [found[k] for k in sorted(found, key=lambda k: int(k.rsplit("_", 1)[1]))]

    def final(self) -> Json:
        """Claude Code's closing `result` event."""
        return json.loads(self.done.stdout.strip().splitlines()[-1])


def _text(result: Json) -> str:
    content = result.get("content")
    if isinstance(content, list):
        return "".join(str(b.get("text", "")) for b in cast(list[Json], content))
    return str(content)


def _sandbox(claude: Path, home: Path, dot_claude: Path, work: Path) -> list[str]:
    bwrap = shutil.which("bwrap")
    assert bwrap is not None
    args = [bwrap, "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc"]
    args += ["--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
    for top in ("/bin", "/lib", "/lib64", "/sbin"):
        if os.path.islink(top):
            args += ["--symlink", os.readlink(top), top]
        elif os.path.isdir(top):
            args += ["--ro-bind", top, top]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    # Every home is hidden; the user's own is an empty tmpfs holding only
    # the fake .claude directory.
    args += ["--tmpfs", "/home", "--tmpfs", str(home)]
    args += ["--bind", str(dot_claude), str(home / ".claude")]
    args += ["--ro-bind", str(claude), CLAUDE]
    args += ["--bind", str(work), WORK, "--chdir", WORK]
    return args


def _copy_repo(dest: Path) -> None:
    """The repository's tracked files, as they are in the working tree."""
    listed = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode()
    for name in filter(None, listed.split("\0")):
        source = REPO / name
        if source.is_file():
            (dest / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest / name)


def _run(tmp_path: Path, calls: list[Call], fake: str, *, settings: bool = True) -> Session:
    claude = _claude()
    if claude is None or not claude.is_file():
        pytest.skip("Claude Code is not installed")
    with claude.open("rb") as binary:
        # Only the binary is bound into the sandbox, so it must stand alone.
        if binary.read(4) != b"\x7fELF":
            pytest.skip("Claude Code is not the native single-file build")
    if shutil.which("bwrap") is None:
        pytest.skip("bubblewrap is not installed")
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    try:
        jail = isolation.jail()
    except isolation.Unavailable as exc:
        pytest.skip(f"no network namespace: {exc}")

    home = Path.home()
    dot_claude = tmp_path / "dot-claude"
    (dot_claude / SESSION).parent.mkdir(parents=True)
    line = {"type": "user", "message": {"role": "user", "content": fake}}
    (dot_claude / SESSION).write_text(json.dumps(line) + "\n", encoding="utf-8")
    work = tmp_path / "work"
    _copy_repo(work)
    if not settings:
        (work / SETTINGS).unlink()

    source = ByteSource()
    capture = Capture(tmp_path / "capture")
    ledger = Ledger(tmp_path / "ledger.jsonl", source)
    mock = Mock(MockSpec(model_reply=REPLY), ledger, capture, source)
    mock.model = ScriptedModel(calls)
    try:
        mock.start(jail.listener)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            "ANTHROPIC_BASE_URL": mock.url,
            "ANTHROPIC_API_KEY": "fake-key-for-the-local-mock",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
        }
        command = [
            *_sandbox(claude, home, dot_claude, work),
            CLAUDE,
            "-p",
            PROMPT,
            "--permission-mode",
            "bypassPermissions",
            "--output-format",
            "stream-json",
            "--verbose",
        ]
        done = subprocess.run(
            jail.command(command),
            pass_fds=jail.fds,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        mock.stop()
        jail.close()
    records = capture.requests.read_text(encoding="utf-8").splitlines()[1:]
    session = Session(done, [json.loads(r) for r in records], dot_claude)
    assert done.returncode == 0, done.stderr
    # The turn ran to the mock's closing reply.
    assert session.final()["result"] == REPLY, done.stdout
    return session


def _reads() -> list[Call]:
    """Each way the scripted model asks for the fake session file that
    Claude Code checks against Read rules."""
    tilde = f"~/.claude/{SESSION}"
    return [
        ("Read", {"file_path": tilde}),
        ("Read", {"file_path": str(Path.home() / ".claude" / SESSION)}),
        ("Bash", {"command": f"cat {tilde}"}),
        ("Bash", {"command": f"cd ~/.claude && grep -r {FAKE_PREFIX} ."}),
    ]


def _fake() -> str:
    return FAKE_PREFIX + secrets.token_hex(8)


def test_a_read_of_agent_data_is_refused_and_never_reaches_the_model(tmp_path: Path) -> None:
    fake = _fake()
    run = _run(tmp_path, _reads(), fake)
    results = run.results()
    assert len(results) == len(_reads())
    for result in results:
        assert result.get("is_error") is True, result
        assert "denied" in _text(result) or "deny rule" in _text(result), result
    assert not run.seen(fake)
    assert fake not in run.done.stdout


def test_without_the_settings_the_same_reads_reach_the_model(tmp_path: Path) -> None:
    """The control: the scripted reads work, and the harness sees a value
    that reaches the mock, so the refusals above come from the settings."""
    fake = _fake()
    run = _run(tmp_path, _reads(), fake, settings=False)
    results = run.results()
    assert len(results) == len(_reads())
    for result in results:
        assert fake in _text(result), result
    assert run.seen(fake)


@pytest.mark.parametrize("settings", [True, False], ids=["guarded", "control"])
def test_a_write_into_agent_data_is_refused(tmp_path: Path, settings: bool) -> None:
    planted = "projects/fake/planted.md"
    write = ("Write", {"file_path": f"~/.claude/{planted}", "content": "planted"})
    run = _run(tmp_path, [write], _fake(), settings=settings)
    [result] = run.results()
    assert (result.get("is_error") is True) is settings, result
    assert (run.dot_claude / planted).exists() is not settings


def test_deny_rules_do_not_stop_a_program_that_opens_the_file_itself(tmp_path: Path) -> None:
    """The documented limit of deny rules: they match the file commands
    Claude Code recognizes, not a script that opens the file. If this
    starts failing, Claude Code closed the gap and CONTRIBUTING.md should
    say so."""
    fake = _fake()
    script = f"print(open(__import__('os').path.expanduser('~/.claude/{SESSION}')).read())"
    run = _run(tmp_path, [("Bash", {"command": f'python3 -c "{script}"'})], fake)
    [result] = run.results()
    assert fake in _text(result), result
    assert run.seen(fake)
