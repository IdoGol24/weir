"""Fixtures for the `weir audit` tests (docs/audit.md).

FAKE DATA ONLY. Everything is built under the temporary directory the caller
passes: a fake home with a fake `~/.aws/credentials`, a fake launch
environment, and a real `weir inventory` run over them that writes the
report, the store and the key the audit reads. Nothing here reads a real
home, session or credential.

Every value is derived from a seed by hashing (`canary_fixtures.fake_value`),
so it has no real provider shape. `SPECIAL` adds the characters the encoded
forms change (`/`, `"`, `+`, a non-ASCII letter), and a `~`, whose byte
encodes to a `-` in URL-safe base64 at one alignment. The tests take credential
ids from the inventory report the run wrote, and locations from where the
builders below put each value, never from the audit's output.

Session records follow the Claude Code session file shape docs/audit.md
classifies; OTLP requests follow the GenAI semantic conventions it reads.
Every encoding a test places is built with the standard library (json,
urllib.parse, base64, bytes.hex), never with weir's own code.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import canary_fixtures as cfx
from click.testing import CliRunner

from weir.cli.main import main

ACME = "ACME_API_TOKEN"
SPECIAL = "PLAIN_SECRET"
GH = "GH_TOKEN"
AWS_ID = "aws_access_key_id"
AWS_SECRET = "aws_secret_access_key"

SESSION_ID = "4b9f0c1e-2d3a-4e5f-8a6b-7c8d9e0f1a2b"


def _values(seed: str = "") -> dict[str, str]:
    def fake(name: str, length: int = 24) -> str:
        return cfx.fake_value(f"audit-{name}{seed}", length)

    special = (
        fake("special-a", 8) + "/" + fake("special-b", 6) + '"' + fake("special-c", 6)
        + "+" + "é" + fake("special-d", 8) + "~" + fake("special-e", 4)
    )
    return {
        ACME: fake("acme"),
        SPECIAL: special,
        GH: fake("gh"),
        AWS_ID: fake("aws-id", 20),
        AWS_SECRET: fake("aws-secret-a", 20) + "/" + fake("aws-secret-b", 19),
    }


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()

    @property
    def report(self) -> dict[str, object]:
        return json.loads(self.stdout)


@dataclass
class Setup:
    root: Path
    home: Path
    report: Path
    store: Path
    key: Path
    values: dict[str, str]
    # credential name -> inventory credential id, read from the report.
    ids: dict[str, str] = field(default_factory=dict[str, str])

    def audit(
        self, paths: Sequence[Path | str], *, as_json: bool = True, key: Path | None = None,
    ) -> Run:
        args = [
            "audit", "--inventory", str(self.report), "--store", str(self.store),
            "--key", str(key or self.key),
        ]
        if as_json:
            args.append("--json")
        args += [str(p) for p in paths]
        result = CliRunner().invoke(main, args, catch_exceptions=False)
        return Run(result.exit_code, result.stdout, result.stderr)


def build(
    root: Path, *, seed: str = "", extra_env: str = "", bashrc: str | None = None,
) -> Setup:
    """A fake home and launch environment, inventoried by `weir inventory`.
    `seed` gives other values in the same places; `extra_env` adds launch
    environment lines and `bashrc` a shell startup file."""
    values = _values(seed)
    home = root / "home"
    project = home / "work" / "proj"
    project.mkdir(parents=True)
    (home / ".aws").mkdir()
    cfx.write(
        home / ".aws" / "credentials",
        f"[default]\naws_access_key_id = {values[AWS_ID]}\n"
        f"aws_secret_access_key = {values[AWS_SECRET]}\n",
    )
    env = root / "launch.env"
    cfx.write(
        env,
        f"{ACME}={values[ACME]}\n{SPECIAL}='{values[SPECIAL]}'\n{GH}={values[GH]}\n"
        + extra_env,
    )
    if bashrc is not None:
        cfx.write(home / ".bashrc", bashrc)
    out = root / "inventory"
    out.mkdir()
    setup = Setup(
        root=root, home=home, report=out / "inventory.json", store=out / "store.json",
        key=out / "fingerprint.key", values=values,
    )
    result = CliRunner().invoke(
        main,
        [
            "inventory", "--home", str(home), "--project", str(project),
            "--env-file", str(env), "--key", str(setup.key), "--store", str(setup.store),
            "--unknown-list", str(out / "unknown-env.txt"), "--json",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.stderr
    cfx.write(setup.report, result.stdout)
    report = json.loads(result.stdout)
    for credential in report["credentials"]:
        name = credential["name"]
        if name in setup.ids:
            name = f"{name}@{credential['location']['display']}"
        setup.ids[name] = credential["id"]
    assert set(values) <= set(setup.ids), "the inventory missed a planted credential"
    return setup


# --- Claude Code session files ----------------------------------------------


@dataclass
class Session:
    """A Claude Code session file being written, one record per line."""

    lines: list[str] = field(default_factory=list[str])
    session_id: str = SESSION_ID

    def record(self, record: dict[str, object]) -> int:
        """Append a record; returns its 1-based line."""
        self.lines.append(json.dumps(record))
        return len(self.lines)

    def raw_line(self, text: str) -> int:
        self.lines.append(text)
        return len(self.lines)

    def _envelope(self, kind: str, **fields: object) -> dict[str, object]:
        n = len(self.lines) + 1
        return {
            "parentUuid": None if n == 1 else f"00000000-0000-4000-8000-{n - 1:012d}",
            "isSidechain": False,
            "type": kind,
            "uuid": f"00000000-0000-4000-8000-{n:012d}",
            "timestamp": "2026-01-01T00:00:00.000Z",
            "cwd": "/fake/home/work/proj",
            "sessionId": self.session_id,
            "version": "2.1.0",
            **fields,
        }

    def prompt(self, text: str) -> tuple[int, str]:
        line = self.record(self._envelope("user", message={"role": "user", "content": text}))
        return line, "message.content"

    def tool_use(self, name: str, tool_input: dict[str, object], tool_id: str) -> int:
        block = {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}
        message = {"role": "assistant", "model": "fake-model", "content": [block]}
        return self.record(self._envelope("assistant", message=message))

    def tool_result(self, tool_id: str, content: str) -> tuple[int, str]:
        block = {"type": "tool_result", "tool_use_id": tool_id, "content": content}
        line = self.record(
            self._envelope("user", message={"role": "user", "content": [block]})
        )
        return line, "message.content[0].content"

    def assistant_text(self, text: str) -> tuple[int, str]:
        message = {
            "role": "assistant", "model": "fake-model", "content": [{"type": "text", "text": text}],
        }
        return self.record(self._envelope("assistant", message=message)), "message.content[0].text"

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        cfx.write(path, "".join(line + "\n" for line in self.lines))
        return path


# --- OTLP telemetry ----------------------------------------------------------


def tool_span(tool: str, arguments: str, result: str) -> dict[str, object]:
    """An `execute_tool` span with its arguments and result recorded."""
    return cfx.span(
        f"execute_tool {tool}",
        attributes=[
            cfx.kv("gen_ai.operation.name", "execute_tool"),
            cfx.kv("gen_ai.tool.name", tool),
            cfx.kv("gen_ai.tool.call.arguments", arguments),
            cfx.kv("gen_ai.tool.call.result", result),
        ],
    )


def chat_span(output_messages: list[dict[str, object]]) -> dict[str, object]:
    """A `chat` span whose output messages are recorded as a JSON string."""
    return cfx.span(
        "chat fake-model",
        span_id="fedcba9876543210",
        attributes=[
            cfx.kv("gen_ai.operation.name", "chat"),
            cfx.kv("gen_ai.output.messages", json.dumps(output_messages)),
        ],
    )


def any_value(value: object) -> dict[str, object]:
    """A JSON value written as an OTLP AnyValue: an object as a
    `kvlistValue`, an array as an `arrayValue`."""
    if isinstance(value, dict):
        members = cast("dict[str, object]", value)
        items = [{"key": k, "value": any_value(v)} for k, v in members.items()]
        return {"kvlistValue": {"values": items}}
    if isinstance(value, list):
        elements = cast("list[object]", value)
        return {"arrayValue": {"values": [any_value(v) for v in elements]}}
    return {"stringValue": value}


def claude_code_event(event: str, **attributes: str) -> dict[str, object]:
    """A log record shaped like a Claude Code `claude_code.<event>` log event."""
    return {
        "timeUnixNano": "1767225600000000000",
        "body": {"stringValue": f"claude_code.{event}"},
        "attributes": [
            cfx.kv("event.name", event),
            cfx.kv("session.id", SESSION_ID),
            *(cfx.kv(key, value) for key, value in attributes.items()),
        ],
    }


def write_otlp(path: Path, *spans: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cfx.write(path, cfx.traces(*spans) + "\n")
    return path


# --- reading a report --------------------------------------------------------


def credential(report: dict[str, object], cid: str) -> dict[str, object]:
    rows = [c for c in report["credentials"] if c["id"] == cid]  # type: ignore[union-attr,index]
    assert len(rows) == 1, cid
    return rows[0]  # type: ignore[return-value]


def hits(report: dict[str, object], cid: str) -> list[dict[str, object]]:
    return [h for h in report["hits"] if h["credential"] == cid]  # type: ignore[union-attr,index]
