"""Fixtures for the `weir statusline` tests (docs/statusline.md).

FAKE DATA ONLY. Everything lives under the temporary directory the caller
passes: the fake home and inventory of `audit_fixtures.build`, a fake Claude
config directory (`home/.claude`) holding a fake session, and a fake weir
state directory. Nothing here reads a real home, setting or session.

A session is laid out as Claude Code lays one out: the transcript
`projects/<project>/<session id>.jsonl`, and beside it the session's own
directory `projects/<project>/<session id>/` with `subagents/` and
`tool-results/`. The tests take what a status line should say from a real
`weir audit --json` run over the same files, read through the counting rule
of docs/statusline.md, never from the status line's own output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import audit_fixtures as fx
from click.testing import CliRunner

from weir.cli.main import main

PROJECT = "-fake-home-work-proj"


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()


@dataclass
class Claude:
    """A fake Claude config directory and weir state directory."""

    setup: fx.Setup
    config: Path
    state: Path

    @property
    def settings(self) -> Path:
        return self.config / "settings.json"

    @property
    def command_file(self) -> Path:
        return self.config / "commands" / "weir.md"

    def transcript(self, session_id: str = fx.SESSION_ID) -> Path:
        return self.config / "projects" / PROJECT / f"{session_id}.jsonl"

    def session_dir(self, session_id: str = fx.SESSION_ID) -> Path:
        return self.config / "projects" / PROJECT / session_id

    def inputs(self) -> list[str]:
        s = self.setup
        return ["--inventory", str(s.report), "--store", str(s.store), "--key", str(s.key)]

    def env(self) -> dict[str, str]:
        """The environment the commands run with: the fake home only."""
        return {"HOME": str(self.setup.home), "CLAUDE_CONFIG_DIR": str(self.config)}

    def invoke(self, args: Sequence[str], stdin: str | None = None) -> Run:
        result = CliRunner().invoke(
            main, list(args), input=stdin, env=self.env(), catch_exceptions=False
        )
        return Run(result.exit_code, result.stdout, result.stderr)

    def statusline(
        self, session_id: str = fx.SESSION_ID, *, transcript: Path | None = None,
        extra: Sequence[str] = (),
    ) -> Run:
        """`weir statusline` as Claude Code runs it: the session JSON on stdin."""
        payload = status_json(transcript or self.transcript(session_id), session_id)
        args = ["statusline", *self.inputs(), "--cache", str(self.state), *extra]
        return self.invoke(args, stdin=payload)

    def audit(self, session_id: str = fx.SESSION_ID) -> dict[str, object]:
        """`weir audit --json` over the session's files: the transcript and,
        when it exists, the session's own directory."""
        paths: list[Path | str] = [self.transcript(session_id)]
        if self.session_dir(session_id).is_dir():
            paths.append(self.session_dir(session_id))
        run = self.setup.audit(paths)
        assert run.exit_code in (0, 1, 3), run.stderr
        return run.report


def build(root: Path, *, bashrc: str | None = None) -> Claude:
    setup = fx.build(root, bashrc=bashrc)
    config = setup.home / ".claude"
    (config / "projects" / PROJECT).mkdir(parents=True)
    return Claude(setup=setup, config=config, state=setup.home / ".weir" / "statusline")


def status_json(transcript: Path, session_id: str) -> str:
    """The JSON Claude Code passes a status line command on stdin (the
    documented fields this command reads, plus a few it ignores)."""
    return json.dumps({
        "session_id": session_id,
        "transcript_path": str(transcript),
        "cwd": "/fake/home/work/proj",
        "model": {"id": "fake-model", "display_name": "Fake"},
        "workspace": {"current_dir": "/fake/home/work/proj"},
        "context_window": {"used_percentage": 12},
    })


# --- the counting rule (docs/statusline.md, "The segment") --------------------


def groups(setup: fx.Setup) -> dict[str, str]:
    """Credential id -> the credential it stands for: ids whose stored
    fingerprints are equal are one value, and environment records of the
    inventory report that share a variable name are one variable. An id
    linked to no other is its own group."""
    store = json.loads(setup.store.read_text())
    report = json.loads(setup.report.read_text())
    links: dict[str, set[str]] = {}
    for record in store["records"]:
        links.setdefault("fingerprint:" + record["fingerprint"], set()).add(record["credential_id"])
    for c in report["credentials"]:
        if c["source"] == "environment":
            links.setdefault("name:" + c["name"], set()).add(c["id"])
    group = {c["id"]: {c["id"]} for c in report["credentials"]}
    for ids in links.values():
        merged = set[str]().union(*(group[cid] for cid in ids))
        for cid in merged:
            group[cid] = merged
    return {cid: min(members) for cid, members in group.items()}


def expected_counts(setup: fx.Setup, report: Mapping[str, object]) -> tuple[int, int, bool]:
    """(in context, sent, incomplete) from an audit report: a credential
    entered the context when it has a `context` hit, or a `tool_call` hit by
    value; it was sent when it has any `tool_call` hit, by value or by name.
    Credentials, not inventory records, are counted."""
    group = groups(setup)
    context: set[str] = set()
    sent: set[str] = set()
    for hit in report["hits"]:  # type: ignore[union-attr]
        cid = group[hit["credential"]]
        if hit["kind"] == "context" or (hit["kind"] == "tool_call" and hit["form"] != "name"):
            context.add(cid)
        if hit["kind"] == "tool_call":
            sent.add(cid)
    return len(context), len(sent), bool(report["unknown"])


def segment_for(counts: tuple[int, int, bool]) -> str:
    """The segment docs/statusline.md prints for finished counts."""
    context, sent, incomplete = counts
    if incomplete and not (context or sent):
        return "weir: unknown"
    line = f"weir: {context} in context, {sent} sent"
    return line + ", part unknown" if incomplete else line


# --- running a settings command the way Claude Code does ---------------------


def run_shell(command: str, stdin: str, env: Mapping[str, str]) -> Run:
    """Run a status line command in a shell, with the session JSON on stdin,
    as Claude Code does. The environment holds the fake home and PATH."""
    full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    proc = subprocess.run(
        ["sh", "-c", command], input=stdin.encode(), capture_output=True, env=full, timeout=120,
        check=False,
    )
    return Run(proc.returncode, proc.stdout.decode(), proc.stderr.decode())


def weir_command() -> str:
    """How setup is expected to start weir: this interpreter, `-m weir`."""
    return f"{sys.executable} -m weir"
