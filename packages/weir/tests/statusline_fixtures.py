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

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import audit_fixtures as fx
import pytest
from click.testing import CliRunner

from weir.cli.main import main

PROJECT = "-fake-home-work-proj"

# docs/statusline.md, "Setup and undo": setup supports POSIX shells only.
posix_shell = pytest.mark.skipif(
    os.name != "posix", reason="weir statusline setup supports POSIX shells only"
)


# The segment's words without its colours (docs/statusline.md, "The segment").
NO_COLOR = {"NO_COLOR": "1"}


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

    def project(self) -> str:
        """The project folder the inventory walked, as its report names it."""
        project = json.loads(self.setup.report.read_text())["inputs"]["project"]
        assert isinstance(project, str)
        return project

    def env(self) -> dict[str, str]:
        """The environment the commands run with: the fake home only, as
        Path.home() reads it on POSIX (HOME) and on Windows (USERPROFILE)."""
        home = str(self.setup.home)
        return {"HOME": home, "USERPROFILE": home, "CLAUDE_CONFIG_DIR": str(self.config)}

    def invoke(
        self, args: Sequence[str], stdin: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Run:
        result = CliRunner().invoke(
            main, list(args), input=stdin, env={**self.env(), **(env or {})},
            catch_exceptions=False,
        )
        return Run(result.exit_code, result.stdout, result.stderr)

    def report(
        self, session_id: str = fx.SESSION_ID, *, folder: str | None = None,
        cwd: str | None = None,
    ) -> Run:
        """`weir statusline report` as /weir runs it, once the status line
        ran for the session with its project folder `folder`, else the
        inventory's project ("": the status line has not run), from the
        session shell's folder `cwd`, else the inventory's project."""
        if folder != "":
            self.statusline(session_id, folder=folder, extra=["--budget-ms", "0"])
        args = ["statusline", "report", *self.inputs(), "--session", session_id,
                "--cache", str(self.state)]
        with contextlib.chdir(cwd or self.project()):
            return self.invoke(args)

    def statusline(
        self, session_id: str = fx.SESSION_ID, *, transcript: Path | None = None,
        extra: Sequence[str] = (), folder: str | None = None,
    ) -> Run:
        """`weir statusline` as Claude Code runs it: the session JSON on stdin,
        its project folder `folder`, else the inventory's project. Its words
        only, NO_COLOR set: test_statusline_look.py checks the colours."""
        payload = status_json(
            transcript or self.transcript(session_id), session_id, folder or self.project()
        )
        args = ["statusline", *self.inputs(), "--cache", str(self.state), *extra]
        return self.invoke(args, stdin=payload, env=NO_COLOR)

    def process(
        self, args: Sequence[str], stdin: str = "", env: Mapping[str, str] | None = None
    ) -> Run:
        """weir in a process of its own, its output a pipe, as Claude Code
        reads a status line command: the fake home, and NO_COLOR only when
        `env` sets it."""
        full = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
        full.update({**self.env(), **(env or {})})
        proc = subprocess.run(
            [sys.executable, "-m", "weir", *args], input=stdin.encode(), capture_output=True,
            env=full, timeout=120, check=False,
        )
        return Run(
            proc.returncode,
            proc.stdout.decode().replace("\r\n", "\n"),
            proc.stderr.decode().replace("\r\n", "\n"),
        )

    def statusline_process(
        self, *, env: Mapping[str, str] | None = None, extra: Sequence[str] = ()
    ) -> Run:
        """`weir statusline` in a process of its own, the session JSON on stdin."""
        payload = status_json(self.transcript(), fx.SESSION_ID, self.project())
        args = ["statusline", *self.inputs(), "--cache", str(self.state), *extra]
        return self.process(args, payload, env)

    def audit(self, session_id: str = fx.SESSION_ID) -> dict[str, object]:
        """`weir audit --json` over the session's files: the transcript and,
        when it exists, the session's own directory."""
        paths: list[Path | str] = [self.transcript(session_id)]
        if self.session_dir(session_id).is_dir():
            paths.append(self.session_dir(session_id))
        run = self.setup.audit(paths)
        assert run.exit_code in (0, 1, 3), run.stderr
        return run.report


def dense_lockfile(size: int) -> str:
    """About `size` characters of a fake lockfile: package names and
    integrity hashes, every hash a candidate the audit checks."""
    lines: list[str] = []
    length = 0
    while length < size:
        n = len(lines)
        line = f'  "pkg-{n}": "sha512-{hashlib.sha512(str(n).encode()).hexdigest()}"\n'
        lines.append(line)
        length += len(line)
    return "".join(lines)


def tool_result_and_copy(session: fx.Session, tool_id: str, text: str) -> int:
    """A tool result as Claude Code writes it: in the message, and again in
    the record's `toolUseResult`."""
    block = {"type": "tool_result", "tool_use_id": tool_id, "content": text}
    envelope = session._envelope("user", message={"role": "user", "content": [block]})  # pyright: ignore[reportPrivateUsage]
    return session.record({**envelope, "toolUseResult": {"stdout": text, "stderr": ""}})


def build(root: Path, *, bashrc: str | None = None, extra_env: str = "") -> Claude:
    setup = fx.build(root, bashrc=bashrc, extra_env=extra_env)
    config = setup.home / ".claude"
    (config / "projects" / PROJECT).mkdir(parents=True)
    return Claude(setup=setup, config=config, state=setup.home / ".weir" / "statusline")


def without_credentials(claude: Claude, *, bashrc: str | None = None) -> None:
    """Point `claude` at a real `weir inventory` of an empty fake home and
    an empty launch environment: an inventory that holds no credential, or
    only what `bashrc`, the fake home's shell startup file, names."""
    root = claude.setup.root / "empty"
    project = root / "home" / "work" / "proj"
    project.mkdir(parents=True)
    if bashrc is not None:
        (root / "home" / ".bashrc").write_text(bashrc)
    env = root / "launch.env"
    env.write_text("")
    out = root / "inventory"
    out.mkdir()
    report, store, key = out / "inventory.json", out / "store.json", out / "fingerprint.key"
    result = CliRunner().invoke(
        main,
        [
            "inventory", "--home", str(root / "home"), "--project", str(project),
            "--env-file", str(env), "--key", str(key), "--store", str(store), "--json",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.stderr
    report.write_text(result.stdout)
    ids = {c["name"]: c["id"] for c in json.loads(result.stdout)["credentials"]}
    claude.setup = dataclasses.replace(claude.setup, report=report, store=store, key=key, ids=ids)


def status_json(transcript: Path, session_id: str, folder: str | None) -> str:
    """The JSON Claude Code passes a status line command on stdin (the
    documented fields this command reads, plus a few it ignores), the
    session's project folder `folder`, or none."""
    workspace = {} if folder is None else {"current_dir": folder, "project_dir": folder}
    return json.dumps({
        "session_id": session_id,
        "transcript_path": str(transcript),
        **({} if folder is None else {"cwd": folder}),
        "model": {"id": "fake-model", "display_name": "Fake"},
        "workspace": workspace,
        "context_window": {"used_percentage": 12},
    })


# --- the counting rule (docs/statusline.md, "The segment") --------------------


def groups(setup: fx.Setup) -> dict[str, str]:
    """Credential id -> the value it holds, as the store links them: ids
    whose stored fingerprints are equal are one value. An id the store holds
    no fingerprint for is its own group."""
    store = json.loads(setup.store.read_text())
    report = json.loads(setup.report.read_text())
    out = {c["id"]: c["id"] for c in report["credentials"]}
    for record in store["records"]:
        out[record["credential_id"]] = "fingerprint:" + record["fingerprint"]
    return out


def expected_counts(setup: fx.Setup, report: Mapping[str, object]) -> tuple[int, int, bool]:
    """(in context, sent, incomplete) from an audit report, by the rule of
    docs/statusline.md, "What is counted": values, not inventory records; a
    `context` or `tool_call` hit put a value in the context, a `tool_call`
    hit sent it."""
    group = groups(setup)
    context: set[str] = set()
    sent: set[str] = set()
    for hit in report["hits"]:  # type: ignore[union-attr]
        if hit["kind"] in ("context", "tool_call"):
            context.add(group[hit["credential"]])
        if hit["kind"] == "tool_call":
            sent.add(group[hit["credential"]])
    return len(context), len(sent), bool(report["unknown"])


# docs/statusline.md, "Colours": the SGR code each part is drawn in.
GREEN, AMBER, RED, DIM = 32, 33, 31, 2
POINTER = "→ /weir"
# A record too long to search within a run
PARTLY_CHECKED = f"weir partly checked {POINTER}"
_SGR = re.compile(r"\x1b\[[0-9;]*m")


def paint(text: str, sgr: int, colour: bool) -> str:
    """`text` drawn in `sgr` and reset after, or plain."""
    return f"\x1b[{sgr}m{text}\x1b[0m" if colour else text


def plain(line: str) -> str:
    """`line` without its SGR codes."""
    return _SGR.sub("", line)


_PAINTED = re.compile(r"\x1b\[0m|\x1b\[(\d+)m([^\x1b]*)\x1b\[0m|([^\x1b]+)")


def spans(line: str) -> list[tuple[str, int | None]]:
    """`line` as its parts: each one's text and SGR code (None: no colour).
    A line that is not text, painted parts and resets is refused."""
    found = [
        (m[2], int(m[1])) if m[1] else (m[3], None)
        for m in _PAINTED.finditer(line) if m[1] or m[3]
    ]
    assert "".join(text for text, _ in found) == plain(line), f"not plain or painted: {line!r}"
    return found


def assert_painted(el: ET.Element, line: str) -> None:
    """The SVG <text> `el` shows `line`, a real segment's output: one
    <tspan> per part, in the fill its SGR code is drawn in."""
    from _harness.statusline_svg import SGR_FILLS, TEXT_FILL  # the images' tests only

    tspan = "{http://www.w3.org/2000/svg}tspan"
    assert "".join(el.itertext()) == plain(line)
    assert [(t.text, t.get("fill")) for t in el.iter(tspan)] == [
        (text, TEXT_FILL if code is None else SGR_FILLS[code]) for text, code in spans(line)
    ]


def counts_for(context: int, sent: int, *, colour: bool = False) -> str:
    """The counts docs/statusline.md shows: amber, red, a zero dim."""
    return (
        f"{paint('⚠', AMBER, colour)} "
        f"{paint(f'{context} in context', AMBER if context else DIM, colour)} · "
        f"{paint(f'{sent} sent', RED if sent else DIM, colour)}"
    )


def segment_for(
    counts: tuple[int, int, bool], *, colour: bool = False, pointer: bool = True,
    inside: bool = True,
) -> str:
    """The segment docs/statusline.md prints for finished counts, in the
    inventory's project or, not `inside`, outside it; the /weir report's
    first line without the pointer."""
    context, sent, incomplete = counts
    if not (context or sent):
        if incomplete:
            return f"weir {paint('unknown', DIM, colour)}"
        if not inside:
            return f"weir {paint('project not inventoried', DIM, colour)}"
        return f"weir {paint('✓ no known key seen', GREEN, colour)}"
    line = f"weir {counts_for(context, sent, colour=colour)}"
    if incomplete:
        line += f" · {paint('part unknown', DIM, colour)}"
    return f"{line} {POINTER}" if pointer else line


# A refresh before the files are read to their end, its SGR codes taken out.
SCANNING_LINE = re.compile(r"weir (⚠ \d+ in context · \d+ sent · )?scanning… \d+%")


# --- running a settings command the way Claude Code does ---------------------


def run_shell(
    command: str, stdin: str, env: Mapping[str, str], cwd: str | None = None
) -> Run:
    """Run a status line command in a shell, with the session JSON on stdin,
    as Claude Code does, from `cwd`, else this directory. The environment
    holds the fake home and PATH. Windows' "\r\n" line ends in the output
    read back as "\n"."""
    full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    proc = subprocess.run(
        ["sh", "-c", command], input=stdin.encode(), capture_output=True, env=full, timeout=120,
        cwd=cwd, check=False,
    )

    def text(data: bytes) -> str:
        return data.decode().replace("\r\n", "\n")

    return Run(proc.returncode, text(proc.stdout), text(proc.stderr))


def weir_command() -> str:
    """How setup is expected to start weir: this interpreter, quoted for
    the shell, `-m weir`."""
    return f"{shlex.quote(sys.executable)} -m weir"


def python_command(code: str) -> str:
    """A command that runs `code` in this interpreter, the same in a POSIX
    shell and in Windows' cmd.exe (the shell `run_beside` uses there).
    `code` holds no double quote."""
    return f'"{sys.executable}" -c "{code}"'
