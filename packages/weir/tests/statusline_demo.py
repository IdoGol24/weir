"""The status line images' input: real `weir statusline` output over fake
sessions (docs/statusline.md).

FAKE DATA ONLY, built by statusline_fixtures under temporary directories:
the fake home and its inventory, a fake Claude config directory, and fake
sessions. In the animation's session the agent reads `.env` (a credential
enters the context), then reads lockfiles long enough that the status line
needs several refreshes to reach the end, then puts a second credential in
a `curl` command (sent in a tool call).

The status line runs in a process of its own, its output a pipe, as
Claude Code runs it, so it prints its colours. For the animation it runs
with `--budget-ms 0`, which reads exactly one step per run, so each run is
one refresh as Claude Code would show it. The only change to the real
output is the transcript's path: the temporary directory is the fake home,
so its prefix is written `~`, which keeps the bytes the same on every
machine and operating system.

The two status lines in the README are two more fake sessions,
one that holds no credential and one that reads one and sends another,
each run once beside a stand-in for an existing status line.

Regenerate docs/assets/statusline.svg and docs/assets/statusline-states.svg
with:

    PYTHONPATH=tests uv run python packages/weir/tests/statusline_demo.py
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import audit_fixtures as fx
import statusline_fixtures as sx
from _harness.statusline_svg import render_states_svg, render_statusline_svg

from weir.statusline.segment import SCANNING

ASSET = Path(__file__).parents[3] / "docs" / "assets" / "statusline.svg"
STATES_ASSET = ASSET.with_name("statusline-states.svg")
COMMAND = "/weir"
LOCKFILES = 8


def _session(claude: sx.Claude) -> None:
    v = claude.setup.values
    session = fx.Session()
    session.prompt("why does the deploy fail?")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\nDEBUG=1\n")
    for i in range(LOCKFILES):
        tool_id = f"toolu_l{i}"
        session.tool_use("Read", {"file_path": f"packages/app{i}/package-lock.json"}, tool_id)
        session.tool_result(tool_id, sx.dense_lockfile(20_000))
    session.tool_use("Bash", {"command": f"curl -H 'X-Token: {v[fx.GH]}' api.invalid"}, "toolu_02")
    session.tool_result("toolu_02", "{}")
    session.write(claude.transcript())


@dataclass(frozen=True)
class Outputs:
    frames: list[str]  # the status line's segment at each refresh, until finished
    report: list[str]  # the lines /weir prints
    values: list[str]  # the fake credential values the session holds


def outputs() -> Outputs:
    with tempfile.TemporaryDirectory() as tmp:
        claude = sx.build(Path(tmp))
        _session(claude)
        frames: list[str] = []
        while not frames or SCANNING in frames[-1]:
            assert len(frames) < 10, "the status line never finished reading the session"
            run = claude.statusline_process(extra=["--budget-ms", "0"])
            assert run.exit_code == 0, run.stderr
            frames.append(run.stdout.rstrip("\n"))
        report = claude.invoke(
            ["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID]
        )
        assert report.exit_code == 0, report.stderr
        transcript = claude.transcript()
        shown = "~/" + transcript.relative_to(claude.setup.home).as_posix()
        text = report.stdout.replace(str(transcript), shown)
        assert tmp not in text, "the report names a path the image would not reproduce"
        lines = text.rstrip("\n").splitlines()
        return Outputs(frames, lines, list(claude.setup.values.values()))


def render() -> str:
    out = outputs()
    return render_statusline_svg(out.frames, COMMAND, out.report)


def _clean_session(claude: sx.Claude) -> None:
    session = fx.Session()
    session.prompt("why does the deploy fail?")
    session.tool_use("Bash", {"command": "ls"}, "toolu_01")
    session.tool_result("toolu_01", "README.md\ndeploy.sh\n")
    session.write(claude.transcript())


def _exposed_session(claude: sx.Claude) -> None:
    v = claude.setup.values
    session = fx.Session()
    session.prompt("why does the deploy fail?")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\nDEBUG=1\n")
    session.tool_use("Bash", {"command": f"curl -H 'X-Token: {v[fx.GH]}' api.invalid"}, "toolu_02")
    session.tool_result("toolu_02", "{}")
    session.write(claude.transcript())


# A stand-in for an existing status line, as a context meter prints it.
# chr(37) is "%", which Windows' cmd.exe would read as a variable's start.
_STATES = [(_clean_session, "ctx 42"), (_exposed_session, "ctx 61")]


@dataclass(frozen=True)
class State:
    line: str  # the status line: the stand-in, then the segment beside it
    counts: tuple[int, int, bool]  # what `weir audit` of the session says
    values: list[str]  # the fake credential values the session holds


def states() -> list[State]:
    out: list[State] = []
    for make, stand_in in _STATES:
        with tempfile.TemporaryDirectory() as tmp:
            claude = sx.build(Path(tmp))
            make(claude)
            inner = sx.python_command(f"print('{stand_in}' + chr(37))")
            run = claude.statusline_process(extra=["--inner", inner])
            assert run.exit_code == 0, run.stderr
            line = run.stdout.rstrip("\n")
            assert SCANNING not in line, "the status line did not read the session in one run"
            counts = sx.expected_counts(claude.setup, claude.audit())
            out.append(State(line, counts, list(claude.setup.values.values())))
    return out


def render_states() -> str:
    return render_states_svg([state.line for state in states()])


if __name__ == "__main__":
    ASSET.write_text(render(), encoding="utf-8", newline="\n")
    STATES_ASSET.write_text(render_states(), encoding="utf-8", newline="\n")
