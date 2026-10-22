"""Acceptance tests for `weir statusline` (docs/statusline.md), written
before the implementation.

Each test builds a fake home, inventories it with the real `weir inventory`,
writes a fake Claude Code session in a fake Claude config directory, and
expects what the document says. What the segment should count is read from
a real `weir audit --json` run over the same session files, through the
counting rule, and checked against where the fixture put each value.

1. The segment counts the credentials that entered the context and the ones
   sent in a tool call, by value or by name, in the transcript, its subagent
   transcripts and saved tool outputs.
2. An unrecognised format is "unknown", never a false zero.
3. Neither the segment nor its cache holds a value or a 6-character run of one.
4. `setup` shows the exact change and writes nothing until an explicit yes;
   with yes it adds the segment beside the existing status line command.
5. `undo` restores the files setup changed, byte for byte.
6. The /weir report lists, per credential, its source, the turn and tool
   call, where it now sits, and advice; the installed /weir command runs it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

# --- 1. counts ---------------------------------------------------------------


def _counted_session(claude: sx.Claude) -> dict[str, set[str]]:
    """ACME read into the context, GH sent by value, PLAIN_SECRET sent by
    name. Returns the names the fixture put in each place."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\nDEBUG=1\n")
    session.tool_use("Bash", {"command": f"curl -H 'X-Token: {v[fx.GH]}' api.invalid"}, "toolu_02")
    session.tool_result("toolu_02", "{}")
    session.tool_use("Bash", {"command": f'curl -d "${fx.SPECIAL}" api.invalid'}, "toolu_03")
    session.tool_result("toolu_03", "{}")
    session.write(claude.transcript())
    return {"context": {fx.ACME, fx.GH}, "sent": {fx.GH, fx.SPECIAL}}


def _planned(claude: sx.Claude, plan: dict[str, set[str]]) -> tuple[int, int]:
    group = sx.groups(claude.setup)
    ids = claude.setup.ids
    return (
        len({group[ids[n]] for n in plan["context"]}), len({group[ids[n]] for n in plan["sent"]}),
    )


def test_counts_credentials_in_context_and_sent_in_a_tool_call(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    plan = _counted_session(claude)

    run = claude.statusline()

    expected = sx.expected_counts(claude.setup, claude.audit())
    assert expected[:2] == _planned(claude, plan)
    assert not expected[2]
    assert run.exit_code == 0
    assert run.stdout == sx.segment_for(expected) + "\n"


def test_one_variable_in_two_environment_records_counts_once(tmp_path: Path) -> None:
    claude = sx.build(tmp_path, bashrc=f'export {fx.GH}="$(gh auth token)"\n')
    report = json.loads(claude.setup.report.read_text())
    records = [c for c in report["credentials"] if c["name"] == fx.GH]
    assert {c["location"]["kind"] for c in records} == {"launch_env", "file"}
    session = fx.Session()
    session.prompt("call the api")
    session.tool_use("Bash", {"command": f'curl -H "Authorization: ${fx.GH}" x.invalid'}, "t1")
    session.write(claude.transcript())
    audit = claude.audit()
    assert all(fx.hits(audit, c["id"]) for c in records)

    run = claude.statusline()
    shown = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])

    expected = sx.expected_counts(claude.setup, audit)
    assert expected == (0, 1, False)
    assert run.stdout == sx.segment_for(expected) + "\n"
    assert shown.exit_code == 0, shown.stderr
    assert shown.lines[0] == sx.segment_for(expected)
    # One block for the one credential, listing every place it was found.
    places = ", ".join(c["location"]["display"] for c in records)
    blocks = _blocks(shown.stdout)
    assert [h for h in blocks if h.startswith(fx.GH)] == [f"{fx.GH} ({places})"]
    block = blocks[f"{fx.GH} ({places})"]
    for c in records:
        assert c["location"]["display"] in _field(block, "source")
    assert _field(block, "sent in a tool call").startswith("1 time by name, first at turn 1")


def test_subagent_transcripts_and_saved_outputs_are_read(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    main = fx.Session()
    main.prompt("delegate the check")
    main.tool_use("Task", {"prompt": "check the config"}, "toolu_01")
    main.tool_result("toolu_01", "done")
    main.write(claude.transcript())
    sub = fx.Session()
    sub.prompt("check the config")
    sub.tool_use("Bash", {"command": "cat ~/.aws/credentials"}, "toolu_s1")
    sub.tool_result("toolu_s1", f"aws_secret_access_key = {v[fx.AWS_SECRET]}\n")
    sub.write(claude.session_dir() / "subagents" / "agent-a1.jsonl")
    saved = claude.session_dir() / "tool-results" / "toolu_09.txt"
    saved.parent.mkdir(parents=True)
    cfx.write(saved, f"{fx.GH}={v[fx.GH]}\n")

    run = claude.statusline()

    report = claude.audit()
    expected = sx.expected_counts(claude.setup, report)
    # The subagent's read is in the context; the saved output alone is stored.
    assert expected == (1, 0, False)
    states = {c["id"]: c["state"] for c in report["credentials"]}  # type: ignore[union-attr]
    assert states[claude.setup.ids[fx.AWS_SECRET]] == "in_context"
    assert states[claude.setup.ids[fx.GH]] == "stored"
    assert run.stdout == sx.segment_for(expected) + "\n"


def test_records_appended_after_a_run_are_counted_on_the_next(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\n")
    session.write(claude.transcript())
    first = claude.statusline()
    assert first.stdout == sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"

    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_02")
    session.write(claude.transcript())
    second = claude.statusline()

    expected = sx.expected_counts(claude.setup, claude.audit())
    assert expected == (2, 1, False)
    assert second.stdout == sx.segment_for(expected) + "\n"


def test_a_long_session_is_read_over_several_runs_and_never_shows_a_false_count(
    tmp_path: Path,
) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("read the logs")
    for n in range(12):
        session.tool_use("Read", {"file_path": f"/fake/log{n}.txt"}, f"toolu_{n:02d}")
        filler = "".join(f"{n:02d} line {i} of a long fake log\n" for i in range(800))
        session.tool_result(f"toolu_{n:02d}", filler)
    session.tool_use("Bash", {"command": f"cat <<< {v[fx.ACME]}"}, "toolu_99")
    session.write(claude.transcript())

    outputs: list[str] = []
    for _ in range(200):
        run = claude.statusline(extra=["--budget-ms", "0"])
        assert run.exit_code == 0
        outputs.append(run.stdout)
        if "checking" not in run.stdout:
            break

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    assert outputs[-1] == expected
    assert len(outputs) > 2, "the session should take several runs at a zero budget"
    for partial in outputs[:-1]:
        assert re.fullmatch(r"weir: (\d+ in context, \d+ sent, )?checking \d+%\n", partial)


# --- 2. unknown, never a false zero --------------------------------------------


def test_an_unrecognised_file_in_the_session_is_unknown_not_zero(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("list the files here")
    session.tool_use("Bash", {"command": "ls"}, "toolu_01")
    session.tool_result("toolu_01", "README.md\n")
    session.write(claude.transcript())
    odd = claude.session_dir() / "notes.dat"
    odd.parent.mkdir(parents=True)
    cfx.write(odd, "an opaque record format\n")

    run = claude.statusline()

    report = claude.audit()
    assert report["result"] == "unknown"
    assert run.stdout == "weir: unknown\n"
    assert run.stdout == sx.segment_for(sx.expected_counts(claude.setup, report)) + "\n"


def test_an_unrecognised_transcript_is_unknown_not_zero(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    cfx.write(claude.transcript(), "this is not a session\nnor is this\n")

    run = claude.statusline()

    assert claude.audit()["result"] == "unknown"
    assert run.stdout == "weir: unknown\n"


def test_a_missing_transcript_is_unknown_not_zero(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)

    run = claude.statusline()

    assert run.exit_code == 0
    assert run.stdout == "weir: unknown\n"


def test_found_credentials_beside_an_unknown_file_are_marked_part_unknown(
    tmp_path: Path,
) -> None:
    claude = sx.build(tmp_path)
    plan = _counted_session(claude)
    odd = claude.session_dir() / "notes.dat"
    odd.parent.mkdir(parents=True)
    cfx.write(odd, "an opaque record format\n")

    run = claude.statusline()

    expected = sx.expected_counts(claude.setup, claude.audit())
    assert expected == (*_planned(claude, plan), True)
    assert run.stdout == sx.segment_for(expected) + "\n"
    assert run.stdout.endswith(", part unknown\n")


# --- 3. no value, anywhere ---------------------------------------------------


def test_neither_the_segment_nor_its_cache_holds_a_value(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt(f"use {v[fx.GH]} for github")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.AWS_ID} = {v[fx.AWS_ID]}\n")
    session.tool_use(v[fx.ACME], {v[fx.ACME]: "x", "q": json.dumps({"s": v[fx.SPECIAL]})}, "t2")
    session.record({"type": v[fx.GH], "sessionId": fx.SESSION_ID, "note": v[fx.ACME]})
    session.write(claude.transcript())
    named = claude.session_dir() / "tool-results" / f"{v[fx.ACME]}.txt"
    named.parent.mkdir(parents=True)
    cfx.write(named, f"x {v[fx.GH]}\n")

    runs = [claude.statusline(), claude.statusline(), claude.statusline(extra=["--budget-ms", "0"])]

    for run in runs:
        assert run.exit_code == 0
        assert run.stdout.startswith("weir: ")
        cfx.assert_value_free(run.stdout + "\n" + run.stderr, v.values())
    cached = sorted(p for p in claude.state.rglob("*") if p.is_file())
    assert cached, "the status line should keep a cache"
    for path in cached:
        text = path.read_bytes().decode("utf-8", "replace")
        cfx.assert_value_free(path.name + "\n" + text, v.values())


# --- 4. setup: a dry run, an explicit yes ----------------------------------------

_EXISTING = {
    "statusLine": {
        "type": "command", "command": "cat >/dev/null; printf 'existing status\\n'", "padding": 1,
    },
    "permissions": {"deny": ["Read(./secrets/**)"]},
}


def _existing_settings(claude: sx.Claude) -> bytes:
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    # Four-space indent and no trailing newline: formatting setup must not need.
    data = json.dumps(_EXISTING, indent=4).encode()
    claude.settings.write_bytes(data)
    return data


def _setup(claude: sx.Claude, *flags: str, answer: str | None = None) -> sx.Run:
    args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
            "--claude-dir", str(claude.config), *flags]
    return claude.invoke(args, stdin=answer)


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_setup_dry_run_shows_the_change_and_writes_nothing(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _existing_settings(claude)
    before = _snapshot(claude.setup.home)

    dry = _setup(claude, "--dry-run")
    declined = _setup(claude, answer="no\n")
    silent = _setup(claude, answer="")

    for run in (dry, declined, silent):
        assert run.exit_code == 0, run.stderr
        assert str(claude.settings) in run.stdout
        assert "existing status" in run.stdout
        assert "statusline" in run.stdout
        assert str(claude.command_file) in run.stdout
    assert _snapshot(claude.setup.home) == before
    assert not claude.command_file.exists()


@pytest.mark.parametrize("answer", ["y\n", "Y\n", "YES\n", "Yes\n", "yes please\n"])
def test_setup_applies_only_on_the_exact_answer_yes(tmp_path: Path, answer: str) -> None:
    claude = sx.build(tmp_path)
    _existing_settings(claude)
    before = _snapshot(claude.setup.home)

    run = _setup(claude, answer=answer)

    assert run.exit_code == 0, run.stderr
    assert _snapshot(claude.setup.home) == before
    assert not claude.command_file.exists()


def test_setup_with_yes_adds_the_segment_beside_the_existing_command(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _existing_settings(claude)
    plan = _counted_session(claude)

    run = _setup(claude, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    settings = json.loads(claude.settings.read_text())
    line = settings["statusLine"]
    # Everything else is kept as it was.
    assert {k: v for k, v in settings.items() if k != "statusLine"} == {
        k: v for k, v in _EXISTING.items() if k != "statusLine"
    }
    assert line["type"] == "command"
    assert line["padding"] == _EXISTING["statusLine"]["padding"]
    assert line["command"].startswith(sx.weir_command() + " statusline ")
    assert claude.command_file.is_file()

    # The command Claude Code will now run prints the existing status line
    # and the weir segment beside it.
    shown = sx.run_shell(
        line["command"], sx.status_json(claude.transcript(), fx.SESSION_ID), claude.env()
    )
    expected = sx.expected_counts(claude.setup, claude.audit())
    assert expected[:2] == _planned(claude, plan)
    assert shown.exit_code == 0, shown.stderr
    assert shown.stdout == "existing status | " + sx.segment_for(expected) + "\n"


def test_setup_with_no_status_line_adds_the_segment_alone(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _counted_session(claude)

    run = _setup(claude, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    command = json.loads(claude.settings.read_text())["statusLine"]["command"]
    shown = sx.run_shell(command, sx.status_json(claude.transcript(), fx.SESSION_ID), claude.env())
    expected = sx.expected_counts(claude.setup, claude.audit())
    assert shown.stdout == sx.segment_for(expected) + "\n"


# --- 5. undo -------------------------------------------------------------------


def _undo(claude: sx.Claude, *flags: str, answer: str | None = None) -> sx.Run:
    return claude.invoke(
        ["statusline", "undo", "--cache", str(claude.state), *flags], stdin=answer
    )


def test_undo_restores_the_original_bytes(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    original = _existing_settings(claude)
    assert _setup(claude, answer="yes\n").exit_code == 0
    assert claude.settings.read_bytes() != original
    setup_done = _snapshot(claude.setup.home)

    dry = _undo(claude, "--dry-run")
    assert dry.exit_code == 0
    assert _snapshot(claude.setup.home) == setup_done

    run = _undo(claude, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    assert claude.settings.read_bytes() == original
    assert not claude.command_file.exists()
    assert not claude.command_file.parent.exists()


def test_undo_removes_a_settings_file_setup_created(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    before = _snapshot(claude.config)
    assert _setup(claude, answer="yes\n").exit_code == 0
    assert claude.settings.is_file()

    run = _undo(claude, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    assert not claude.settings.exists()
    assert _snapshot(claude.config) == before


def test_undo_refuses_when_the_settings_changed_after_setup(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _existing_settings(claude)
    assert _setup(claude, answer="yes\n").exit_code == 0
    later = b'"theme": "dark", "permissions"'
    edited = claude.settings.read_bytes().replace(b'"permissions"', later)
    claude.settings.write_bytes(edited)

    run = _undo(claude, answer="yes\n")

    assert run.exit_code != 0
    assert claude.settings.read_bytes() == edited
    assert str(claude.settings) in run.stdout + run.stderr


# --- 6. the /weir report ---------------------------------------------------------


def _report_session(claude: sx.Claude) -> dict[str, tuple[int, int]]:
    """Returns name -> (turn, line) where the fixture put each value."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("hello")
    session.assistant_text("hi")
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    acme, _ = session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\n")
    aws = session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "t2")
    session.tool_result("t2", "ok")
    session.prompt("now call the api")
    gh = session.tool_use("Bash", {"command": f'curl -H "Authorization: ${fx.GH}" x.invalid'}, "t3")
    session.write(claude.transcript())
    return {fx.ACME: (2, acme), fx.AWS_SECRET: (2, aws), fx.GH: (3, gh)}


def _labels(claude: sx.Claude) -> dict[str, tuple[str, str]]:
    """Name -> (heading, source location) as the inventory report names them."""
    report = json.loads(claude.setup.report.read_text())
    out: dict[str, tuple[str, str]] = {}
    for c in report["credentials"]:
        display = c["location"]["display"]
        where = display if c.get("scope") is None else f"{display} {c['scope']}"
        out[c["name"]] = (f"{c['name']} ({where})", display)
    return out


def _blocks(stdout: str) -> dict[str, list[str]]:
    """The report's per-credential blocks: a heading, then indented lines."""
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in stdout.splitlines():
        if line and not line.startswith(" "):
            current = blocks.setdefault(line, [])
        elif line.startswith("  ") and current is not None:
            current.append(line.strip())
    return blocks


def _field(block: list[str], name: str) -> str:
    (value,) = [line[len(name) + 2 :] for line in block if line.startswith(name + ": ")]
    return value


def test_the_weir_report_lists_source_turn_tool_call_location_and_advice(
    tmp_path: Path,
) -> None:
    claude = sx.build(tmp_path)
    placed = _report_session(claude)
    labels = _labels(claude)
    transcript = str(claude.transcript())

    run = claude.invoke(
        ["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID]
    )

    assert run.exit_code == 0, run.stderr
    cfx.assert_value_free(run.stdout + run.stderr, claude.setup.values.values())
    expected = sx.expected_counts(claude.setup, claude.audit())
    assert run.lines[0] == sx.segment_for(expected)
    blocks = _blocks(run.stdout)

    heading, source = labels[fx.ACME]
    turn, line = placed[fx.ACME]
    acme = blocks[heading]
    assert source in _field(acme, "source")
    entered = _field(acme, "entered the context")
    assert f"turn {turn}" in entered and "Bash tool result" in entered
    assert f"{transcript}:{line}" in entered
    assert transcript in _field(acme, "now sits in")
    assert "rotate" in _field(acme, "advice")

    heading, source = labels[fx.AWS_SECRET]
    turn, line = placed[fx.AWS_SECRET]
    aws = blocks[heading]
    assert source in _field(aws, "source")
    sent = _field(aws, "sent in a tool call")
    assert f"turn {turn}" in sent and "Bash tool call" in sent and "argument command" in sent
    assert f"{transcript}:{line}" in sent
    assert transcript in _field(aws, "now sits in")
    advice = _field(aws, "advice")
    assert "rotate" in advice and source in advice

    heading, source = labels[fx.GH]
    turn, line = placed[fx.GH]
    gh = blocks[heading]
    sent = _field(gh, "sent in a tool call")
    assert f"turn {turn}" in sent and "by name" in sent and f"{transcript}:{line}" in sent
    assert "entered the context" not in {line.split(":")[0] for line in gh}
    assert "rotate" in _field(gh, "advice")


def test_the_installed_weir_command_runs_the_report(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _report_session(claude)
    assert _setup(claude, answer="yes\n").exit_code == 0

    text = claude.command_file.read_text()
    (command,) = re.findall(r"^!`(.+)`$", text, flags=re.MULTILINE)
    assert "${CLAUDE_SESSION_ID}" in command
    shown = sx.run_shell(
        command.replace("${CLAUDE_SESSION_ID}", fx.SESSION_ID), "", claude.env()
    )

    direct = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])
    assert shown.exit_code == 0, shown.stderr
    assert shown.stdout == direct.stdout
    cfx.assert_value_free(text, claude.setup.values.values())


@pytest.mark.parametrize("session_id", ["../escape", "", "a/b"])
def test_the_report_refuses_a_session_id_that_is_not_one(tmp_path: Path, session_id: str) -> None:
    claude = sx.build(tmp_path)

    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", session_id])

    assert run.exit_code == 2
    assert "not a session id" in run.stderr
