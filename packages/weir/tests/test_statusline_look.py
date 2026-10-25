"""How the segment looks (docs/statusline.md, "The segment"), written
before the implementation.

Each state has its words, its icon and its colours, drawn with ANSI SGR
codes that Claude Code's status line renders, every coloured part reset
after itself so the status line beside it keeps its own colours. With
NO_COLOR set the words and symbols are the same and there is no escape
code. Only a session read to its end with nothing found, in the
inventory's project, says "no known key seen" in green; what is unread,
unknown, partly checked or outside that project never does.

The words come from docs/statusline.md, "The segment", through
statusline_fixtures.segment_for; the end-to-end tests run weir in a
process of its own, its output a pipe, as Claude Code runs it.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import re
import shlex
import sys
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

from weir.statusline.segment import segment_text

G, A, R, D = sx.GREEN, sx.AMBER, sx.RED, sx.DIM


def _p(text: str, sgr: int) -> str:
    return sx.paint(text, sgr, True)


# (segment_text arguments, the line without colour, the line with it)
_STATES: list[tuple[dict[str, object], str, str]] = [
    (
        {"context": 0, "sent": 0, "unknown": False},
        "weir ✓ no known key seen",
        f"weir {_p('✓ no known key seen', G)}",
    ),
    (
        {"context": 2, "sent": 1, "unknown": False},
        "weir ⚠ 2 in context · 1 sent → /weir",
        f"weir {_p('⚠', A)} {_p('2 in context', A)} · {_p('1 sent', R)} → /weir",
    ),
    (
        {"context": 1, "sent": 0, "unknown": False},
        "weir ⚠ 1 in context · 0 sent → /weir",
        f"weir {_p('⚠', A)} {_p('1 in context', A)} · {_p('0 sent', D)} → /weir",
    ),
    (
        {"context": 2, "sent": 1, "unknown": True},
        "weir ⚠ 2 in context · 1 sent · part unknown → /weir",
        f"weir {_p('⚠', A)} {_p('2 in context', A)} · {_p('1 sent', R)} · "
        f"{_p('part unknown', D)} → /weir",
    ),
    (
        {"context": 0, "sent": 0, "unknown": True},
        "weir unknown",
        f"weir {_p('unknown', D)}",
    ),
    (
        {"context": 0, "sent": 0, "unknown": False, "inventoried": False},
        "weir project not inventoried",
        f"weir {_p('project not inventoried', D)}",
    ),
    (
        {"context": 2, "sent": 1, "unknown": False, "inventoried": False},
        "weir ⚠ 2 in context · 1 sent → /weir",
        f"weir {_p('⚠', A)} {_p('2 in context', A)} · {_p('1 sent', R)} → /weir",
    ),
    (
        {"context": 0, "sent": 0, "unknown": False, "partial": True},
        "weir partly checked → /weir",
        f"weir {_p('partly checked → /weir', D)}",
    ),
    (
        {"context": 2, "sent": 1, "unknown": False, "partial": True},
        "weir partly checked → /weir",
        f"weir {_p('partly checked → /weir', D)}",
    ),
    (
        {"context": 0, "sent": 0, "unknown": False, "scanning": 40},
        "weir scanning… 40%",
        f"weir {_p('scanning… 40%', D)}",
    ),
    (
        {"context": 0, "sent": 0, "unknown": True, "scanning": 0},
        "weir scanning… 0%",
        f"weir {_p('scanning… 0%', D)}",
    ),
    (
        {"context": 1, "sent": 0, "unknown": False, "scanning": 55},
        "weir ⚠ 1 in context · 0 sent · scanning… 55%",
        f"weir {_p('⚠', A)} {_p('1 in context', A)} · {_p('0 sent', D)} · "
        f"{_p('scanning… 55%', D)}",
    ),
]


@pytest.mark.parametrize(("args", "words", "coloured"), _STATES)
def test_each_state_has_its_words_and_colours(
    args: dict[str, object], words: str, coloured: str
) -> None:
    args = {"inventoried": True, **args}
    assert segment_text(**args, colour=False) == words  # type: ignore[arg-type]
    assert segment_text(**args, colour=True) == coloured  # type: ignore[arg-type]


# Text, or one SGR code this document names, its text, and a reset.
_SPANS = re.compile(r"(?:[^\x1b]|\x1b\[(?:32|33|31|2)m[^\x1b]+\x1b\[0m)*")


def _every_state() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for context, sent, unknown, partial, scanning, inventoried in itertools.product(
        range(3), range(3), (False, True), (False, True), (None, 0, 55), (False, True)
    ):
        if sent <= context:  # a value sent in a tool call is in the context
            out.append({
                "context": context, "sent": sent, "unknown": unknown, "partial": partial,
                "scanning": scanning, "inventoried": inventoried,
            })
    return out


@pytest.mark.parametrize("args", _every_state())
def test_only_a_clean_session_read_to_its_end_says_no_known_key_seen(
    args: dict[str, object],
) -> None:
    coloured = segment_text(**args, colour=True)  # type: ignore[arg-type]
    words = segment_text(**args, colour=False)  # type: ignore[arg-type]
    # Every coloured part is one this document names and is reset after
    # itself; without colour the words and symbols are the same.
    assert _SPANS.fullmatch(coloured), coloured
    assert "\x1b" not in words
    assert sx.plain(coloured) == words
    assert words.startswith("weir ")
    finished = (
        args["context"] == args["sent"] == 0
        and not args["unknown"] and not args["partial"] and args["scanning"] is None
    )
    clean = finished and args["inventoried"]
    assert ("✓" in words) is clean
    assert ("no known key seen" in words) is clean
    assert (f"\x1b[{G}m" in coloured) is clean
    if args["partial"]:
        # Partly checked is never a number and never green.
        assert words == sx.PARTLY_CHECKED
    elif args["scanning"] is not None:
        assert sx.SCANNING_LINE.fullmatch(words), words
        assert words.endswith(f"{args['scanning']}%")
    elif args["unknown"] and not args["context"]:
        assert words == "weir unknown"  # never a zero
    elif finished and not args["inventoried"]:
        assert words == "weir project not inventoried"  # outside its project: never green
    assert not re.search(r"\d", words) or "in context" in words or "scanning" in words


@pytest.mark.parametrize("args", _every_state())
def test_without_the_pointer_the_words_are_the_same(args: dict[str, object]) -> None:
    if args["partial"] or args["scanning"] is not None:
        return  # the report reads the whole session: never partly checked or scanning
    pointed = segment_text(**args, colour=False)  # type: ignore[arg-type]
    bare = segment_text(**args, colour=False, pointer=False)  # type: ignore[arg-type]
    assert "→" not in bare
    assert pointed in (bare, f"{bare} {sx.POINTER}")


# --- end to end: weir in a process of its own, as Claude Code runs it --------


def _exposed(claude: sx.Claude) -> None:
    """ACME read into the context, GH sent in a tool call."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\nDEBUG=1\n")
    session.tool_use("Bash", {"command": f"curl -H 'X-Token: {v[fx.GH]}' api.invalid"}, "toolu_02")
    session.tool_result("toolu_02", "{}")
    session.write(claude.transcript())


def _clean(claude: sx.Claude) -> None:
    session = fx.Session()
    session.prompt("list the files here")
    session.tool_use("Bash", {"command": "ls"}, "toolu_01")
    session.tool_result("toolu_01", "README.md\n")
    session.write(claude.transcript())


def _unknown(claude: sx.Claude) -> None:
    cfx.write(claude.transcript(), "this is not a session\nnor is this\n")


@pytest.mark.parametrize("make", [_exposed, _clean, _unknown])
def test_the_segment_is_coloured_on_the_pipe_and_plain_with_no_color(
    tmp_path: Path, make: object
) -> None:
    claude = sx.build(tmp_path)
    make(claude)  # type: ignore[operator]
    expected = sx.expected_counts(claude.setup, claude.audit())

    coloured = claude.statusline_process()
    empty = claude.statusline_process(env={"NO_COLOR": ""})
    off = claude.statusline_process(env={"NO_COLOR": "1"})

    assert coloured.exit_code == off.exit_code == 0, coloured.stderr + off.stderr
    assert coloured.stdout == sx.segment_for(expected, colour=True) + "\n"
    # NO_COLOR counts only when it is set and not empty (no-color.org).
    assert empty.stdout == coloured.stdout
    assert off.stdout == sx.segment_for(expected) + "\n"
    assert "\x1b" not in off.stdout
    for run in (coloured, off):
        cfx.assert_value_free(run.stdout + run.stderr, claude.setup.values.values())


def test_a_clean_session_is_green_and_an_exposed_one_amber_and_red(tmp_path: Path) -> None:
    clean = sx.build(tmp_path / "clean")
    _clean(clean)
    exposed = sx.build(tmp_path / "exposed")
    _exposed(exposed)

    green = clean.statusline_process().stdout
    warned = exposed.statusline_process().stdout

    assert clean.audit()["result"] == "clean"
    assert green == f"weir \x1b[{G}m✓ no known key seen\x1b[0m\n"
    context, sent, _ = sx.expected_counts(exposed.setup, exposed.audit())
    assert (context, sent) == (2, 1)
    assert f"\x1b[{A}m{context} in context\x1b[0m" in warned
    assert f"\x1b[{R}m{sent} sent\x1b[0m" in warned
    assert warned.endswith(" → /weir\n")
    assert "✓" not in warned and "no known key seen" not in warned


def test_a_session_still_being_read_is_dim_and_never_green(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("read the logs")
    for n in range(12):
        session.tool_use("Read", {"file_path": f"/fake/log{n}.txt"}, f"toolu_{n:02d}")
        filler = "".join(f"{n:02d} line {i} of a long fake log\n" for i in range(800))
        session.tool_result(f"toolu_{n:02d}", filler)
    session.write(claude.transcript())

    first = claude.statusline_process(extra=["--budget-ms", "0"]).stdout

    assert sx.SCANNING_LINE.fullmatch(sx.plain(first).rstrip("\n")), first
    progress = re.fullmatch(r"weir \x1b\[2m(scanning… \d+%)\x1b\[0m\n", first)
    assert progress, first
    assert "✓" not in first and f"\x1b[{G}m" not in first


def test_the_segment_sits_beside_the_existing_line_without_tinting_it(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _exposed(claude)
    expected = sx.expected_counts(claude.setup, claude.audit())
    inner = sx.python_command("print('ctx 42%')")

    run = claude.statusline_process(extra=["--inner", inner])

    assert run.exit_code == 0, run.stderr
    assert run.stdout == "ctx 42%\x1b[0m | " + sx.segment_for(expected, colour=True) + "\n"
    # Every colour the segment turns on it turns off again.
    assert _drawn(run.stdout)[-1] == ("\n", frozenset())
    assert run.stdout.rstrip("\n").endswith(sx.POINTER)


def _drawn(text: str) -> list[tuple[str, frozenset[int]]]:
    """Each character of `text` and the SGR codes a terminal draws it in."""
    drawn: list[tuple[str, frozenset[int]]] = []
    on: frozenset[int] = frozenset()
    for code, char in re.findall(r"\x1b\[([0-9;]*)m|(.)", text, re.DOTALL):
        if char:
            drawn.append((char, on))
        else:
            for n in (int(c or 0) for c in code.split(";")):
                on = frozenset() if n == 0 else on | {n}
    return drawn


def test_a_colour_the_existing_line_leaves_on_never_tints_the_segment(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _exposed(claude)
    expected = sx.expected_counts(claude.setup, claude.audit())
    left_on = "\x1b[34mctx 42%"
    inner = sx.python_command("import sys; sys.stdout.write(chr(27) + '[34mctx 42%')")

    coloured = claude.statusline_process(extra=["--inner", inner])
    off = claude.statusline_process(extra=["--inner", inner], env={"NO_COLOR": "1"})

    assert coloured.exit_code == 0, coloured.stderr
    assert coloured.stdout.startswith(left_on)
    alone = " | " + sx.segment_for(expected, colour=True) + "\n"
    assert _drawn(coloured.stdout)[len("ctx 42%"):] == _drawn(alone)
    assert off.stdout == left_on + " | " + sx.segment_for(expected) + "\n"


@pytest.mark.parametrize(("stdin", "words"), [("not json", "weir no session")])
def test_the_words_with_no_counts_are_dim(tmp_path: Path, stdin: str, words: str) -> None:
    claude = sx.build(tmp_path)
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state)]

    coloured = claude.process(args, stdin)
    off = claude.process(args, stdin, {"NO_COLOR": "1"})

    assert coloured.stdout == f"weir \x1b[{D}m{words.removeprefix('weir ')}\x1b[0m\n"
    assert off.stdout == words + "\n"


def test_a_wrong_key_is_a_dim_error_that_points_to_the_report(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _exposed(claude)
    cfx.write(claude.setup.key, "cd" * 32 + "\n")

    coloured = claude.statusline_process()
    off = claude.statusline_process(env={"NO_COLOR": "1"})

    assert coloured.stdout == f"weir \x1b[{D}merror → /weir\x1b[0m\n"
    assert off.stdout == "weir error → /weir\n"


def _says_nothing_to_check(claude: sx.Claude) -> None:
    report_args = ["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID]

    coloured = claude.statusline_process()
    off = claude.statusline_process(env={"NO_COLOR": "1"})
    report = claude.process(report_args)

    assert coloured.exit_code == off.exit_code == report.exit_code == 0
    assert coloured.stdout == f"weir \x1b[{D}mnothing to check\x1b[0m\n"
    assert off.stdout == "weir nothing to check\n"
    assert report.lines[0] == "weir nothing to check"
    for run in (coloured, off, report):
        assert "✓" not in run.stdout and f"\x1b[{G}m" not in run.stdout
        cfx.assert_value_free(run.stdout + run.stderr, claude.setup.values.values())


@pytest.mark.parametrize("make", [_exposed, _clean])
def test_an_inventory_with_no_credentials_says_nothing_to_check(
    tmp_path: Path, make: object
) -> None:
    # The session holds fake values, from an inventory the segment is not
    # given: with nothing inventoried there is nothing to count, so the
    # line never says no known key seen.
    claude = sx.build(tmp_path)
    make(claude)  # type: ignore[operator]
    sx.without_credentials(claude)

    assert claude.audit()["credentials"] == []
    _says_nothing_to_check(claude)


@pytest.mark.parametrize("make", [_exposed, _clean])
def test_an_inventory_of_only_a_dynamic_credential_says_nothing_to_check(
    tmp_path: Path, make: object
) -> None:
    # The inventory names a credential, but its value is computed when the
    # shell starts, so weir holds no fingerprint of it: nothing to count.
    claude = sx.build(tmp_path)
    make(claude)  # type: ignore[operator]
    sx.without_credentials(claude, bashrc="export TOKEN=$(pass show x)\n")

    inventory = json.loads(claude.setup.report.read_text())
    assert [c["name"] for c in inventory["credentials"]] == ["TOKEN"]
    audit = claude.audit()
    assert [c["state"] for c in audit["credentials"]] == ["not_checkable"]  # type: ignore[union-attr,index]
    assert audit["coverage"]["not_checkable"] == 1  # type: ignore[index]
    _says_nothing_to_check(claude)


def test_the_report_first_line_is_the_plain_words_without_the_pointer(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _exposed(claude)
    expected = sx.expected_counts(claude.setup, claude.audit())

    run = claude.process(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])

    assert run.exit_code == 0, run.stderr
    assert run.lines[0] == sx.segment_for(expected, pointer=False)
    assert "\x1b" not in run.stdout
    cfx.assert_value_free(run.stdout + run.stderr, claude.setup.values.values())


# --- the session's project and the inventory's (docs/statusline.md, "The project") --


NOT_INVENTORIED = "weir project not inventoried"


def _elsewhere(claude: sx.Claude) -> str:
    """A folder beside the inventory's project whose name starts with
    the project's: outside it all the same."""
    folder = Path(claude.project() + "-other")
    folder.mkdir()
    return str(folder)


def _without_project(claude: sx.Claude) -> None:
    """The inventory's report as `weir inventory --no-project` writes it:
    no project."""
    report = json.loads(claude.setup.report.read_text())
    report["inputs"]["project"] = None
    claude.setup.report.write_text(json.dumps(report))


@pytest.mark.parametrize("where", ["the project", "a folder under it"])
def test_a_clean_session_in_the_inventory_s_project_is_green(tmp_path: Path, where: str) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = Path(claude.project())
    if where != "the project":
        folder = folder / "src" / "app"
        folder.mkdir(parents=True)

    run = claude.statusline(folder=str(folder))

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    assert run.stdout == sx.segment_for((0, 0, False)) + "\n"
    assert run.stdout == "weir ✓ no known key seen\n"


def test_a_clean_session_in_another_project_is_a_dim_note_never_green(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = _elsewhere(claude)
    payload = sx.status_json(claude.transcript(), fx.SESSION_ID, folder)
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state)]

    coloured = claude.process(args, payload)
    off = claude.process(args, payload, sx.NO_COLOR)

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    assert coloured.stdout == f"weir \x1b[{D}mproject not inventoried\x1b[0m\n"
    assert off.stdout == NOT_INVENTORIED + "\n"
    assert off.stdout == sx.segment_for((0, 0, False), inside=False) + "\n"


def test_counts_in_another_project_are_shown_as_in_the_project(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _exposed(claude)
    expected = sx.expected_counts(claude.setup, claude.audit())
    assert expected[:2] != (0, 0)

    run = claude.statusline(folder=_elsewhere(claude))

    assert run.stdout == sx.segment_for(expected) + "\n"


def test_an_inventory_with_no_project_is_never_green(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = claude.project()
    _without_project(claude)

    run = claude.statusline(folder=folder)

    assert run.stdout == NOT_INVENTORIED + "\n"


@pytest.mark.parametrize("given", ["neither", "cwd only"])
def test_the_session_folder_is_project_dir_else_cwd_and_never_green_without(
    tmp_path: Path, given: str,
) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    session = json.loads(sx.status_json(claude.transcript(), fx.SESSION_ID, None))
    if given == "cwd only":
        session["cwd"] = claude.project()
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state)]

    run = claude.invoke(args, stdin=json.dumps(session), env=sx.NO_COLOR)

    expected = "weir ✓ no known key seen" if given == "cwd only" else NOT_INVENTORIED
    assert run.stdout == expected + "\n"


def test_project_dir_is_taken_before_cwd(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    session = json.loads(sx.status_json(claude.transcript(), fx.SESSION_ID, claude.project()))
    session["workspace"]["project_dir"] = _elsewhere(claude)
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state)]

    run = claude.invoke(args, stdin=json.dumps(session), env=sx.NO_COLOR)

    assert run.stdout == NOT_INVENTORIED + "\n"


def _switch(claude: sx.Claude, folder: str) -> list[str]:
    """The switch command docs/statusline.md gives for `folder`, into the
    inventory files the report was given."""
    s = claude.setup
    report, store, key = (shlex.quote(str(path)) for path in (s.report, s.store, s.key))
    return [
        f"    weir inventory --home ~ --project {shlex.quote(folder)} --process-env --json"
        f" --store {store} --key {key} > {report}",
        "  the earlier project's keys then stop being counted",
    ]


def _ends_with(report: sx.Run, inside: sx.Run, tail: list[str]) -> None:
    """`report` is the report run `inside` the project but its first line,
    with `tail` after it."""
    assert report.exit_code == inside.exit_code == 0, report.stderr
    assert report.lines[1 : len(inside.lines)] == inside.lines[1:]
    assert report.lines[len(inside.lines) :] == tail


@pytest.mark.parametrize("make", [_clean, _exposed])
def test_the_report_in_another_project_says_how_to_switch_the_inventory(
    tmp_path: Path, make: object,
) -> None:
    claude = sx.build(tmp_path)
    make(claude)  # type: ignore[operator]
    project = claude.project()
    folder = _elsewhere(claude)
    expected = sx.expected_counts(claude.setup, claude.audit())
    inside = claude.report()

    outside = claude.report(folder=folder)

    assert inside.lines[0] == sx.segment_for(expected, pointer=False)
    assert "not the inventoried project" not in inside.stdout
    assert outside.lines[0] == sx.segment_for(expected, pointer=False, inside=False)
    _ends_with(outside, inside, [
        "",
        f"project: {folder} is not the inventoried project ({project}),"
        " so keys in its files are not known",
        "  to switch the inventory to this folder, run from the shell Claude Code starts from:",
        *_switch(claude, folder),
    ])
    cfx.assert_value_free(outside.stdout + outside.stderr, claude.setup.values.values())


@sx.posix_shell
def test_the_switch_command_switches_the_inventory_the_status_line_reads(
    tmp_path: Path,
) -> None:
    """The command /weir gives, run as printed, writes the files the status
    line reads: a clean session in the new folder is then green."""
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = _elsewhere(claude)
    assert claude.statusline(folder=folder).stdout == NOT_INVENTORIED + "\n"
    printed = claude.report(folder=folder).lines[-2].strip()
    env = {**claude.env(), "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"}

    switched = sx.run_shell(printed, "", env)

    assert switched.exit_code == 0, switched.stderr
    assert claude.project() == folder
    assert claude.statusline(folder=folder).stdout == "weir ✓ no known key seen\n"


@pytest.mark.parametrize("launched", ["in the project", "elsewhere"])
def test_the_report_answers_for_the_launch_folder_as_the_status_line_does(
    tmp_path: Path, launched: str,
) -> None:
    """Claude Code launched in one folder, its shell moved to the other:
    the status line and /weir say the same, from the launch folder."""
    claude = sx.build(tmp_path)
    _clean(claude)
    project, other = claude.project(), _elsewhere(claude)
    folder, shell = (project, other) if launched == "in the project" else (other, project)

    line = claude.statusline(folder=folder)
    report = claude.report(folder=folder, cwd=shell)

    green = launched == "in the project"
    assert line.stdout == sx.segment_for((0, 0, False), inside=green) + "\n"
    assert report.lines[0] == sx.segment_for((0, 0, False), pointer=False, inside=green)
    assert ("not the inventoried project" in report.stdout) is not green


_UNKNOWN = (
    "project: the session's project folder is not known yet (the status line records it"
    " on its first refresh), so it is not known to be the inventoried project ({})"
)


@pytest.mark.parametrize("shell", ["in the project", "elsewhere"])
def test_before_the_status_line_records_the_folder_the_report_is_never_green(
    tmp_path: Path, shell: str,
) -> None:
    """Not known yet, never green, even run from the project; a switch
    command only for a current folder that is not the inventoried project
    already."""
    claude = sx.build(tmp_path)
    _clean(claude)
    project = claude.project()
    here = project if shell == "in the project" else _elsewhere(claude)

    report = claude.report(folder="", cwd=here)
    inside = claude.report()

    assert inside.lines[0] == sx.segment_for((0, 0, False), pointer=False)
    assert report.lines[0] == sx.segment_for((0, 0, False), pointer=False, inside=False)
    switch = [] if here == project else [
        f"  to switch the inventory to the current folder, {here}, run from the shell"
        " Claude Code starts from:",
        *_switch(claude, here),
    ]
    _ends_with(report, inside, ["", _UNKNOWN.format(project), *switch])


@pytest.mark.parametrize("passed", [True, False], ids=["recorded", "not recorded"])
def test_the_report_never_advises_walking_the_home(tmp_path: Path, passed: bool) -> None:
    """Claude Code started from the home: the report gives no switch
    command, as setup never offers the home as the project."""
    claude = sx.build(tmp_path)
    _clean(claude)
    home = str(claude.setup.home)

    report = claude.report(folder=home if passed else "", cwd=home)

    assert report.exit_code == 0, report.stderr
    assert report.lines[0] == NOT_INVENTORIED
    assert report.lines[-1] == (
        f"  no switch command: {home} is or holds your home, and walking it"
        " as the project would read the whole home"
    )
    assert "weir inventory" not in report.stdout


def test_a_report_with_nothing_to_check_names_the_folder_it_was_given(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    sx.without_credentials(claude)
    project = claude.project()
    folder = _elsewhere(claude)

    inside = claude.report()
    outside = claude.report(folder=folder)

    assert inside.lines[0] == outside.lines[0] == "weir nothing to check"
    assert "project:" not in inside.stdout
    assert f"project: {folder} is not the inventoried project ({project})," in outside.stdout
    assert "not known yet" not in outside.stdout


@pytest.mark.parametrize("given", [".", "~/proj", "$NAME", "proj"])
def test_a_folder_that_is_not_absolute_is_unknown_and_never_green(
    tmp_path: Path, given: str,
) -> None:
    """Run from inside the project, where a relative folder would resolve
    to it: Claude Code passes absolute folders, so any other is unknown."""
    claude = sx.build(tmp_path)
    _clean(claude)
    project = claude.project()

    with contextlib.chdir(project):
        line = claude.statusline(folder=given)
    report = claude.report(folder=given, cwd=project)
    inside = claude.report()

    assert line.stdout == NOT_INVENTORIED + "\n"
    assert report.lines[0] == NOT_INVENTORIED
    _ends_with(report, inside, ["", _UNKNOWN.format(project)])


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not remove a process's current folder",
)
@pytest.mark.parametrize("passed", [True, False], ids=["recorded", "not recorded"])
def test_a_report_run_from_a_deleted_folder_gives_no_switch_command_and_never_crashes(
    tmp_path: Path, passed: bool,
) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = _elsewhere(claude)
    gone = tmp_path / "gone"
    gone.mkdir()
    if passed:
        claude.statusline(folder=folder)

    with contextlib.chdir(gone):
        gone.rmdir()
        report = claude.invoke([
            "statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
            "--cache", str(claude.state),
        ])

    assert report.exit_code == 0, report.stderr
    assert report.lines[0] == NOT_INVENTORIED
    if passed:
        assert report.lines[-2:] == _switch(claude, folder)
    else:
        assert report.lines[-2:] == [
            _UNKNOWN.format(claude.project()),
            "  no switch command: the current folder cannot be read",
        ]


def _record_only(claude: sx.Claude) -> Path:
    """The one folder record in the status line's cache."""
    (record,) = (p for p in claude.state.iterdir() if p.suffix == ".folder")
    return record


@pytest.mark.parametrize("source", ["status JSON", "record"])
def test_a_folder_with_a_nul_byte_is_unknown_and_never_crashes(
    tmp_path: Path, source: str,
) -> None:
    """A path holds no NUL, so one in the status JSON or written into the
    record by hand is no folder: never green, never a traceback."""
    claude = sx.build(tmp_path)
    _clean(claude)
    project = claude.project()
    forged = project + "\0x"

    if source == "status JSON":
        line = claude.statusline(folder=forged)
    else:
        line = claude.statusline(folder=project)
        _record_only(claude).write_bytes(forged.encode())
    report = claude.report(folder="", cwd=project)
    inside = claude.report()

    if source == "status JSON":
        assert line.stdout == NOT_INVENTORIED + "\n"
    assert report.lines[0] == NOT_INVENTORIED
    _ends_with(report, inside, ["", _UNKNOWN.format(project)])


@pytest.mark.parametrize(
    "unusable", [".", "{}\0x", "{}\ud800", "{}\udc80"],
    ids=["relative", "nul", "lone surrogate", "escaped byte"])
@pytest.mark.parametrize("order", ["usable first", "unusable first"])
def test_the_report_follows_the_last_refresh_s_folder(
    tmp_path: Path, order: str, unusable: str,
) -> None:
    """A refresh with no usable folder clears the record, so /weir is
    never green while the status line is not; the next usable one records
    the folder again."""
    claude = sx.build(tmp_path)
    _clean(claude)
    project = claude.project()
    folders = [project, unusable.format(project)]
    if order == "unusable first":
        folders.reverse()

    with contextlib.chdir(project):
        lines = [claude.statusline(folder=folder) for folder in folders]
    report = claude.report(folder="", cwd=project)

    green = order == "unusable first"
    assert lines[-1].stdout == sx.segment_for((0, 0, False), inside=green) + "\n"
    assert report.lines[0] == sx.segment_for((0, 0, False), pointer=False, inside=green)
    assert ("not known yet" in report.stdout) is not green


def test_with_no_project_inventoried_the_switch_drops_no_earlier_project(
    tmp_path: Path,
) -> None:
    claude = sx.build(tmp_path)
    _clean(claude)
    folder = _elsewhere(claude)
    _without_project(claude)

    report = claude.report(folder=folder, cwd=folder)

    assert report.lines[-1].startswith("    weir inventory --home ~ --project ")
    assert "earlier project" not in report.stdout
