"""How the segment looks (docs/statusline.md, "The segment"), written
before the implementation.

Each state has its words, its icon and its colours, drawn with ANSI SGR
codes that Claude Code's status line renders, every coloured part reset
after itself so the status line beside it keeps its own colours. With
NO_COLOR set the words and symbols are the same and there is no escape
code. Only a session read to its end with nothing found says "nothing
exposed" in green; what is unread, unknown or partly checked never does.

The words come from docs/statusline.md, "The segment", through
statusline_fixtures.segment_for; the end-to-end tests run weir in a
process of its own, its output a pipe, as Claude Code runs it.
"""

from __future__ import annotations

import itertools
import json
import re
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
        "weir ✓ nothing exposed",
        f"weir {_p('✓ nothing exposed', G)}",
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
    assert segment_text(**args, colour=False) == words  # type: ignore[arg-type]
    assert segment_text(**args, colour=True) == coloured  # type: ignore[arg-type]


# Text, or one SGR code this document names, its text, and a reset.
_SPANS = re.compile(r"(?:[^\x1b]|\x1b\[(?:32|33|31|2)m[^\x1b]+\x1b\[0m)*")


def _every_state() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for context, sent, unknown, partial, scanning in itertools.product(
        range(3), range(3), (False, True), (False, True), (None, 0, 55)
    ):
        if sent <= context:  # a value sent in a tool call is in the context
            out.append({
                "context": context, "sent": sent, "unknown": unknown, "partial": partial,
                "scanning": scanning,
            })
    return out


@pytest.mark.parametrize("args", _every_state())
def test_only_a_clean_session_read_to_its_end_says_nothing_exposed(
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
    clean = (
        args["context"] == args["sent"] == 0
        and not args["unknown"] and not args["partial"] and args["scanning"] is None
    )
    assert ("✓" in words) is clean
    assert ("nothing exposed" in words) is clean
    assert (f"\x1b[{G}m" in coloured) is clean
    if args["partial"]:
        # Partly checked is never a number and never nothing exposed.
        assert words == sx.PARTLY_CHECKED
    elif args["scanning"] is not None:
        assert sx.SCANNING_LINE.fullmatch(words), words
        assert words.endswith(f"{args['scanning']}%")
    elif args["unknown"] and not args["context"]:
        assert words == "weir unknown"  # never a zero
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
    assert green == f"weir \x1b[{G}m✓ nothing exposed\x1b[0m\n"
    context, sent, _ = sx.expected_counts(exposed.setup, exposed.audit())
    assert (context, sent) == (2, 1)
    assert f"\x1b[{A}m{context} in context\x1b[0m" in warned
    assert f"\x1b[{R}m{sent} sent\x1b[0m" in warned
    assert warned.endswith(" → /weir\n")
    assert "✓" not in warned and "nothing exposed" not in warned


def test_a_session_still_being_read_is_dim_and_never_nothing_exposed(tmp_path: Path) -> None:
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
    # line never says nothing exposed.
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
