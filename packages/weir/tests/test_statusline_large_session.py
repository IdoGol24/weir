"""`weir statusline` on a long fake session, cancelled as Claude Code
cancels it, and the fingerprint key's file (docs/statusline.md). Fake data
only: generated transcripts of 5 to 22 MB under the test's temporary
directory and the fake inventory of statusline_fixtures."""

from __future__ import annotations

import base64
import hashlib
import os
import random
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx


def _checkpoint_time(state: Path) -> int:
    return max((p.stat().st_mtime_ns for p in state.glob("*.json")), default=0)


def _long_session(claude: sx.Claude) -> Path:
    """About 5 MB of tool results that hold no credential, then one read of
    a fake credential and one send of another."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("read the fake logs")
    filler = "".join(f"line {i} of a long fake log, nothing secret here\n" for i in range(400))
    for n in range(260):
        session.tool_use("Read", {"file_path": f"/fake/log{n}.txt"}, f"toolu_{n:03d}")
        session.tool_result(f"toolu_{n:03d}", filler)
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_env")
    session.tool_result("toolu_env", f"{fx.ACME}={v[fx.ACME]}\n")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    return session.write(claude.transcript())


def _pasted_image_session(claude: sx.Claude) -> Path:
    """A prompt with a pasted image of about 20 MB of base64, then one read
    of a fake credential and one send of another."""
    v = claude.setup.values
    session = fx.Session()
    data = base64.b64encode(random.Random(7).randbytes(15_000_000)).decode()
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
    text = {"type": "text", "text": "what is in this picture?"}
    session.record(session._envelope("user", message={"role": "user", "content": [image, text]}))
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_env")
    session.tool_result("toolu_env", f"{fx.ACME}={v[fx.ACME]}\n")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    return session.write(claude.transcript())


def _long_text_session(claude: sx.Claude) -> Path:
    """One tool result of about 22 MB of text that holds no credential: a
    log, then 2 MB of hashes as a lockfile holds them, every one a candidate
    the audit checks. Then one read of a fake credential and one send of
    another."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("read the whole fake log")
    session.tool_use("Read", {"file_path": "/fake/huge.log"}, "toolu_log")
    rng = random.Random(11)
    words = ["request", "served", "in", "ms", "status", "ok", "retry", "cache", "miss", "user"]
    log = "".join(
        f"{n} {' '.join(rng.choice(words) for _ in range(8))} {rng.randrange(10**6)}\n"
        for n in range(400_000)
    )
    lock = "".join(hashlib.sha256(str(n).encode()).hexdigest() + " " for n in range(32_000))
    session.tool_result("toolu_log", log + lock)
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_env")
    session.tool_result("toolu_env", f"{fx.ACME}={v[fx.ACME]}\n")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    return session.write(claude.transcript())


def _many_blocks_session(claude: sx.Claude) -> Path:
    """One tool result of about 21 MB made of 21,500 short text blocks (a
    query result, say), one of which holds a fake credential; then one
    send of another."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("run the fake query")
    session.tool_use("mcp__db__query", {"sql": "select * from events"}, "toolu_q")
    row = "event served from the fake cache, status ok, nothing secret here " * 15
    blocks: list[object] = [{"type": "text", "text": f"{n} {row}"} for n in range(21_500)]
    blocks[10_000] = {"type": "text", "text": f"{fx.ACME}={v[fx.ACME]}"}
    session.tool_result("toolu_q", blocks)
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    return session.write(claude.transcript())


def _start(claude: sx.Claude, cache: Path, *extra: str) -> subprocess.Popen[bytes]:
    """The real `python -m weir statusline` process, as Claude Code runs it."""
    command = [sys.executable, "-m", "weir", "statusline", *claude.inputs(),
               "--cache", str(cache), *extra]
    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=claude.env(),
    )
    assert proc.stdin is not None
    proc.stdin.write(sx.status_json(claude.transcript(), fx.SESSION_ID).encode())
    proc.stdin.close()
    return proc


def _output(proc: subprocess.Popen[bytes]) -> str:
    assert proc.stdout is not None
    out = proc.stdout.read().decode()
    proc.stdout.close()
    proc.wait()
    return out


def _until_read(claude: sx.Claude, cache: Path, first: subprocess.Popen[bytes], *extra: str) -> str:
    """What `first` and the runs after it, none cancelled, show once read."""
    shown = _output(first)
    while "scanning" in shown:
        shown = _output(_start(claude, cache, *extra))
    return shown


@pytest.mark.skipif(os.name != "posix", reason="SIGTERM and SIGKILL as Claude Code sends them")
@pytest.mark.parametrize(
    ("build", "partly"),
    [(_long_session, False), (_pasted_image_session, False), (_long_text_session, True),
     (_many_blocks_session, True)],
    ids=["many records", "pasted image", "one long text record", "one record of many blocks"],
)
def test_a_first_scan_cancelled_again_and_again_still_completes(
    tmp_path: Path, build: Callable[[sx.Claude], Path], partly: bool
) -> None:
    """Each run is the real `python -m weir statusline` process, killed with
    SIGTERM or SIGKILL at a random point: the first three before the time
    one uninterrupted run takes to save progress at all, then each a moment
    after it saves progress, or after two seconds without any; or, for a
    session with one record of about 21 MB (`partly`), each between one and
    two seconds after it starts, whatever it saved. The scan still
    finishes with the counts `weir audit` gives, or, `partly`, with them or
    partly checked (when the record takes longer to search on this machine
    than its time bound, or three tries are cancelled), never another
    count, while the /weir report gives the counts."""
    seed = random.randrange(1 << 32)
    print("seed:", seed)
    rng = random.Random(seed)
    claude = sx.build(tmp_path)
    assert build(claude).stat().st_size > 5_000_000
    budget = () if partly else ("--budget-ms", "600000")

    began = time.monotonic()
    fresh = _start(claude, tmp_path / "fresh", *budget)
    while not _checkpoint_time(tmp_path / "fresh") and fresh.poll() is None:
        time.sleep(0.005)
    first_progress = time.monotonic() - began  # the uninterrupted run goes on beside the rest

    finished = ""
    kills = 0
    give_up = time.monotonic() + 240
    for n in range(300):
        assert time.monotonic() < give_up, f"no run finished after {kills} cancels"
        proc = _start(claude, claude.state, *budget)
        early = kills < 3
        if early:  # cancelled inside the work before any progress is saved
            time.sleep(rng.uniform(0.0, first_progress))
        elif partly:
            stop = time.monotonic() + rng.uniform(1.0, 2.0)
            while proc.poll() is None and time.monotonic() < stop:
                time.sleep(0.005)
        else:
            before = _checkpoint_time(claude.state)
            patience = time.monotonic() + 2
            while (
                _checkpoint_time(claude.state) == before and proc.poll() is None
                and time.monotonic() < patience
            ):
                time.sleep(0.005)
            time.sleep(rng.uniform(0.0, 0.15))
        if proc.poll() is not None:
            finished = _output(proc)
            if early:
                # Faster than the uninterrupted run took to save progress (it
                # was measured on a busier machine): start the scan over, so
                # three runs are still cancelled before any progress.
                shutil.rmtree(claude.state)
                continue
            if "scanning" in finished:
                continue  # its time bound passed: the next run reads on
            break
        proc.send_signal((signal.SIGTERM, signal.SIGKILL)[n % 2])
        _output(proc)
        kills += 1
    uninterrupted = _until_read(claude, tmp_path / "fresh", fresh, *budget)
    report = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    shown = {expected, sx.PARTLY_CHECKED + "\n"} if partly else {expected}
    assert kills >= 3, "the scan should have been cancelled again and again"
    assert expected == "weir: 2 in context, 1 sent\n"
    assert uninterrupted in shown
    assert finished in shown
    assert report.lines[0] + "\n" == expected
    for path in (p for p in claude.state.rglob("*") if p.is_file()):
        cfx.assert_value_free(path.name + "\n" + path.read_bytes().decode("utf-8", "replace"),
                              claude.setup.values.values())


def _lockfile_session(claude: sx.Claude) -> Path:
    """One read of a fake lockfile of 200 KB holding a fake credential,
    with its copy as Claude Code writes it; then one send of another."""
    v = claude.setup.values
    session = fx.Session()
    session.prompt("read the fake lockfile")
    lock = sx.dense_lockfile(200_000)
    half = len(lock) // 2
    session.tool_use("Read", {"file_path": "/fake/package-lock.json"}, "toolu_lock")
    text = f"{lock[:half]}{fx.ACME}={v[fx.ACME]}\n{lock[half:]}"
    sx.tool_result_and_copy(session, "toolu_lock", text)
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    return session.write(claude.transcript())


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL as Claude Code sends it")
@pytest.mark.parametrize("kills", [1, 2, 3])
def test_a_long_record_whose_search_is_cancelled_is_tried_three_times(
    tmp_path: Path, kills: int
) -> None:
    """A run killed while it searches a long record (a 200 KB lockfile with
    its copy) leaves it to the next run, which tries it again; after three
    such tries the record is skipped and the session is partly checked.
    Either way the /weir report gives the counts `weir audit` gives."""
    claude = sx.build(tmp_path)
    _lockfile_session(claude)
    # One step, the records before the long one: the next run starts with it.
    assert "scanning" in _output(_start(claude, claude.state, "--budget-ms", "0"))

    for _ in range(kills):
        before = _checkpoint_time(claude.state)
        searching = _start(claude, claude.state)
        while _checkpoint_time(claude.state) == before:
            assert searching.poll() is None
            time.sleep(0.001)
        searching.send_signal(signal.SIGKILL)
        _output(searching)
    shown = _until_read(claude, claude.state, _start(claude, claude.state))
    report = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    assert report.lines[0] + "\n" == expected
    assert shown == (sx.PARTLY_CHECKED + "\n" if kills == 3 else expected)


@pytest.mark.skipif(os.name != "posix", reason="SIGTERM as Claude Code sends it")
def test_a_record_of_very_many_tiny_blocks_cancelled_every_second_ends_partly_checked(
    tmp_path: Path,
) -> None:
    """A tool result of 700,000 blocks of a few characters (about 35 MB)
    takes longer to parse than the second each run is given before it is
    cancelled (SIGTERM). Each run still counts as a try at it, so the
    record is skipped after three: a run ends on its own, partly checked,
    never left at scanning."""
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("list the fake ids")
    session.tool_use("mcp__db__ids", {"table": "events"}, "toolu_ids")
    blocks: list[object] = [{"type": "text", "text": f"id {n:020d}"} for n in range(700_000)]
    blocks[350_000] = {"type": "text", "text": f"{fx.ACME}={v[fx.ACME]}"}
    session.tool_result("toolu_ids", blocks)
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_aws")
    assert session.write(claude.transcript()).stat().st_size > 30_000_000

    finished: list[str] = []
    for _ in range(10):
        proc = _start(claude, claude.state)
        stop = time.monotonic() + 1.0
        while proc.poll() is None and time.monotonic() < stop:
            time.sleep(0.005)
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            _output(proc)
            continue
        finished.append(_output(proc))
        if "scanning" not in finished[-1]:
            break

    assert finished and finished[-1] == sx.PARTLY_CHECKED + "\n", finished


# --- the fingerprint key is its owner's alone ----------------------------------------


def test_the_fingerprint_key_is_a_file_only_its_owner_can_read(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    if os.name == "posix":  # Windows has no owner-only mode bits to check
        assert stat.S_IMODE(claude.setup.key.stat().st_mode) == 0o600
    session = fx.Session()
    session.prompt("hello")
    session.write(claude.transcript())
    assert claude.statusline().stdout == "weir: 0 in context, 0 sent\n"


@pytest.mark.skipif(os.name != "posix", reason="owner and mode bits are POSIX")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_key_file_others_can_read_is_refused(tmp_path: Path, mode: int) -> None:
    claude = sx.build(tmp_path)
    key = claude.setup.key
    key.chmod(mode)
    session = fx.Session()
    session.prompt("hello")
    session.write(claude.transcript())
    home = claude.setup.home

    line = claude.statusline()
    report = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])
    audit = claude.setup.audit([claude.transcript()])
    inventory = claude.invoke(
        ["inventory", "--home", str(home), "--project", str(home / "work" / "proj"),
         "--key", str(key)]
    )

    assert line.stdout == "weir: error, run /weir\n"
    for run in (report, audit):
        assert run.exit_code == 2
    assert inventory.exit_code == 2
    # Refused, never repaired behind the person's back.
    assert stat.S_IMODE(key.stat().st_mode) == mode
