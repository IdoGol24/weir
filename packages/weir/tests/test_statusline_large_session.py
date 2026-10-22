"""`weir statusline` on a large fake session (docs/statusline.md, "Speed
and the cache").

FAKE DATA ONLY: a generated transcript of about 50 MB in a fake Claude
config directory under the test's temporary directory, and the fake
inventory of `statusline_fixtures.build`.

What the segment should say comes from a real `weir audit --json` run over
the same file. What a refresh read is counted outside the code under test:
every file the process opens is wrapped and every byte a read returns is
counted (`os.read` and `mmap` too), and where the kernel keeps it, the
process's own read counter (`rchar` in /proc/self/io) is checked as well.
The timings are recorded as test properties and printed; the bytes are
asserted.
"""

from __future__ import annotations

import builtins
import io
import json
import mmap
import os
import re
import shutil
import stat
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

SIZE = 50 * 1000 * 1000
_IO = Path("/proc/self/io")


def _rchar() -> int | None:
    """The kernel's count of bytes this process's reads returned, where the
    kernel keeps one."""
    if not _IO.is_file():
        return None
    for line in _IO.read_text().splitlines():
        name, _, value = line.partition(":")
        if name == "rchar":
            return int(value)
    return None


class _Counted:
    """A file object whose reads are counted."""

    def __init__(self, inner: Any, count: list[int]) -> None:
        self._inner = inner
        self._count = count

    def _add(self, data: Any) -> Any:
        if isinstance(data, (bytes, bytearray, str)):
            self._count[0] += len(data)
        elif isinstance(data, list):
            self._count[0] += sum(len(x) for x in data)  # pyright: ignore[reportUnknownArgumentType, reportUnknownVariableType]
        return data

    def read(self, *args: Any) -> Any:
        return self._add(self._inner.read(*args))

    def read1(self, *args: Any) -> Any:
        return self._add(self._inner.read1(*args))

    def readline(self, *args: Any) -> Any:
        return self._add(self._inner.readline(*args))

    def readlines(self, *args: Any) -> Any:
        return self._add(self._inner.readlines(*args))

    def readinto(self, buffer: Any) -> Any:
        n = self._inner.readinto(buffer)
        self._count[0] += n or 0
        return n

    def __iter__(self) -> Iterator[Any]:
        for line in self._inner:
            yield self._add(line)

    def __enter__(self) -> _Counted:
        self._inner.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._inner.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _measured(
    run: Callable[[], sx.Run], monkeypatch: pytest.MonkeyPatch
) -> tuple[sx.Run, int, int | None, float]:
    """The run, the bytes its reads returned, the kernel's count of them
    (None where there is none), and the seconds it took."""
    count = [0]
    real_open, real_read = io.open, os.read

    def counted_open(*args: Any, **kwargs: Any) -> Any:
        return _Counted(real_open(*args, **kwargs), count)

    def counted_read(fd: int, n: int) -> bytes:
        return _Counted(None, count)._add(real_read(fd, n))  # type: ignore[no-any-return]

    def no_mmap(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a refresh read through mmap, which this test cannot count")

    with monkeypatch.context() as patch:
        patch.setattr(io, "open", counted_open)
        patch.setattr(builtins, "open", counted_open)
        patch.setattr(os, "read", counted_read)
        patch.setattr(mmap, "mmap", no_mmap)
        before, start = _rchar(), time.perf_counter()
        result = run()
        seconds = time.perf_counter() - start
        after = _rchar()
    kernel = None if before is None or after is None else after - before
    return result, count[0], kernel, seconds


def _large_session(claude: sx.Claude) -> Path:
    """About SIZE bytes of tool results that hold no credential, then one
    record that reads a fake credential into the context."""
    head = fx.Session()
    head.prompt("read the fake logs")
    filler = "".join(f"line {i} of a long fake log, nothing secret here\n" for i in range(400))
    block = fx.Session()
    for n in range(20):
        block.tool_use("Read", {"file_path": f"/fake/log{n}.txt"}, f"toolu_{n:03d}")
        block.tool_result(f"toolu_{n:03d}", filler)
    block_bytes = "".join(line + "\n" for line in block.lines).encode()
    tail = fx.Session()
    tail.tool_use("Bash", {"command": "cat .env"}, "toolu_env")
    tail.tool_result("toolu_env", f"{fx.ACME}={claude.setup.values[fx.ACME]}\n")
    path = claude.transcript()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        out.write("".join(line + "\n" for line in head.lines).encode())
        for _ in range(SIZE // len(block_bytes) + 1):
            out.write(block_bytes)
        out.write("".join(line + "\n" for line in tail.lines).encode())
    return path


def _appended(claude: sx.Claude) -> bytes:
    """A few records Claude Code appends: a tool call that sends a fake
    credential by value."""
    more = fx.Session()
    more.prompt("now call the api")
    secret = claude.setup.values[fx.AWS_SECRET]
    more.tool_use("Bash", {"command": f"aws --secret {secret} s3 ls"}, "t9")
    more.tool_result("t9", "ok")
    return "".join(line + "\n" for line in more.lines).encode()


def test_a_refresh_reads_only_what_was_appended_to_a_50_mb_session(
    tmp_path: Path, record_property: Callable[[str, object], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claude = sx.build(tmp_path)
    path = _large_session(claude)
    size = path.stat().st_size
    assert size >= SIZE

    full, full_read, full_kernel, full_s = _measured(
        lambda: claude.statusline(extra=["--budget-ms", "600000"]), monkeypatch
    )
    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    assert full.stdout == expected
    assert expected == "weir: 1 in context, 0 sent\n"

    added = _appended(claude)
    inode = path.stat().st_ino
    with path.open("ab") as out:
        out.write(added)
    assert path.stat().st_ino == inode
    again, again_read, again_kernel, again_s = _measured(
        lambda: claude.statusline(extra=["--budget-ms", "600000"]), monkeypatch
    )

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    assert again.stdout == expected
    assert expected == "weir: 2 in context, 1 sent\n"
    # The full refresh read the whole file; the next one the appended bytes
    # and the few small files every run reads (the inventory inputs, the
    # cache, and the two 4 KiB windows that show the read part unchanged).
    inputs = sum(p.stat().st_size for p in (claude.setup.report, claude.setup.store))
    cache = sum(p.stat().st_size for p in claude.state.rglob("*") if p.is_file())
    bound = len(added) + 2 * 4096 + 2 * (inputs + cache) + 64 * 1024
    assert full_read >= size
    assert again_read <= bound
    if full_kernel is not None and again_kernel is not None:
        assert full_kernel >= size
        assert again_kernel <= bound
    assert again_s < full_s
    # With no cache and no time to spare, a refresh still takes one step and
    # says how far it got: its time is bounded by the step, not the file.
    # It parses a few chunks of whole lines, not the 50 MB: every string any
    # code hands the JSON parser is counted.
    kept = claude.state.rename(tmp_path / "kept-cache")
    parsed = [0]
    real_loads = json.loads

    def counted_loads(text: Any, *args: Any, **kwargs: Any) -> Any:
        parsed[0] += len(text)
        return real_loads(text, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(json, "loads", counted_loads)
        stepped, _, _, stepped_s = _measured(
            lambda: claude.statusline(extra=["--budget-ms", "0"]), monkeypatch
        )
    assert re.fullmatch(r"weir: checking \d+%\n", stepped.stdout)
    assert parsed[0] <= 4 * 64 * 1024
    assert stepped_s < full_s
    shutil.rmtree(claude.state)
    kept.rename(claude.state)

    numbers = {
        "file_bytes": size, "appended_bytes": len(added),
        "full_refresh_bytes_read": full_read, "full_refresh_s": round(full_s, 3),
        "incremental_refresh_bytes_read": again_read, "incremental_refresh_s": round(again_s, 3),
        "first_step_s": round(stepped_s, 3), "first_step_bytes_parsed": parsed[0],
        "kernel_full_refresh_bytes_read": full_kernel,
        "kernel_incremental_refresh_bytes_read": again_kernel,
    }
    for name, value in numbers.items():
        record_property(name, value)
    print("large session:", json.dumps(numbers))

    # The cache holds no value and no 6-character fragment of one.
    cached = [p for p in claude.state.rglob("*") if p.is_file()]
    assert cached
    for p in cached:
        cfx.assert_value_free(p.name + "\n" + p.read_bytes().decode("utf-8", "replace"),
                              claude.setup.values.values())


def test_a_change_in_the_read_part_is_read_again_from_the_start(tmp_path: Path) -> None:
    """A file that grew but whose start changed (rewritten in place, same
    inode) is read again whole, not resumed from the old offset."""
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.ACME}={v[fx.ACME]}\n")
    for n in range(40):  # well past the 4 KiB window before the offset
        session.tool_use("Read", {"file_path": f"/fake/f{n}"}, f"toolu_r{n}")
        session.tool_result(f"toolu_r{n}", "nothing here\n" * 20)
    path = session.write(claude.transcript())
    assert claude.statusline().stdout == "weir: 1 in context, 0 sent\n"

    data = path.read_bytes()
    scrubbed = data.replace(v[fx.ACME].encode(), b"x" * len(v[fx.ACME]))
    assert len(scrubbed) == len(data)
    more = fx.Session()
    more.prompt("thanks")
    with path.open("r+b") as handle:
        handle.write(scrubbed)
        handle.seek(0, os.SEEK_END)
        handle.write("".join(line + "\n" for line in more.lines).encode())

    run = claude.statusline()

    expected = sx.segment_for(sx.expected_counts(claude.setup, claude.audit())) + "\n"
    assert expected == "weir: 0 in context, 0 sent\n"
    assert run.stdout == expected


def test_the_fingerprint_key_is_a_file_only_its_owner_can_read(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    mode = stat.S_IMODE(claude.setup.key.stat().st_mode)
    assert mode == 0o600
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

    line = claude.statusline()
    report = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID])
    audit = claude.setup.audit([claude.transcript()])
    setup = claude.invoke(
        ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
         "--claude-dir", str(claude.config), "--dry-run"]
    )

    assert line.stdout == "weir: error, run /weir\n"
    for run in (report, setup):
        assert run.exit_code == 2
        assert f"key {key}: is readable or writable by others" in run.stderr
    assert audit.exit_code == 2
    assert f"key {key}: is readable or writable by others" in audit.stderr
    assert not claude.settings.exists()
    home = claude.setup.home
    inventory = claude.invoke(
        ["inventory", "--home", str(home), "--project", str(home / "work" / "proj"),
         "--key", str(key)]
    )
    assert inventory.exit_code == 2
    assert f"fingerprint key {key} is readable or writable by others" in inventory.stderr
    # Refused, never repaired behind the person's back.
    assert stat.S_IMODE(key.stat().st_mode) == mode
