"""`weir canary judge` behaviour: coverage states, incomplete reasons, the
capture's two roles, the printing rule and purity (docs/canary.md).

Each incomplete reason has a test that fails when its check is removed: the
fixture is otherwise clean, so without the check the run would pass.
"""

from __future__ import annotations

import gzip
import json
import os
import socket
import subprocess
import typing
from pathlib import Path

import canary_fixtures as fx
import msgspec
import pytest

from weir.canary import Report, report_json_schema

_A = fx.fake_value("judge-a")
_B = fx.fake_value("judge-b")


def _exercised(pid: str, evidence: str = "request") -> dict[str, object]:
    return {"type": "exercised", "placement": pid, "evidence": evidence}


def _clean_setup(tmp_path: Path, *extra: dict[str, object]) -> tuple[Path, Path]:
    """A complete, clean run: one exercised placement, one ok flow, spans."""
    ledger = fx.write_ledger(
        tmp_path / "ledger.jsonl",
        [
            fx.placement("env.A", _A, required=True),
            _exercised("env.A"),
            {"type": "flow", "id": "quickstart", "status": "ok"},
            *extra,
        ],
    )
    otlp = tmp_path / "otlp.jsonl"
    fx.write(otlp, fx.traces(fx.span("op", attributes=[fx.kv("k", "v")])) + "\n")
    return ledger, otlp


def _incomplete(run: fx.Run) -> list[str]:
    return [line for line in run.lines if line.startswith("incomplete: ")]


def test_a_clean_complete_run_exits_0_with_its_coverage_line(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 0
    # Six strings: the scope name, and the span's name, spanId, traceId and
    # its one attribute's key and value.
    assert run.lines == [
        "coverage: 1 placements (0 leaked, 1 exercised, 0 not exercised, 1 required),"
        f" 1 flows (1 ok), 1 files, 1 spans, 0 log records, 0 metric data points,"
        f" 6 strings, {otlp.stat().st_size} bytes swept",
        "result: clean",
    ]


def test_required_not_exercised_makes_the_run_incomplete(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, fx.placement("env.B", _B, required=True))
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 3
    assert "not exercised: env.B" in run.lines
    assert _incomplete(run) == ["incomplete: required_not_exercised env.B"]
    assert run.lines[-1] == "result: incomplete"


def test_an_optional_not_exercised_placement_is_printed_but_complete(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, fx.placement("env.B", _B))
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 0
    assert "not exercised: env.B" in run.lines
    assert _incomplete(run) == []


@pytest.mark.parametrize("status", ["failed", "timeout", "skipped"])
def test_a_flow_that_is_not_ok_makes_the_run_incomplete(tmp_path: Path, status: str) -> None:
    ledger, otlp = _clean_setup(tmp_path, {"type": "flow", "id": "second", "status": status})
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 3
    assert _incomplete(run) == [f"incomplete: flow_not_ok second={status}"]


def test_an_unexpected_credential_makes_the_run_incomplete(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(
        tmp_path, {"type": "unexpected", "id": "unexpected.search.authorization#1"}
    )
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 3
    assert _incomplete(run) == [
        "incomplete: unexpected_credential unexpected.search.authorization#1"
    ]


def test_a_compressed_capture_file_is_not_scanned(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    packed = tmp_path / "body.gz"
    packed.write_bytes(gzip.compress(_A.encode()))
    run = fx.judge(ledger, [otlp], [packed])
    assert run.exit_code == 3
    assert f"not scanned: {packed} (compressed)" in run.lines
    assert _incomplete(run) == [f"incomplete: not_scanned {packed}"]
    assert ", 1 files," in run.lines[-2]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symbolic links")
def test_a_symlink_inside_a_capture_directory_is_not_followed(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    outside = tmp_path / "outside.txt"
    fx.write(outside, f"token={_A}\n")
    swept = tmp_path / "swept"
    swept.mkdir()
    try:
        (swept / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    run = fx.judge(ledger, [otlp], [swept])
    assert fx.leak_lines(run) == []
    assert f"not scanned: {swept}/link.txt (symlink)" in run.lines
    assert _incomplete(run) == [f"incomplete: not_scanned {swept}/link.txt"]
    assert run.exit_code == 3


@pytest.mark.parametrize(
    ("content", "lines"),
    [
        ("not json\n", [2]),
        ('["resourceSpans"]\n', [2]),
        ('{"resource_spans": []}\n', [2]),
        ("\n", [2]),
        ('{"resourceSpans": []}', [2]),  # truncated: no final newline
    ],
    ids=["not JSON", "not an object", "none of the three fields", "empty line", "truncated"],
)
def test_a_line_that_is_not_an_export_request_is_unparsed(
    tmp_path: Path, content: str, lines: list[int]
) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    fx.write(otlp, otlp.read_text() + content)
    run = fx.judge(ledger, [otlp], as_json=True)
    assert run.exit_code == 3
    assert run.report["incomplete"] == [
        {"reason": "unparsed_record", "subject": f"{otlp}:{n}"} for n in lines
    ]
    assert typing.cast(dict[str, int], run.report["coverage"])["unparsed_records"] == len(lines)


def test_an_unparsed_line_is_still_swept(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    fx.write(otlp, otlp.read_text() + f'{{"broken": "{_A}"\n')
    run = fx.judge(ledger, [otlp])
    assert fx.leak_lines(run) == [f"LEAK env.A file={otlp}:2 signal=raw form=raw"]
    assert f"incomplete: unparsed_record {otlp}:2" in run.lines
    assert run.exit_code == 1  # a found leak outranks incompleteness


def test_telemetry_only_in_a_swept_file_is_an_empty_capture(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    swept = tmp_path / "telemetry-body.json"
    fx.write(swept, otlp.read_text())
    fx.write(otlp, json.dumps({"resourceSpans": []}) + "\n")
    run = fx.judge(ledger, [otlp], [swept])
    assert run.exit_code == 3
    assert _incomplete(run) == ["incomplete: empty_capture"]
    assert ", 0 spans," in run.lines[-2]


def test_logs_and_metrics_count_toward_completeness(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    fx.write(
        otlp,
        fx.logs({"body": {"stringValue": "x"}}) + "\n" + fx.metrics(fx.gauge("m", points=2)) + "\n",
    )
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 0
    assert ", 0 spans, 1 log records, 2 metric data points," in run.lines[-2]


def test_states_take_precedence_leaked_then_exercised(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(
        tmp_path,
        fx.placement("env.B", _B, required=True),
        _exercised("env.B", "egress"),
        _exercised("env.B", "egress"),
        _exercised("env.A", "minted"),
    )
    fx.write(otlp, fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])) + "\n")
    report = fx.judge(ledger, [otlp], as_json=True).report
    assert report["placements"] == [
        {
            "id": "env.A",
            "kind": "env",
            "required": True,
            "state": "leaked",
            "evidence": ["minted", "request"],
            "hits": 1,
        },
        {
            "id": "env.B",
            "kind": "env",
            "required": True,
            "state": "exercised",
            "evidence": ["egress"],
            "hits": 0,
        },
    ]
    assert report["result"] == "leak" and report["exit_code"] == 1


def test_a_leak_outranks_incompleteness_and_still_lists_reasons(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, {"type": "flow", "id": "late", "status": "timeout"})
    fx.write(otlp, fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])) + "\n")
    run = fx.judge(ledger, [otlp])
    assert run.exit_code == 1
    assert _incomplete(run) == ["incomplete: flow_not_ok late=timeout"]
    assert run.lines[-1] == "result: leak"


def test_a_structured_hit_suppresses_the_raw_hit_on_its_line_only(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, fx.placement("env.B", _B))
    request = json.loads(fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])))
    # Members outside the three signals are left to the raw sweep.
    request["extra"] = f"{_A} {_B}"
    fx.write(otlp, json.dumps(request) + "\n" + json.dumps({"resourceSpans": [], "x": _A}) + "\n")
    run = fx.judge(ledger, [otlp])
    assert fx.leak_lines(run) == [
        f'LEAK env.A file={otlp}:1 signal=traces span="op" at=attributes.k form=raw',
        f"LEAK env.A file={otlp}:2 signal=raw form=raw",
        f"LEAK env.B file={otlp}:1 signal=raw form=raw",
    ]


def test_hits_are_sorted_and_identical_hits_printed_once(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, fx.placement("code.B", _B))
    spans = [
        fx.span("z", attributes=[fx.kv("k", _B), fx.kv("k", _B)]),
        fx.span("a", attributes=[fx.kv("k", _A)]),
    ]
    fx.write(otlp, "\n".join([fx.traces(*spans), fx.traces(spans[1])]) + "\n")
    stderr = tmp_path / "flow.stderr"
    fx.write(stderr, f"{_A}\n{_A} {_A}\n")
    run = fx.judge(ledger, [otlp], [stderr])
    assert fx.leak_lines(run) == [
        f'LEAK code.B file={otlp}:1 signal=traces span="z" at=attributes.k form=raw',
        f"LEAK env.A file={stderr}:1 signal=raw form=raw",
        f"LEAK env.A file={stderr}:2 signal=raw form=raw",
        f'LEAK env.A file={otlp}:1 signal=traces span="a" at=attributes.k form=raw',
        f'LEAK env.A file={otlp}:2 signal=traces span="a" at=attributes.k form=raw',
    ]


def test_directories_are_read_recursively_with_found_paths(tmp_path: Path) -> None:
    ledger, _ = _clean_setup(tmp_path)
    capture = tmp_path / "capture"
    (capture / "b").mkdir(parents=True)
    fx.write((capture / "a.jsonl"), fx.traces(fx.span("op")) + "\n")
    fx.write(
        (capture / "b" / "c.jsonl"), fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])) + "\n"
    )
    run = fx.judge(ledger, [capture])
    assert fx.leak_lines(run) == [
        f'LEAK env.A file={capture}/b/c.jsonl:1 signal=traces span="op" at=attributes.k form=raw'
    ]
    assert ", 2 files, 2 spans," in run.lines[-2]


# --- exit 2 for the capture ---------------------------------------------------


def test_a_missing_capture_path_is_exit_2(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    run = fx.judge(ledger, [otlp], [tmp_path / "absent"])
    assert run.exit_code == 2 and run.stdout == ""
    assert run.stderr.startswith(f"error: capture {tmp_path / 'absent'}: cannot be read (")


@pytest.mark.parametrize("second", ["same file", "its directory"])
def test_a_file_reached_through_two_given_paths_is_exit_2(tmp_path: Path, second: str) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    run = fx.judge(ledger, [otlp], [otlp if second == "same file" else tmp_path])
    assert run.exit_code == 2 and run.stdout == ""
    assert "reached through more than one given path" in run.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_a_fifo_under_a_capture_directory_is_exit_2(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    swept = tmp_path / "swept"
    swept.mkdir()
    os.mkfifo(swept / "pipe")
    run = fx.judge(ledger, [otlp], [swept])
    assert run.exit_code == 2 and run.stdout == ""
    assert run.stderr == f"error: capture {swept}/pipe: not a regular file or directory\n"


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX permissions")
def test_an_unreadable_entry_is_exit_2(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    swept = tmp_path / "swept"
    swept.mkdir()
    locked = swept / "locked.txt"
    fx.write(locked, "x\n")
    os.chmod(locked, 0)
    run = fx.judge(ledger, [otlp], [swept])
    assert run.exit_code == 2 and run.stdout == ""
    assert "locked.txt: cannot be read" in run.stderr


# --- the printing rule ----------------------------------------------------------


def test_capture_text_holding_a_value_is_withheld(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    spans = [
        fx.span(f"tool {_A}", attributes=[fx.kv("k", "v")]),
        fx.span("op", attributes=[fx.kv(f"header.{_A[:9]}", _A)]),
    ]
    fx.write(
        otlp,
        fx.traces(*spans) + "\n" + fx.metrics(fx.gauge(f"m.{_A[2:12]}", description=_A)) + "\n",
    )
    named = tmp_path / "swept"
    named.mkdir()
    fx.write((named / f"dump-{_A[4:13]}.txt"), _A + "\n")
    run = fx.judge(ledger, [otlp], [named])
    assert fx.leak_lines(run) == [
        f'LEAK env.A file={otlp}:1 signal=traces span="[withheld]" at=name form=raw',
        f'LEAK env.A file={otlp}:1 signal=traces span="op" at=attributes.[withheld] form=raw',
        f'LEAK env.A file={otlp}:2 signal=metrics metric="[withheld]" at=description form=raw',
        "LEAK env.A file=[withheld]:1 signal=raw form=raw",
    ]
    fx.assert_value_free(run.stdout, [_A])


def test_a_value_past_the_cut_still_withholds_the_whole_name(tmp_path: Path) -> None:
    """The rule tests the string as captured, not only what survives the
    200-character cut."""
    ledger, otlp = _clean_setup(tmp_path)
    fx.write(otlp, fx.traces(fx.span("n" * 300 + _A, attributes=[fx.kv("k", "v")])) + "\n")
    run = fx.judge(ledger, [otlp])
    assert fx.leak_lines(run) == [
        f'LEAK env.A file={otlp}:1 signal=traces span="[withheld]" at=name form=raw'
    ]


def test_the_span_id_is_reported_as_lowercase_hex(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    spans = [
        fx.span("upper", span_id="00F067AA0BA902B7", attributes=[fx.kv("k", _A)]),
        fx.span("not hex", span_id="not-a-span-id!!!", attributes=[fx.kv("k", _A)]),
    ]
    fx.write(otlp, fx.traces(*spans) + "\n")
    report = fx.judge(ledger, [otlp], as_json=True).report
    hits = typing.cast(list[dict[str, object]], report["hits"])
    assert [(h["span"], h["span_id"]) for h in hits] == [
        ("not hex", None),
        ("upper", "00f067aa0ba902b7"),
    ]


def test_capture_text_is_flattened_and_cut_to_200_characters(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path)
    long_name = "n" * 250
    spans = [
        fx.span("line one\nline two\x1b", attributes=[fx.kv("k", _A)]),
        fx.span(long_name, attributes=[fx.kv("k", _A)]),
    ]
    fx.write(otlp, fx.traces(*spans) + "\n")
    report = fx.judge(ledger, [otlp], as_json=True).report
    names = [h["span"] for h in typing.cast(list[dict[str, object]], report["hits"])]
    assert sorted(typing.cast(list[str], names)) == sorted(
        ["line one\\x0aline two\\x1b", "n" * 197 + "..."]
    )
    assert all(len(typing.cast(str, n)) <= 200 for n in names)


# --- purity, schema, value-free ---------------------------------------------------


def test_the_judge_opens_no_socket_and_starts_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The suite already blocks socket construction (tests/_harness/g3.py);
    this also blocks every way to start a process, then runs a full judge."""

    def refuse(*_args: object, **_kwargs: object) -> typing.NoReturn:
        raise AssertionError("the judge started a process or opened a socket")

    for target, name in (
        (subprocess, "Popen"),
        (os, "system"),
        (os, "popen"),
        (os, "fork"),
        (os, "posix_spawn"),
        (os, "execv"),
        (socket, "socket"),
        (socket, "getaddrinfo"),
    ):
        if hasattr(target, name):
            monkeypatch.setattr(target, name, refuse)
    ledger, otlp = _clean_setup(tmp_path)
    fx.write(otlp, fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])) + "\n")
    assert fx.judge(ledger, [otlp]).exit_code == 1


def test_the_json_report_matches_its_schema_and_decodes_strictly(tmp_path: Path) -> None:
    ledger, otlp = _clean_setup(tmp_path, {"type": "flow", "id": "f2", "status": "failed"})
    fx.write(otlp, fx.traces(fx.span("op", attributes=[fx.kv("k", _A)])) + "\nbad\n")
    run = fx.judge(ledger, [otlp], as_json=True)
    report = msgspec.json.decode(run.stdout, type=Report, strict=True)
    assert report.exit_code == run.exit_code == 1
    assert run.stdout.startswith('{\n  "schema": "canary-report/1",\n  "result": "leak",')
    schema = report_json_schema()
    assert list(typing.cast(dict[str, object], schema["$defs"])["Report"]["properties"]) == list(  # type: ignore[index]
        json.loads(run.stdout)
    )
    fx.assert_value_free(run.stdout, [_A])


def test_deep_nesting_is_walked_or_left_to_the_raw_sweep_never_a_crash(tmp_path: Path) -> None:
    """A capture can nest deeper than Python's stack. Within the decoder's
    limit the walk still finds the value; past it the line is unparsed and
    the raw sweep finds it."""
    ledger, otlp = _clean_setup(tmp_path, fx.placement("env.B", _B))
    # Past Python's default recursion limit (1000), so a recursive walk would
    # crash, yet under the decoder's C recursion limit on every platform:
    # CPython 3.12 caps it at 3000 on Windows.
    walked = 2_000
    unparsable = 200_000
    fx.write(
        otlp,
        fx.traces(fx.span("op"))
        + "\n"
        + '{"resourceSpans": '
        + "[" * walked
        + json.dumps(_A)
        + "]" * walked
        + "}\n"
        + '{"resourceSpans": '
        + "[" * unparsable
        + json.dumps(_B)
        + "]" * unparsable
        + "}\n",
    )
    run = fx.judge(ledger, [otlp], as_json=True)
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    assert [(h["placement"], h["line"], h["signal"]) for h in hits] == [
        ("env.A", 2, "traces"),
        ("env.B", 3, "raw"),
    ]
    # The outermost array is resourceSpans itself; each one inside is a level.
    assert hits[0]["location"] == "resource" + "[0]" * (walked - 1)
    assert run.report["incomplete"] == [{"reason": "unparsed_record", "subject": f"{otlp}:3"}]
