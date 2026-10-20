"""The ledger is strict (docs/canary.md, "The ledger").

Each clause of the contract's exit-2 list is one case here. Every rejection
exits 2, prints no report, names the ledger and the line, and never echoes
ledger content: each bad record carries a fake value, an unknown field name
or an enum value built to be recognisable, and none may reach stderr.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import canary_fixtures as fx
import pytest

_VALUE = fx.fake_value("ledger-a")
_OTHER = fx.fake_value("ledger-b")
_MARK = fx.fake_value("content-marker", 12)  # content that must never be echoed
_GOOD = fx.placement("env.API_KEY", _VALUE)


def _lines(*records: object) -> str:
    return "".join(
        (r if isinstance(r, str) else json.dumps(r)) + "\n"
        for r in ({"schema": "canary-ledger/1"}, *records)
    )


# (case id, ledger text, the line the error must name or None)
_CASES: list[tuple[str, str, int | None]] = [
    ("header missing", json.dumps(_GOOD) + "\n", 1),
    ("header names another schema", _lines().replace("canary-ledger/1", "canary-ledger/2"), 1),
    ("header empty file", "", None),
    ("not a JSON object", _lines(_GOOD, f'["{_MARK}"]'), 3),
    ("not JSON", _lines(_GOOD, f"{{{_MARK}"), 3),
    ("empty line", _lines(_GOOD, ""), 3),
    ("no final newline", _lines(_GOOD).rstrip("\n"), 2),
    ("unknown type", _lines(_GOOD, {"type": _MARK, "id": "x.y"}), 3),
    ("unknown field", _lines({**_GOOD, _MARK: 1}), 2),
    ("wrong type", _lines({**_GOOD, "required": "yes"}), 2),
    ("wrong type for value", _lines({**_GOOD, "value": 1234567890123456789}), 2),
    ("unknown kind", _lines({**_GOOD, "kind": _MARK}), 2),
    (
        "unknown evidence",
        _lines(_GOOD, {"type": "exercised", "placement": "env.API_KEY", "evidence": _MARK}),
        3,
    ),
    ("unknown status", _lines(_GOOD, {"type": "flow", "id": "f1", "status": _MARK}), 3),
    ("id with a bad character", _lines({**_GOOD, "id": "env API KEY"}), 2),
    ("id with a trailing newline", _lines({**_GOOD, "id": "env.API_KEY\n"}), 2),
    ("empty id", _lines({**_GOOD, "id": ""}), 2),
    ("id over 128 characters", _lines({**_GOOD, "id": "a" * 129}), 2),
    (
        "id holding 8 characters of a value",
        _lines(_GOOD, {"type": "flow", "id": "f." + _VALUE[3:11], "status": "ok"}),
        3,
    ),
    ("placement id repeats", _lines(_GOOD, fx.placement("env.API_KEY", _OTHER)), 3),
    (
        "flow id repeats",
        _lines(
            _GOOD,
            {"type": "flow", "id": "f1", "status": "ok"},
            {"type": "flow", "id": "f1", "status": "ok"},
        ),
        4,
    ),
    (
        "unexpected id repeats",
        _lines(_GOOD, {"type": "unexpected", "id": "u.a#1"}, {"type": "unexpected", "id": "u.a#1"}),
        4,
    ),
    ("value repeats", _lines(_GOOD, fx.placement("env.OTHER", _VALUE)), 3),
    ("value shorter than 16 characters", _lines(fx.placement("env.SHORT", _VALUE[:15])), 2),
    (
        "exercised names no placement",
        _lines(_GOOD, {"type": "exercised", "placement": "env.MISSING", "evidence": "request"}),
        3,
    ),
    ("no placement", _lines({"type": "flow", "id": "f1", "status": "ok"}), None),
    ("duplicate key", _lines(json.dumps(_GOOD)[:-1] + f', "value": "{_OTHER}"}}'), 2),
    ("not UTF-8", _lines(_GOOD) + '{"type": "unexpected", "id": "u.\udcff"}\n', 3),
]


@pytest.mark.parametrize(
    ("text", "line"), [(c[1], c[2]) for c in _CASES], ids=[c[0] for c in _CASES]
)
def test_a_bad_ledger_is_exit_2_naming_the_line_never_content(
    tmp_path: Path, text: str, line: int | None
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(text.encode("utf-8", errors="surrogateescape"))
    os.chmod(ledger, 0o600)
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert run.exit_code == 2
    assert run.stdout == ""
    assert run.stderr.startswith(f"error: ledger {ledger}")
    assert run.stderr.count("\n") == 1
    if line is not None:
        assert f"line {line}:" in run.stderr
    fx.assert_value_free(run.stderr, [_VALUE, _OTHER, _MARK])


def test_a_good_ledger_with_a_forward_reference_is_accepted(tmp_path: Path) -> None:
    """`exercised` names a placement "defined in this ledger, on any line"."""
    ledger = tmp_path / "ledger.jsonl"
    fx.write(
        ledger,
        _lines({"type": "exercised", "placement": "env.API_KEY", "evidence": "request"}, _GOOD),
    )
    os.chmod(ledger, 0o600)
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert run.exit_code == 0, run.stderr
    assert run.lines[-1] == "result: clean"


def test_a_missing_ledger_is_exit_2(tmp_path: Path) -> None:
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    run = fx.judge(tmp_path / "absent.jsonl", [tmp_path / "otlp.jsonl"])
    assert run.exit_code == 2 and run.stdout == ""
    assert "cannot be read" in run.stderr


@pytest.mark.skipif(os.name != "posix", reason="the mode rule applies on a POSIX system")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_a_ledger_readable_by_group_or_others_is_exit_2(tmp_path: Path, mode: int) -> None:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [_GOOD])
    os.chmod(ledger, mode)
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert run.exit_code == 2 and run.stdout == ""
    assert "readable by group or others" in run.stderr


@pytest.mark.skipif(os.name != "posix", reason="the mode rule applies on a POSIX system")
def test_an_owner_only_ledger_is_accepted_whatever_its_other_bits(tmp_path: Path) -> None:
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [_GOOD])
    os.chmod(ledger, 0o400)
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("op")) + "\n")
    assert fx.judge(ledger, [tmp_path / "otlp.jsonl"]).exit_code == 0
