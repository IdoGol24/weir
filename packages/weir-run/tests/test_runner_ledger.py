"""The ledger the runner writes, judged by the contract's ledger rules
(docs/canary.md, "The ledger") and by `weir canary judge`, which enforces them.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from weir_run.ledger import Ledger, LedgerError
from weir_run.needles import needles
from weir_run.shapes import ByteSource, shaped


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger.jsonl", ByteSource(), ["flow.quickstart"])


def _judge(judge: list[str], tmp_path: Path) -> subprocess.CompletedProcess[bytes]:
    otlp = tmp_path / "otlp"
    otlp.mkdir(exist_ok=True)
    return subprocess.run(
        [
            *judge,
            "canary",
            "judge",
            "--ledger",
            str(tmp_path / "ledger.jsonl"),
            "--otlp",
            str(otlp),
        ],
        capture_output=True,
        check=False,
    )


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")
def test_the_ledger_is_created_private(ledger: Ledger) -> None:
    mode = stat.S_IMODE(ledger.path.stat().st_mode)
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


def test_header_then_whole_lines(ledger: Ledger) -> None:
    ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"), required=True)
    ledger.close()
    data = ledger.path.read_bytes()
    assert data.endswith(b"\n")
    records = _records(ledger.path)
    assert records[0] == {"schema": "canary-ledger/1"}
    assert records[1]["type"] == "placement" and records[1]["required"] is True


def test_the_judge_accepts_what_the_runner_writes(
    ledger: Ledger, judge: list[str], tmp_path: Path
) -> None:
    a = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"), required=True)
    ledger.mint("access_token", shaped(ledger.source, "generic"))
    ledger.exercised(a.id, "request")
    ledger.unexpected("model", "authorization")
    ledger.flow("flow.quickstart", "ok")
    ledger.close()
    done = _judge(judge, tmp_path)
    # Accepted: not exit 2. Nothing captured, so the run is incomplete.
    assert done.returncode == 3, done.stderr
    assert b"incomplete: unexpected_credential unexpected.model.authorization#1" in done.stdout


def test_a_minted_value_is_ledgered_with_minted_evidence(ledger: Ledger) -> None:
    minted = ledger.mint("access_token", shaped(ledger.source, "generic"))
    ledger.close()
    records = _records(ledger.path)
    assert records[1] == {
        "type": "placement",
        "id": "runtime.oauth.access_token#1",
        "kind": "mock-oauth",
        "value": minted.value,
    }
    assert records[2] == {
        "type": "exercised",
        "placement": minted.id,
        "evidence": "minted",
    }


def test_values_are_unique_per_placement(ledger: Ledger) -> None:
    same = iter(["SameValue0123456789a", "SameValue0123456789a", "OtherValue0123456789"])
    first = ledger.plant("env.A_KEY", "env", lambda: next(same))
    second = ledger.plant("env.B_KEY", "env", lambda: next(same))
    assert first.value != second.value


def test_unexpected_records_name_endpoint_and_field_only(ledger: Ledger) -> None:
    first = ledger.unexpected("search", "x-api-key")
    second = ledger.unexpected("search", "x-api-key")
    ledger.close()
    assert (first, second) == ("unexpected.search.x-api-key#1", "unexpected.search.x-api-key#2")
    assert [r for r in _records(ledger.path) if r.get("type") == "unexpected"] == [
        {"type": "unexpected", "id": first},
        {"type": "unexpected", "id": second},
    ]


@pytest.mark.parametrize("bad", ["", "has space", "x" * 129, "semi;colon"])
def test_ids_outside_the_id_rule_are_refused(ledger: Ledger, bad: str) -> None:
    with pytest.raises(LedgerError):
        ledger.flow(bad, "ok")


def test_an_id_holding_a_run_of_a_value_is_refused(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    with pytest.raises(LedgerError):
        ledger.flow(f"flow.{p.value[3:11]}", "ok")


def test_unknown_evidence_status_and_placements_are_refused(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    with pytest.raises(LedgerError):
        ledger.exercised(p.id, "observed")
    with pytest.raises(LedgerError):
        ledger.exercised("env.NOT_PLANTED", "request")
    with pytest.raises(LedgerError):
        ledger.flow("flow.quickstart", "crashed")


def test_a_placement_repr_never_shows_its_value(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    assert p.value not in repr(p)


def test_holders_finds_a_value_in_any_form(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    basic = b"Basic " + base64.b64encode(b"user:" + p.value.encode())
    assert ledger.holders(basic) == [p.id]
    assert ledger.holders(b"Bearer " + p.value.encode()) == [p.id]
    assert ledger.holders(b"Bearer " + p.value[:-1].encode()) == []


def test_redact_replaces_every_needle(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    text = b" | ".join(n for _, n in needles(p.value))
    redacted = ledger.redact(text)
    for _, needle in needles(p.value):
        assert needle not in redacted
    assert redacted.count(f"<canary:{p.id}>".encode()) == len(needles(p.value))


def test_withheld_follows_the_printing_rule(ledger: Ledger) -> None:
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"))
    assert ledger.withheld(f"host-{p.value[5:13]}.invalid")
    assert not ledger.withheld(f"host-{p.value[5:12]}.invalid")
    assert ledger.withheld(base64.b64encode(p.value.encode()).decode())
