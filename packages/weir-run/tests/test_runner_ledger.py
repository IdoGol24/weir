"""The ledger the runner writes, judged by the contract's ledger rules
(docs/canary.md, "The ledger") and by `weir canary judge`, which enforces them.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from weir_run.ledger import Ledger, LedgerError
from weir_run.needles import needles
from weir_run.shapes import ID_OVERLAP, SHAPES, ByteSource, shaped, windows


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
    a = ledger.plant(
        "env.A_KEY",
        "env",
        shaped(ledger.source, "generic"),
        required=True,
        providers=("model",),
        provider_host="api.a.invalid",
    )
    ledger.mint("access_token", shaped(ledger.source, "generic"), ("oauth", "search"))
    ledger.exercised(a.id, "request")
    ledger.unexpected("model", "authorization")
    ledger.flow("flow.quickstart", "ok")
    ledger.close()
    done = _judge(judge, tmp_path)
    # Accepted: not exit 2. Nothing captured, so the run is incomplete.
    assert done.returncode == 3, done.stderr
    assert b"incomplete: unexpected_credential unexpected.model.authorization#1" in done.stdout


def test_a_minted_value_is_ledgered_with_minted_evidence(ledger: Ledger) -> None:
    minted = ledger.mint("access_token", shaped(ledger.source, "generic"), ("oauth", "search"))
    ledger.close()
    records = _records(ledger.path)
    assert records[1] == {
        "type": "placement",
        "id": "runtime.oauth.access_token#1",
        "kind": "mock-oauth",
        "value": minted.value,
        "providers": ["oauth", "search"],
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
    # docs/canary.md: a run of 6 consecutive characters is withheld, 5 is not.
    assert ledger.withheld(f"host-{p.value[5:11]}.invalid")
    assert not ledger.withheld(f"host-{p.value[5:10]}.invalid")
    assert ledger.withheld(base64.b64encode(p.value.encode()).decode())


@pytest.mark.parametrize("shape", sorted(s for s in SHAPES if SHAPES[s].prefix))
def test_withheld_judges_the_random_part(ledger: Ledger, shape: str) -> None:
    """The prefix every key of a shape carries is no trace of this key; a
    run of ID_OVERLAP characters of its random part is, even where the run
    starts inside the prefix."""
    prefix = SHAPES[shape].prefix
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, shape), parts=SHAPES[shape].parts)
    assert p.value.startswith(prefix)
    assert not ledger.withheld(f"a key of kind {prefix}")
    assert not ledger.withheld(p.value[: len(prefix) + ID_OVERLAP - 1])
    assert ledger.withheld(p.value[: len(prefix) + ID_OVERLAP])
    assert ledger.withheld(f"slice {p.value[-ID_OVERLAP:]}")


def test_host_text_is_judged_in_either_case(ledger: Ledger) -> None:
    """A host name reaches the runner case-folded: with host, a run of a
    value is withheld in any letter case; without it, only as drawn."""
    p = ledger.plant("env.A_KEY", "env", shaped(ledger.source, "aws-access-key-id"))
    # A run with a letter, which the shape draws in upper case only.
    run = next(w for w in sorted(windows(p.value)) if w != w.lower())
    for text in (run, run.lower(), run.swapcase()):
        assert ledger.withheld(f"{text}.example.invalid", host=True)
    assert ledger.withheld(run)
    assert not ledger.withheld(f"{run.lower()}.example.invalid")
    assert not ledger.withheld(f"{run[:-1].lower()}.example.invalid", host=True)


@pytest.mark.parametrize("shape", sorted(s for s in SHAPES if len(SHAPES[s].prefix) >= ID_OVERLAP))
def test_host_text_is_judged_by_the_whole_value(ledger: Ledger, shape: str) -> None:
    """docs/canary.md, "Printing capture-derived text": a host holding a run
    of 6 characters of a ledger value is withheld, and the value includes
    its shape's prefix, as the judge reads it. The relay of a flow's own
    output judges the random part only, so the prefix reads as printed."""
    prefix = SHAPES[shape].prefix
    ledger.plant("env.A_KEY", "env", shaped(ledger.source, shape), parts=SHAPES[shape].parts)
    host = f"{prefix}x.example"
    for text in (host, host.upper()):
        assert ledger.withheld(text, host=True)
    assert not ledger.withheld(host)
    assert not ledger.withheld(f"{prefix[: ID_OVERLAP - 1]}x.example", host=True)


def test_a_value_must_carry_its_prefix(ledger: Ledger) -> None:
    with pytest.raises(LedgerError, match="random parts"):
        ledger.plant(
            "env.A_KEY", "env", shaped(ledger.source, "generic"), parts=SHAPES["openai"].parts
        )


# Random parts no 6-character run could match, so every slice would print.
UNMATCHABLE: dict[str, Callable[[str], tuple[str, ...]]] = {
    "none": lambda v: (),
    "too-short": lambda v: (v[: ID_OVERLAP - 1],),
    "not-in-value": lambda v: (v[1:] + "!",),
}


@pytest.mark.parametrize("parts", UNMATCHABLE.values(), ids=UNMATCHABLE.keys())
def test_random_parts_the_rule_could_never_match_are_refused(
    ledger: Ledger, parts: Callable[[str], tuple[str, ...]]
) -> None:
    with pytest.raises(LedgerError, match="random parts"):
        ledger.plant("env.A_KEY", "env", shaped(ledger.source, "generic"), parts=parts)
