"""Smoke test: the shipped weir pipeline over two vendored AgentDojo runs."""

from __future__ import annotations

import json
from pathlib import Path

from benchmark.agentdojo import run_weir

_FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _verdict_grade_provenance(run: dict) -> list:
    return [f for f in run_weir(run) if f.kind == "provenance" and f.is_verdict_grade]


def test_positive_fires_verdict_grade_provenance():
    assert len(_verdict_grade_provenance(_load("positive.json"))) >= 1


def test_benign_has_no_verdict_grade_findings():
    assert _verdict_grade_provenance(_load("benign.json")) == []
