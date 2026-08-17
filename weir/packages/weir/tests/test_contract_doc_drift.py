"""Drift check: docs/contract.md is generated from render_contract_doc(), so
the committed doc cannot silently diverge from the DegradationReason enum and
its remediation strings."""

from __future__ import annotations

from pathlib import Path

from weir.adapters.otel._contract import render_contract_doc

_DOC = Path(__file__).parents[3] / "docs" / "contract.md"


def test_committed_contract_doc_matches_the_renderer() -> None:
    assert render_contract_doc() == _DOC.read_text(encoding="utf-8")
