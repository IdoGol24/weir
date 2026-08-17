"""Drift pin for the truthfulness gate (2026-08-17 review): every user-facing
remediation string that claims something about external software behavior is
recorded in REMEDIATION_SOURCES.md with a source URL and a date-checked. This
test recomputes the reviewed digest from the live strings and compares it
against the `reviewed-digest:` line in that file, so an edit to any claim
breaks CI until the doc is re-reviewed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from weir.adapters.otel._contract import REMEDIATION
from weir.catalog import DEFAULT_CATALOG

_SOURCES_DOC = Path(__file__).parents[3] / "REMEDIATION_SOURCES.md"


def reviewed_digest() -> str:
    payload = {
        "contract": {reason.value: text for reason, text in REMEDIATION.items()},
        "catalog": dict(DEFAULT_CATALOG.remediations),
    }
    canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _committed_digest() -> str:
    for line in _SOURCES_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("reviewed-digest:"):
            return line.removeprefix("reviewed-digest:").strip()
    raise AssertionError("REMEDIATION_SOURCES.md has no reviewed-digest: line")


def test_reviewed_digest_matches_committed_sources_doc() -> None:
    assert reviewed_digest() == _committed_digest(), (
        "a REMEDIATION or catalog remediation string changed without a "
        "matching review in REMEDIATION_SOURCES.md - re-review the claim, "
        "update the doc, and recompute reviewed-digest"
    )
