"""Derive the expected exposure results from the committed capture.

The expectations are RUN, never typed (AGENTS.md): this feeds the committed
bytes through the real scan and serializes what comes out. It lives test-side
because tracegen may not import `weir.catalog` or `weir.exposure` - the import
contract that keeps the corpus independent of the analyzer that judges it - and
tests sit outside that contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import msgspec

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG
from weir.evaluate.exposure import evaluate_exposure
from weir.exposure import classify_exposure
from weir.rules_commons import load_rules

_ROOT = Path(__file__).parents[2]
CAPTURE = _ROOT / "fixtures" / "exposure" / "attribute-exposure.json"
EXPECTED = _ROOT / "fixtures" / "exposure" / "attribute-exposure.expected.json"


def render_expected() -> str:
    surface = scan_surface(decode_input(CAPTURE.read_bytes()))
    scan = classify_exposure(surface, DEFAULT_CATALOG)
    findings = evaluate_exposure(scan, load_rules())
    document = {
        "scan": msgspec.to_builtins(scan, str_keys=True),
        "findings": msgspec.to_builtins(findings, str_keys=True),
        "verdict_grade": sum(1 for f in findings if f.is_verdict_grade),
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
