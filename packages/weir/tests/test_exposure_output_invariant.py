# packages/weir/tests/test_exposure_output_invariant.py
"""No rendered weir output contains a credential-shaped value.

Not "the paths we thought of": every exposure class's content_pattern is run
with finditer over every artifact weir produces, and every match is put through
is_verbatim_eligible. This closes the node-preview and ledger free-text paths
in one assertion and stays true as renderers change. `message.text` is named
here for the SARIF renderer when it lands, because that is the one field
someone will be tempted to fill "for context".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import msgspec
import pytest
from click.testing import CliRunner

from weir.adapters.otel import OtlpRejectError, adapt_otlp, decode_input
from weir.catalog import DEFAULT_CATALOG, is_verbatim_eligible
from weir.cli.main import main

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_EXPOSURE_CLASSES = [s for s in DEFAULT_CATALOG.sources if s.exposure]


def assert_no_eligible_values(text: str, label: str) -> None:
    for source in _EXPOSURE_CLASSES:
        for match in re.finditer(source.content_pattern, text):
            value = (match.group(1) if match.re.groups else match.group(0)) or ""
            assert not is_verbatim_eligible(value, source), (
                f"{label} rendered a value eligible for {source.name} at "
                f"offset {match.start()}")


def _corpus() -> list[Path]:
    paths = sorted(_FIXTURES_DIR.rglob("*.json")) + sorted(_FIXTURES_DIR.rglob("*.jsonl"))
    return [p for p in paths if "expected" not in p.name and "baseline" not in p.name]


def _ledger_text(fixture: Path) -> str | None:
    """The adapter's degradation ledger, encoded the same way msgspec would
    render it, for fixtures that are OTLP wire input. `None` for fixtures
    that are already-canonical traces or deliberately not-OTLP-shaped
    (`OtlpRejectError`) - those never produce a ledger to check."""
    try:
        result = adapt_otlp(fixture.read_bytes())
    except OtlpRejectError:
        return None
    return msgspec.json.encode(result.degradations).decode("utf-8")


@pytest.mark.parametrize("fixture", _corpus(), ids=lambda p: p.name)
def test_no_rendered_artifact_carries_a_credential_shaped_value(
    fixture: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    report = tmp_path / "r.html"
    scan = runner.invoke(main, ["scan", str(fixture), "--report", str(report)])
    gauge = runner.invoke(main, ["gauge", str(fixture)])

    assert_no_eligible_values(scan.output, f"scan text for {fixture.name}")
    assert_no_eligible_values(gauge.output, f"gauge text for {fixture.name}")
    if report.exists():
        assert_no_eligible_values(
            report.read_text(encoding="utf-8"), f"html for {fixture.name}")
    ledger = _ledger_text(fixture)
    if ledger is not None:
        assert_no_eligible_values(ledger, f"degradation ledger for {fixture.name}")


def test_undecodable_span_ledger_entry_carries_no_eligible_credential() -> None:
    # A span that fails structural decode while carrying a real-shaped key
    # (here in its `name`) must not leak that value into the ledger. The
    # quarantine subject names the span's KEYS, never a raw JSON slice of it
    # (see CHANGELOG); a raw slice would put the value straight into a
    # rendered artifact via test_no_rendered_artifact_carries_a_credential_
    # shaped_value above.
    doc = {
        "resourceSpans": [{"scopeSpans": [{"spans": [
            {"attributes": "bogus",
             "name": "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"},
        ]}]}]
    }
    wire = decode_input(json.dumps(doc).encode())
    entry = next(d for d in wire.degradations if d.reason == "undecodable_span")
    assert_no_eligible_values(entry.subject, "quarantined span subject")
    assert_no_eligible_values(entry.note, "quarantined span note")


def test_the_invariant_would_catch_a_leak() -> None:
    # The assertion has teeth only if it fails on a real value.
    with pytest.raises(AssertionError):
        assert_no_eligible_values(
            "context: sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4", "probe")
