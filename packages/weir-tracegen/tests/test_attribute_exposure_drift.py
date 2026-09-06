"""The capture is generated and the expectations are derived; neither is
hand-edited, and both are pinned byte for byte."""

import json
from pathlib import Path

from _harness.exposure import CAPTURE, EXPECTED, render_expected

from weir_tracegen.attribute_exposure import render_all

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"


def test_capture_matches_committed() -> None:
    for rel, content in render_all().items():
        assert (_FIXTURES_DIR / rel).read_text(encoding="utf-8") == content, (
            f"fixtures/{rel} is stale - regenerate via attribute_exposure.write_all")


def test_no_stray_files() -> None:
    on_disk = {p.name for p in (_FIXTURES_DIR / "exposure").iterdir()}
    assert on_disk == {"attribute-exposure.json", "attribute-exposure.expected.json"}


def test_expected_results_match_committed() -> None:
    assert EXPECTED.read_text(encoding="utf-8") == render_expected(), (
        "fixtures/exposure/attribute-exposure.expected.json is stale - regenerate with:\n"
        "  ./.venv/Scripts/python.exe -c \"import sys; sys.path.insert(0, 'tests'); "
        "from _harness.exposure import EXPECTED, render_expected; "
        "EXPECTED.write_text(render_expected(), encoding='utf-8', newline='\\n')\"")


def test_the_capture_proves_the_claims_the_spec_makes_of_it() -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    hits = expected["scan"]["hits"]
    eligible = [h for h in hits if h["eligible"]]

    # One credential, one fingerprint, six vendor-attribute locations plus the
    # raw-string and status-message plants.
    assert len({h["fingerprint"] for h in eligible}) == 1
    assert {h["source_class"] for h in eligible} == {"openai_api_key"}
    assert len([h for h in eligible
                if h["location"].startswith("attributes.acme.agent.")]) == 6
    assert any(h["location"] == "attributes.gen_ai.input.messages" for h in eligible)
    assert any(h["location"] == "status.message" for h in eligible)
    assert expected["verdict_grade"] == len(eligible)

    # Filter independence: the six vendor-attribute hits live on three agent
    # spans, one of which the GenAI marker filter drops.
    assert len({h["span_ref"] for h in eligible
                if h["location"].startswith("attributes.acme.agent.")}) == 3
    assert any(h["span_ref"] == "3333333333333333" for h in eligible)

    # The corpus exercises the triage path itself, not just verdict-grade
    # hits: two different routes into the review queue.
    triage = [h for h in hits if not h["eligible"]]
    assert triage, "the corpus must exercise the triage path, not just verdict-grade"
    assert {h["source_class"] for h in triage} == {"credential_field", "google_api_key"}
    # Both routes into the review queue: a key name with no floor to clear, and
    # a credential-shaped value that failed its class's floor.
    assert all(h["fingerprint"] is None and h["last4"] is None for h in triage)
    assert not any(h["eligible"] and h["location"].startswith("events[") for h in hits)


def test_the_capture_carries_the_key_and_the_expectations_do_not() -> None:
    assert _KEY in CAPTURE.read_text(encoding="utf-8")
    assert _KEY not in EXPECTED.read_text(encoding="utf-8")


def _scan_mutated(transform):
    """Run the real pipeline over a mutated copy of the committed capture. The
    mutation is applied to TEXT, so nothing about the fixture is special-cased."""
    from weir.adapters.otel import decode_input
    from weir.adapters.otel.exposure import scan_surface
    from weir.catalog import DEFAULT_CATALOG
    from weir.evaluate.exposure import evaluate_exposure
    from weir.exposure import classify_exposure
    from weir.rules_commons import load_rules

    data = transform(CAPTURE.read_text(encoding="utf-8")).encode("utf-8")
    scan = classify_exposure(scan_surface(decode_input(data)), DEFAULT_CATALOG)
    return scan, evaluate_exposure(scan, load_rules())


def test_changing_one_character_moves_the_fingerprint_not_the_locations() -> None:
    baseline, base_findings = _scan_mutated(lambda t: t)
    mutated, mut_findings = _scan_mutated(lambda t: t.replace(_KEY, _KEY[:-1] + "5"))
    base_fp = {h.fingerprint for h in baseline.hits if h.eligible}
    mut_fp = {h.fingerprint for h in mutated.hits if h.eligible}
    assert base_fp != mut_fp
    assert len(base_fp) == len(mut_fp) == 1
    assert [h.location for h in baseline.hits] == [h.location for h in mutated.hits]
    assert len(base_findings) == len(mut_findings)


def test_a_placeholder_key_drops_the_verdict_and_leaves_a_triage_line() -> None:
    # Chosen to clear min_distinct_chars (30 distinct suffix characters) so
    # the reject list is the ONLY thing that can demote it. A low-entropy
    # placeholder like sk-proj-REDACTEDREDACTED... is rejected by the floor
    # first, and would make this test prove the wrong clause.
    placeholder = "sk-proj-EXAMPLEQh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5"
    scan, findings = _scan_mutated(lambda t: t.replace(_KEY, placeholder))
    assert not any(f.is_verdict_grade for f in findings)
    assert any(h.source_class == "openai_api_key" and not h.eligible for h in scan.hits)
    assert any("not eligible" in r for f in findings for r in f.demotion_reasons)


def test_removing_every_genai_key_does_not_change_the_hits() -> None:
    baseline, _ = _scan_mutated(lambda t: t)
    stripped, _ = _scan_mutated(lambda t: t.replace("gen_ai.", "acme.stripped."))
    assert [(h.span_ref, h.location.replace("acme.stripped.", "gen_ai."), h.source_class)
            for h in stripped.hits] == [
        (h.span_ref, h.location, h.source_class) for h in baseline.hits]
