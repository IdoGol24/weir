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
