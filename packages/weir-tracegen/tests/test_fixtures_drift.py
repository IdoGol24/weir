"""§6: fixtures are committed, never hand-edited - CI regenerates from seeds
and fails on any diff. This test IS that regeneration check for the demo's
gold corpus (fixtures/*.json, committed at repo root)."""

from pathlib import Path

from weir_tracegen.emitter import emit, emit_degraded
from weir_tracegen.fixture_io import render_fixture_json

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_DEMO_SEED = 1


def _assert_matches_committed(filename: str, rendered: str) -> None:
    committed = (_FIXTURES_DIR / filename).read_text()
    assert rendered == committed, (
        f"fixtures/{filename} is stale - regenerate it from weir_tracegen.emitter "
        f"(seed={_DEMO_SEED}); fixtures are never hand-edited (§6)"
    )


def test_injection_exfil_fixture_matches_committed() -> None:
    _assert_matches_committed(
        "injection-exfil.json",
        render_fixture_json(emit("injection-exfil", seed=_DEMO_SEED)),
    )


def test_injection_exfil_benign_fixture_matches_committed() -> None:
    _assert_matches_committed(
        "injection-exfil-benign.json",
        render_fixture_json(emit("injection-exfil-benign", seed=_DEMO_SEED)),
    )


def test_injection_exfil_benign_degraded_fixture_matches_committed() -> None:
    _assert_matches_committed(
        "injection-exfil-benign.degraded.json",
        render_fixture_json(
            emit_degraded(
                "injection-exfil-benign", seed=_DEMO_SEED, degrade_tool_call_indices=[1, 4]
            )
        ),
    )
