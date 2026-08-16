"""Drift check for the OTLP corpus, plus the accept-side invariant and G1."""

import json
from pathlib import Path
from typing import Any

from _harness.g1 import assert_byte_identical_across_hash_seeds
from _harness.otlp import assert_accept_side

from weir_tracegen.otlp_fixtures import render_all

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"

_EXPECTED_FILES = {
    "otlp/injection-exfil-benign.default-realistic.json",
    "otlp/injection-exfil-benign.full.json",
    "otlp/injection-exfil-benign.partial.json",
    "otlp/injection-exfil.default-realistic.json",
    "otlp/injection-exfil.full.json",
    "otlp/injection-exfil.partial.json",
}


def test_corpus_paths_are_exactly_as_expected() -> None:
    assert set(render_all()) == _EXPECTED_FILES


def test_corpus_matches_committed() -> None:
    for rel, content in render_all().items():
        committed = (_FIXTURES_DIR / rel).read_text(encoding="utf-8")
        assert content == committed, (
            f"fixtures/{rel} is stale - regenerate via otlp_fixtures.write_all; "
            "fixtures are generated, never hand-edited"
        )


def test_no_stray_files() -> None:
    actual = {path.resolve() for path in (_FIXTURES_DIR / "otlp").rglob("*.json")}
    assert actual == {(_FIXTURES_DIR / rel).resolve() for rel in _EXPECTED_FILES}


def test_every_committed_file_is_accept_side() -> None:
    for rel in sorted(_EXPECTED_FILES):
        document: dict[str, Any] = json.loads((_FIXTURES_DIR / rel).read_text(encoding="utf-8"))
        assert_accept_side(document)


def test_render_is_hash_seed_independent() -> None:
    assert_byte_identical_across_hash_seeds(
        "import hashlib;"
        "from weir_tracegen.otlp_fixtures import render_all;"
        "c = render_all();"
        "print(hashlib.sha256(''.join(k + c[k] for k in sorted(c)).encode()).hexdigest())"
    )


def test_render_needs_no_network() -> None:
    # G3 is already inherited: _harness/g3.py is an AUTOUSE fixture, so the
    # whole suite runs under the socket block and this would raise
    # NetworkAccessBlocked if the renderer reached out. Asserted explicitly
    # because "it happens to be offline" should be a checked property.
    assert render_all()
