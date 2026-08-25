"""Drift check: the bundled `weir gauge --sample` fixture is a byte-for-byte
copy of the committed corpus fixture, never a hand-maintained duplicate that
can silently diverge from it."""

from __future__ import annotations

from pathlib import Path

_BUNDLED = Path(__file__).parents[1] / "src" / "weir" / "data" / "sample-export.json"
_CORPUS = (
    Path(__file__).parents[3]
    / "fixtures"
    / "otlp"
    / "injection-exfil.default-realistic.json"
)


def test_bundled_sample_export_matches_the_committed_corpus_fixture() -> None:
    assert _BUNDLED.read_bytes() == _CORPUS.read_bytes()
