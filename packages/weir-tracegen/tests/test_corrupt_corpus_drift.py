"""Committed corrupt corpus == renderer output, byte for byte, and no strays."""

from pathlib import Path

from weir_tracegen.corrupt import render_corrupt_corpus

_FIXTURES = Path(__file__).parents[3] / "fixtures" / "otlp-corrupt"


def test_corrupt_corpus_matches_committed() -> None:
    rendered = render_corrupt_corpus()
    for rel, content in rendered.items():
        assert (_FIXTURES / rel).read_bytes() == content, rel


def test_no_stray_files() -> None:
    rendered = set(render_corrupt_corpus())
    on_disk = {p.name for p in _FIXTURES.iterdir()}
    assert on_disk == rendered
