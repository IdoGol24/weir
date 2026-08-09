"""Section 6 drift check for the diffspec corpus: regenerate everything from
seeds and by-construction ground truth, and fail on any byte difference. Also
fails on stray files, so the committed corpus is exactly what render_all
produces and nothing else.

This TEST may import weir.catalog - tests sit outside the tracegen import
contract that binds the package source."""

import importlib.metadata
from pathlib import Path

from weir.catalog import DEFAULT_CATALOG
from weir.catalog.digest import catalog_digest
from weir_tracegen.diffspec_fixtures import render_all

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"


def _rendered() -> dict[str, str]:
    return render_all(
        catalog_digest=catalog_digest(DEFAULT_CATALOG),
        weir_version=importlib.metadata.version("weir"),
    )


def test_diffspec_corpus_matches_committed() -> None:
    for rel, content in _rendered().items():
        committed = (_FIXTURES_DIR / rel).read_text(encoding="utf-8")
        assert content == committed, (
            f"fixtures/{rel} is stale - regenerate via diffspec_fixtures.write_all; "
            "fixtures are generated, never hand-edited (section 6)"
        )


def test_no_stray_files_in_diffspec_dir() -> None:
    expected = {(_FIXTURES_DIR / rel).resolve() for rel in _rendered()}
    actual = {path.resolve() for path in (_FIXTURES_DIR / "diffspec").rglob("*.json")}
    assert actual == expected


def test_corpus_covers_all_four_families() -> None:
    rendered = _rendered()
    assert len([k for k in rendered if k.startswith("diffspec/runs/")]) == 5
    assert len([k for k in rendered if k.startswith("diffspec/variants/")]) == 4
    assert len([k for k in rendered if k.startswith("diffspec/degraded/")]) == 1
    assert len([k for k in rendered if k.startswith("diffspec/baselines/")]) == 4
    assert len([k for k in rendered if k.startswith("diffspec/expected/")]) == 8
    assert len(rendered) == 22
