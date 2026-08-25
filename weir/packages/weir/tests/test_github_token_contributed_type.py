"""github_token: the first source class contributed as catalog data only.

The IBAN class was authored by the person with merge access, so it proves
nothing about the contribution surface. This module is the walkthrough
evidence - a shape-shaped type added with no validator function, whose
finding fires and whose near-miss does not.

Every expectation here is DERIVED from the committed fixture bytes by running
the real pipeline, never restated as a literal. The two token values are read
back out of the traces rather than declared, so a fixture edit that changed
them could not pass by agreeing with a constant in this file.
"""

from pathlib import Path

from click.testing import CliRunner

from weir.catalog import DEFAULT_CATALOG
from weir.catalog.eligibility import is_verbatim_eligible
from weir.cli.main import main
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import decode_canonical_trace

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_POSITIVE = "github-token-exfil.json"
_NEAR_MISS = "github-token-nearmiss.json"


def _labeled_github_tokens(fixture: str) -> list[str]:
    """What the catalog's content_pattern actually pulls out of the committed
    trace - the loose label layer, before eligibility gets a vote."""
    trace = decode_canonical_trace((_FIXTURES_DIR / fixture).read_bytes())
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    return [
        label.matched_value
        for label in labeled.source_labels
        if label.source_class == "github_token"
    ]


def test_the_positive_fixture_fires_and_names_the_contributed_class() -> None:
    result = CliRunner().invoke(main, ["scan", str(_FIXTURES_DIR / _POSITIVE)])
    assert result.exit_code == 1
    assert "github-token-to-outbound-sink" in result.output
    assert "github_token" in result.output


def test_the_near_miss_fixture_does_not_fire() -> None:
    result = CliRunner().invoke(main, ["scan", str(_FIXTURES_DIR / _NEAR_MISS)])
    assert result.exit_code == 0
    assert "0 verdict-grade findings" in result.output


def test_eligibility_not_the_content_pattern_is_what_discriminates() -> None:
    # The point of the near-miss discipline. content_pattern is deliberately
    # loose, so it must label BOTH the real token and the lookalike; only
    # eligibility may tell them apart. If content_pattern were tightened to
    # the token's exact shape, eligibility would become a tautology and this
    # assertion is what would notice.
    source = next(s for s in DEFAULT_CATALOG.sources if s.name == "github_token")
    labeled = _labeled_github_tokens(_POSITIVE)
    assert len(labeled) == 2
    eligible = [value for value in labeled if is_verbatim_eligible(value, source)]
    assert len(eligible) == 1
    # Derived, not declared: the eligible one is the real token, the rejected
    # one is the lookalike that is one character short.
    (rejected,) = [value for value in labeled if value not in eligible]
    assert len(eligible[0]) == len(rejected) + 1


def test_the_near_miss_is_labeled_but_ineligible() -> None:
    # A near-miss that failed to label at all would prove nothing: it would be
    # rejected by the label pattern, never reaching the floor under test.
    source = next(s for s in DEFAULT_CATALOG.sources if s.name == "github_token")
    labeled = _labeled_github_tokens(_NEAR_MISS)
    assert labeled, "the near-miss must clear content_pattern, or it tests nothing"
    assert not any(is_verbatim_eligible(value, source) for value in labeled)
