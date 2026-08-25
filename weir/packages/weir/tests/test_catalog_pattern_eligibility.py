"""`pattern` eligibility: shape-shaped data types need no validator function."""

import re

import pytest

from weir.catalog._types import SourceSpec, VerbatimEligibility
from weir.catalog.eligibility import is_verbatim_eligible

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _source(eligibility: VerbatimEligibility) -> SourceSpec:
    # content_pattern is deliberately loose everywhere in this catalog; it is
    # eligibility that must discriminate.
    return SourceSpec(name="probe", content_pattern=r".+", eligibility=eligibility)


def test_pattern_accepts_a_matching_value() -> None:
    source = _source(VerbatimEligibility(pattern=r"AKIA[0-9A-Z]{16}"))
    assert is_verbatim_eligible(_AWS_KEY, source)


def test_pattern_rejects_a_non_matching_value() -> None:
    source = _source(VerbatimEligibility(pattern=r"AKIA[0-9A-Z]{16}"))
    assert not is_verbatim_eligible("hello", source)


def test_pattern_is_fullmatch_not_search() -> None:
    # The whole point: a contributor should not have to remember anchors, and
    # an unanchored pattern must not match INSIDE a longer string. Without
    # fullmatch this value would be eligible and every log line containing a
    # key would fire.
    source = _source(VerbatimEligibility(pattern=r"AKIA[0-9A-Z]{16}"))
    assert not is_verbatim_eligible(f"prefix-{_AWS_KEY}-suffix", source)


def test_an_anchored_pattern_still_works() -> None:
    # Contributors who DO write anchors must not be punished for it.
    source = _source(VerbatimEligibility(pattern=r"^AKIA[0-9A-Z]{16}$"))
    assert is_verbatim_eligible(_AWS_KEY, source)


def test_structure_class_still_wins_when_both_are_set() -> None:
    # The struct's docstring says exactly one option decides. Precedence is
    # declared rather than left to field order: structure_class is the
    # strongest signal (a real checksum), so it is checked first.
    source = _source(VerbatimEligibility(structure_class="iban", pattern=r".+"))
    assert not is_verbatim_eligible(_AWS_KEY, source)


def test_empty_eligibility_still_rejects_everything() -> None:
    assert not is_verbatim_eligible(_AWS_KEY, _source(VerbatimEligibility()))


def test_an_invalid_pattern_fails_loudly_at_use() -> None:
    # A contributor typo must not silently make every value ineligible. This
    # covers the PROGRAMMATIC path only - a spec built in code, bypassing the
    # loader. The contract point for authored catalogs is the loader, which
    # compiles every pattern at load time (Task 2); a bad regex must never
    # reach the analysis path, because an uncaught re.error mid-scan exits 1
    # and in a CI gate that is indistinguishable from a verdict-grade finding.
    source = _source(VerbatimEligibility(pattern=r"AKIA[0-9A-Z"))
    with pytest.raises(re.error):
        is_verbatim_eligible(_AWS_KEY, source)


def test_min_length_alone_is_the_weak_option_it_replaces() -> None:
    # Documents WHY pattern exists: min_length lets any long string through,
    # which is exactly the false positive `pattern` is here to prevent.
    weak = _source(VerbatimEligibility(min_length=20))
    assert is_verbatim_eligible("x" * 20, weak)
    strong = _source(VerbatimEligibility(pattern=r"AKIA[0-9A-Z]{16}"))
    assert not is_verbatim_eligible("x" * 20, strong)
