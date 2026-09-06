"""Eligibility is what earns verdict grade for a credential class (spec
section 1): a strict pattern, a distinct-character floor, and a reject list."""

from pathlib import Path

import pytest

from weir.catalog import (
    DEFAULT_CATALOG,
    SourceSpec,
    VerbatimEligibility,
    class_prefix,
    is_verbatim_eligible,
)
from weir.catalog.loader import load_catalog

_REAL_SHAPE = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"


def _source(name: str) -> SourceSpec:
    return next(s for s in DEFAULT_CATALOG.sources if s.name == name)


def test_a_real_shaped_openai_key_is_eligible() -> None:
    assert is_verbatim_eligible(_REAL_SHAPE, _source("openai_api_key"))


def test_the_distinct_char_floor_counts_the_value_without_its_class_prefix() -> None:
    # `sk-proj-` carries 7 distinct characters by itself, so a floor counted
    # over the whole value would wave a zeroed key through at 8. Counted over
    # the stripped suffix it fails on its own merits, and 8 then means the same
    # thing for every class regardless of how long that class's prefix is.
    assert not is_verbatim_eligible("sk-proj-" + "0" * 40, _source("openai_api_key"))
    assert not is_verbatim_eligible("sk-proj-" + "x" * 40, _source("openai_api_key"))
    assert not is_verbatim_eligible(
        "sk-proj-REDACTEDREDACTEDREDACTEDREDACTED", _source("openai_api_key")
    )
    assert not is_verbatim_eligible("AKIA" + "A" * 16, _source("aws_access_key_id"))
    assert not is_verbatim_eligible("AIza" + "0" * 35, _source("google_api_key"))


def test_class_prefix_covers_every_bundled_shape() -> None:
    assert class_prefix("sk-proj-Qh7Rk2Ls9Vn4") == "sk-proj-"
    assert class_prefix("sk-ant-api03-Qh7Rk2") == "sk-ant-"
    assert class_prefix("ghp_abcdefghij") == "ghp_"
    assert class_prefix("AKIAQH7RK2LS9VN4XB6Z") == "AKIA"
    assert class_prefix("AIzaSyQh7Rk2Ls9Vn4") == "AIza"


def test_reject_patterns_are_case_insensitive_where_declared() -> None:
    # Clears the floor with 16 distinct characters in its suffix, so only the
    # reject list can kill it. The mask and REDACTED shapes fail the floor
    # first, which leaves the list as belt-and-braces for named placeholders -
    # exactly what it is for.
    assert not is_verbatim_eligible(
        "sk-proj-examplekeymaterialgoesrighthere000", _source("openai_api_key")
    )


def test_credential_field_can_never_be_eligible() -> None:
    # No structure_class, no pattern, no min_length: triage by construction.
    assert not is_verbatim_eligible("hunter2hunter2", _source("credential_field"))


def test_aws_key_id_needs_the_exact_width() -> None:
    assert is_verbatim_eligible("AKIAQH7RK2LS9VN4XB6Z", _source("aws_access_key_id"))
    assert not is_verbatim_eligible("AKIAQH7RK2LS9VN4", _source("aws_access_key_id"))


def test_the_documented_aws_example_key_is_rejected() -> None:
    assert not is_verbatim_eligible("AKIAIOSFODNN7EXAMPLE", _source("aws_access_key_id"))


def test_exposure_classes_are_exactly_the_declared_six() -> None:
    assert {s.name for s in DEFAULT_CATALOG.sources if s.exposure} == {
        "openai_api_key",
        "anthropic_api_key",
        "aws_access_key_id",
        "google_api_key",
        "github_token",
        "credential_field",
    }


def test_financial_account_identifier_is_not_an_exposure_class() -> None:
    # An IBAN in a prompt is agent content, not a telemetry leak.
    assert not _source("financial_account_identifier").exposure


def test_an_invalid_reject_pattern_dies_at_load_naming_the_field(tmp_path: Path) -> None:
    (tmp_path / "catalog.json").write_text(
        """
        {
          "sources": [
            {"name": "x", "content_pattern": "a",
             "eligibility": {"pattern": "a", "reject_patterns": ["a(("]}}
          ],
          "sinks": [], "remediations": {}, "scope_remediations": {}
        }
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reject_patterns"):
        load_catalog(tmp_path / "catalog.json")


def test_eligibility_defaults_keep_existing_classes_unchanged() -> None:
    e = VerbatimEligibility(pattern="ghp_[A-Za-z0-9]{36}")
    assert e.min_distinct_chars is None
    assert e.reject_patterns == []
