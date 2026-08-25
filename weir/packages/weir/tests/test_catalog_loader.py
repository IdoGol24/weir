"""The catalog is loadable data, not a Python literal."""

import inspect
from pathlib import Path

import msgspec
import pytest

import weir.catalog.default as default_module
from weir.catalog import DEFAULT_CATALOG, catalog_digest
from weir.catalog.loader import load_catalog

# Pinned from Task 1. Moving the catalog from a literal into JSON must not
# change its content, and the digest is what proves that.
_EXPECTED_DIGEST = "0d616619cd0b992faa10bfb26490738bc6c4b7195fce0937590e8e6e92795606"


def test_default_catalog_is_the_loaded_one() -> None:
    assert DEFAULT_CATALOG == load_catalog()


def test_the_move_did_not_change_the_catalog_content() -> None:
    assert catalog_digest(DEFAULT_CATALOG) == _EXPECTED_DIGEST


def test_a_contributor_catalog_loads_with_no_code_change(tmp_path: Path) -> None:
    # The whole point of the task: a new data type is a JSON edit. This one
    # uses `pattern`, so it needs no validator function at all.
    (tmp_path / "catalog.json").write_text(
        """
        {
          "sources": [
            {"name": "aws_access_key_id",
             "content_pattern": "\\\\b[A-Z0-9]{20}\\\\b",
             "eligibility": {"pattern": "AKIA[0-9A-Z]{16}"}}
          ],
          "sinks": [{"tool_name": "send_email", "destination_arg_keys": ["to"]}],
          "remediations": {},
          "scope_remediations": {}
        }
        """,
        encoding="utf-8",
    )
    catalog = load_catalog(tmp_path / "catalog.json")
    assert catalog.sources[0].name == "aws_access_key_id"
    assert catalog.sources[0].eligibility.pattern == "AKIA[0-9A-Z]{16}"


def test_a_malformed_catalog_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "catalog.json").write_text('{"sources": "not a list"}', encoding="utf-8")
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        load_catalog(tmp_path / "catalog.json")


def test_an_invalid_pattern_dies_at_load_naming_the_source(tmp_path: Path) -> None:
    # The contract point. An uncompilable regex reaching the analysis path
    # would raise re.error mid-scan and exit 1, which a CI gate cannot tell
    # apart from a real verdict-grade finding.
    (tmp_path / "catalog.json").write_text(
        """
        {
          "sources": [
            {"name": "typo_class",
             "content_pattern": ".+",
             "eligibility": {"pattern": "AKIA[0-9A-Z"}}
          ],
          "sinks": [], "remediations": {}, "scope_remediations": {}
        }
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"typo_class.*eligibility\.pattern"):
        load_catalog(tmp_path / "catalog.json")


def test_an_invalid_content_pattern_also_dies_at_load(tmp_path: Path) -> None:
    # content_pattern is equally contributor-authored and has the identical
    # failure mode, so it is compiled by the same loop.
    (tmp_path / "catalog.json").write_text(
        """
        {
          "sources": [
            {"name": "typo_class",
             "content_pattern": "[unclosed",
             "eligibility": {"min_length": 8}}
          ],
          "sinks": [], "remediations": {}, "scope_remediations": {}
        }
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"typo_class.*content_pattern"):
        load_catalog(tmp_path / "catalog.json")


def test_the_bundled_file_is_the_only_source_of_the_default() -> None:
    # Guards the regression this task exists to prevent: someone reintroducing
    # a Python literal alongside the JSON, so the two can drift.
    source = inspect.getsource(default_module)
    assert "SourceSpec(" not in source
    assert "load_catalog" in source
