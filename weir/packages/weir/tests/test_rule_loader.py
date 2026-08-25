import msgspec
import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.rules_commons import load_rules
from weir.rules_commons.loader import _BUNDLED_RULES_DIR


def test_load_rules_returns_every_bundled_rule() -> None:
    # Derived from the directory the loader actually reads, not a restated
    # list: dropping a rule JSON into `bundled/` is the whole contribution
    # story for rules, and it must not require editing this file.
    on_disk = sorted(path.stem for path in _BUNDLED_RULES_DIR.glob("*.json"))
    assert [r.id for r in load_rules()] == on_disk


def test_load_rules_is_deterministically_ordered() -> None:
    first = load_rules()
    second = load_rules()
    assert [r.id for r in first] == [r.id for r in second]


def test_load_rules_orders_by_id_not_filesystem_order(tmp_path) -> None:  # noqa: ANN001
    for rule_id in ("zzz-rule", "aaa-rule", "mmm-rule"):
        (tmp_path / f"{rule_id}.json").write_text(
            msgspec.json.encode(
                {
                    "id": rule_id,
                    "version": "1.0.0",
                    "stage": "active",
                    "description": "test",
                    "source_class": "financial_account_identifier",
                    "sink_tool_name": "send_email",
                    "mode": "verbatim",
                }
            ).decode()
        )
    rules = load_rules(tmp_path)
    assert [r.id for r in rules] == ["aaa-rule", "mmm-rule", "zzz-rule"]


def test_every_loaded_rule_references_a_real_catalog_source_and_sink() -> None:
    # A rule naming a source class the catalog does not define would silently
    # never fire. Checked for every bundled rule, so a contributed rule that
    # misspells its source class fails here rather than in the wild.
    rules = load_rules()
    assert rules, "no bundled rules found"
    source_names = {s.name for s in DEFAULT_CATALOG.sources}
    sink_names = {s.tool_name for s in DEFAULT_CATALOG.sinks}
    for rule in rules:
        assert rule.source_class in source_names
        assert rule.sink_tool_name in sink_names


def test_load_rules_rejects_malformed_rule_file(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "broken.json").write_text('{"id": "broken", "version": "1.0.0"}')
    with pytest.raises(msgspec.ValidationError):
        load_rules(tmp_path)


def test_load_rules_is_hash_seed_independent() -> None:
    code = (
        "from weir.rules_commons import load_rules\n"
        "print([r.id for r in load_rules()])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
