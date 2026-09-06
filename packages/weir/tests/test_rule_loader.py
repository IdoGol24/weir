import msgspec
import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG, Catalog, SourceSpec, VerbatimEligibility
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
    # misspells its source class fails here rather than in the wild. The sink
    # check is mode-dependent: an exposure rule is a presence claim about one
    # location, so it has no sink by construction, but its source class must
    # be one the exposure scan actually looks at.
    #
    # The two exposure asserts below are shadowed against the bundled
    # directory: `load_rules()` runs the loader's own hard-errors first, so
    # nothing that reaches this point can trip them - they fail correctly
    # when isolated (see the loader tests), but do not count as coverage
    # here. They stand as a backstop if that guard is ever relaxed.
    #
    # The `else` branch is the one still doing real work: fed an intact
    # verbatim rule with `sink_tool_name: "not_a_real_sink"`, the loader
    # accepts it - it only checks the sink is non-null, never that it
    # exists in the catalog. `assert rule.sink_tool_name in sink_names` is
    # the only thing here that would catch a misspelled sink.
    rules = load_rules()
    assert rules, "no bundled rules found"
    source_names = {s.name for s in DEFAULT_CATALOG.sources}
    sink_names = {s.tool_name for s in DEFAULT_CATALOG.sinks}
    for rule in rules:
        assert rule.source_class in source_names
        if rule.mode == "exposure":
            assert rule.sink_tool_name is None
            assert next(s for s in DEFAULT_CATALOG.sources if s.name == rule.source_class).exposure
        else:
            assert rule.sink_tool_name in sink_names


def test_load_rules_rejects_malformed_rule_file(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "broken.json").write_text('{"id": "broken", "version": "1.0.0"}')
    with pytest.raises(msgspec.ValidationError):
        load_rules(tmp_path)


def test_load_rules_validates_against_an_injected_catalog(tmp_path) -> None:  # noqa: ANN001
    # The seam exists so a contributed catalog can be validated without
    # mutating the bundled one.
    (tmp_path / "r.json").write_text(
        msgspec.json.encode(
            {
                "id": "r",
                "version": "1.0.0",
                "stage": "active",
                "description": "d",
                "source_class": "acme_token",
                "sink_tool_name": None,
                "mode": "exposure",
            }
        ).decode()
    )
    catalog = Catalog(
        sources=[
            SourceSpec(
                name="acme_token",
                content_pattern="acme-[0-9]+",
                eligibility=VerbatimEligibility(pattern="acme-[0-9]{8}"),
                exposure=True,
            )
        ],
        sinks=[],
        remediations={},
    )
    rules = load_rules(tmp_path, catalog=catalog)
    assert rules[0].source_class == "acme_token"
    # And the same rule is rejected against the bundled catalog, which has no such class.
    with pytest.raises(ValueError, match="not in the catalog"):
        load_rules(tmp_path)


def test_load_rules_is_hash_seed_independent() -> None:
    code = (
        "from weir.rules_commons import load_rules\n"
        "print([r.id for r in load_rules()])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
