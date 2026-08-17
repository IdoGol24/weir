"""Presets are generation labels with recorded clause sets."""

import pytest

from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import PRESETS, Clause, apply_preset


def test_three_presets_ship_each_with_a_clause_set() -> None:
    assert set(PRESETS) == {"full", "partial", "default-realistic"}
    for preset in PRESETS.values():
        assert preset.clauses, "a preset name without a clause set is the prose bug reborn"


def test_full_satisfies_every_clause() -> None:
    assert PRESETS["full"].clauses == frozenset(Clause)


def test_partial_is_content_on_linkage_absent() -> None:
    clauses = PRESETS["partial"].clauses
    assert Clause.FULL_ARGUMENT_PAYLOADS in clauses
    assert Clause.EXPLICIT_TOOL_CALL_LINKAGE not in clauses


def test_default_realistic_is_content_off_linkage_present() -> None:
    clauses = PRESETS["default-realistic"].clauses
    assert Clause.FULL_ARGUMENT_PAYLOADS not in clauses
    assert Clause.EXPLICIT_TOOL_CALL_LINKAGE in clauses


def test_source_ref_and_actor_clauses_hold_in_every_preset() -> None:
    # No shipped dial removes step ids or actors, so these two clauses hold
    # everywhere. If a future dial breaks one, this test says so.
    for preset in PRESETS.values():
        assert Clause.PRESERVED_SOURCE_REF in preset.clauses
        assert Clause.STABLE_ACTOR_IDENTIFIERS in preset.clauses


def test_apply_preset_dials_the_plan() -> None:
    plan = instantiate("injection-exfil", seed=1)
    assert all(step.content_captured for step in apply_preset(plan, "full").steps)
    assert all(
        not step.content_captured for step in apply_preset(plan, "default-realistic").steps
    )
    assert all(j.join_confidence == "nested" for j in apply_preset(plan, "partial").joins)


def test_apply_preset_does_not_mutate_the_input() -> None:
    plan = instantiate("injection-exfil", seed=1)
    apply_preset(plan, "default-realistic")
    assert all(step.content_captured for step in plan.steps)


def test_full_is_the_identity_dialing() -> None:
    plan = instantiate("injection-exfil", seed=1)
    assert apply_preset(plan, "full") == plan


def test_unknown_preset_rejected() -> None:
    with pytest.raises(KeyError):
        apply_preset(instantiate("injection-exfil", seed=1), "no-such-preset")
