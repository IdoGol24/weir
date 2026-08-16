"""Dials are pure plan-to-plan functions."""

import pytest

from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.dials import (
    drop_step,
    with_clock_skew,
    with_truncated_content,
    without_content,
    without_linkage,
)


def _plan():
    return instantiate("injection-exfil", seed=1)


def test_dials_do_not_mutate_the_input_plan() -> None:
    plan = _plan()
    before = [step.content_captured for step in plan.steps]
    without_content(plan)
    assert [step.content_captured for step in plan.steps] == before


def test_without_content_clears_capture_on_every_step() -> None:
    dialed = without_content(_plan())
    assert all(not step.content_captured for step in dialed.steps)
    # Structure is untouched: only the capture flag moves.
    assert len(dialed.steps) == len(_plan().steps)
    assert dialed.joins == _plan().joins


def test_without_linkage_demotes_joins_to_nested() -> None:
    dialed = without_linkage(_plan())
    assert all(join.join_confidence == "nested" for join in dialed.joins)
    assert [s.kind for s in dialed.steps] == [s.kind for s in _plan().steps]


def test_with_truncated_content_shortens_but_keeps_capture_on() -> None:
    dialed = with_truncated_content(_plan(), limit=12)
    for step in dialed.steps:
        assert step.content_captured is True
        if step.content is not None:
            assert len(step.content) <= 12


def test_with_clock_skew_offsets_only_the_named_step() -> None:
    dialed = with_clock_skew(_plan(), step_index=3, offset_ns=500_000_000)
    assert dialed.steps[3].clock_offset_ns == 500_000_000
    assert all(s.clock_offset_ns == 0 for i, s in enumerate(dialed.steps) if i != 3)


def test_drop_step_removes_it_and_reindexes_joins() -> None:
    plan = _plan()
    # Index 7 is the trailing tool_result; dropping it must retire the join
    # that referenced it rather than leave a dangling index.
    dialed = drop_step(plan, index=7)
    assert len(dialed.steps) == len(plan.steps) - 1
    for join in dialed.joins:
        assert join.call_index < len(dialed.steps)
        assert join.result_index < len(dialed.steps)


def test_drop_step_refuses_to_orphan_a_join_target() -> None:
    # The accept-side razor at the plan level: dropping a tool_call whose
    # result remains would leave the result parentless in the OTLP rendering,
    # which is reject-adjacent and belongs to the corrupt corpus, not a dial.
    with pytest.raises(ValueError, match="orphan"):
        drop_step(_plan(), index=6)


def test_dropping_a_later_step_leaves_earlier_joins_alone() -> None:
    dialed = drop_step(_plan(), index=7)
    assert (dialed.joins[0].call_index, dialed.joins[0].result_index) == (1, 2)
