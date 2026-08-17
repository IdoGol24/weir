"""Spec 7.3: gauge outputs per scenario x preset over the adapter path,
expectations DERIVED from the preset's declared clause set. This is the
calibration table in derived-test form - not the full R3.11 per-clause
conformance checker, which M4 does not build."""

import json

import pytest

from weir.adapters.otel import adapt_otlp
from weir.catalog import DEFAULT_CATALOG
from weir.gauge import GaugeReport, compute_gauge_report
from weir.graph import build_session_graph
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import ScenarioSpec, instantiate
from weir_tracegen.scenarios.dials import with_flat_linkage
from weir_tracegen.scenarios.presets import PRESETS, Clause, apply_preset

_SCENARIOS = ("injection-exfil", "injection-exfil-benign")
_FULL_BP = 10_000


def _gauge_for(plan: ScenarioSpec, preset_name: str) -> GaugeReport:
    data = json.dumps(render_otlp(plan, preset=preset_name)).encode()
    graph = build_session_graph(adapt_otlp(data).trace)
    return compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework=None)


@pytest.mark.parametrize("scenario", _SCENARIOS)
@pytest.mark.parametrize("preset_name", sorted(PRESETS))
def test_gauge_calibration_derives_from_the_clause_set(
    scenario: str, preset_name: str
) -> None:
    preset = PRESETS[preset_name]
    plan = apply_preset(instantiate(scenario, seed=1), preset_name)
    report = _gauge_for(plan, preset_name)

    if Clause.FULL_ARGUMENT_PAYLOADS in preset.clauses:
        assert report.inspectable_args_bp == _FULL_BP
        assert report.degraded_bp == 0
    else:
        assert report.inspectable_args_bp == 0
        assert report.degraded_bp == _FULL_BP

    if Clause.EXPLICIT_TOOL_CALL_LINKAGE in preset.clauses:
        assert report.join_quality.explicit_bp == _FULL_BP
    else:
        # Fill-absences-only: nesting is present in `partial`, so mined ids
        # are ignored and the fallback is all-nested (spec 7.3).
        assert report.join_quality.nested_bp == _FULL_BP
        assert report.join_quality.content_mined_bp == 0


def test_flat_linkage_calibration_reaches_the_content_mined_tier() -> None:
    plan = with_flat_linkage(instantiate("injection-exfil", seed=1))
    report = _gauge_for(plan, "full")
    assert report.join_quality.content_mined_bp == _FULL_BP
    # Content-mined linkage is NOT verdict-eligible, so coverage excludes it.
    assert report.evidentiary_coverage_bp == 0
