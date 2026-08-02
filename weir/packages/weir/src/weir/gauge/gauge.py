"""Gauge (L13, R3.1-R3.5 + R3.10): SessionGraph + Catalog -> GaugeReport.

Standalone (R3.5): needs no rules and no catalog customization — only the
bundled default catalog's remediation table (R3.4). Pure, over the graph
built at L12; doesn't touch the labeler/taint/rule layers at all.

R3.6-R3.9 threshold gates, CTA block, Fidelity Attestation seam, per-path
breakdown, and R3.11 profile conformance are deferred per the demo-slice
doc's L13 notes — this is the coverage-number opening beat only.
"""

from __future__ import annotations

from weir.catalog import Catalog
from weir.gauge._types import GaugeReport, JoinQualitySplit
from weir.graph import SessionGraph
from weir.schema.trace import JoinConfidence, NodeKind, ToolCallPayload

_BASIS_POINTS_SCALE = 10_000


def _basis_points(count: int, total: int) -> int:
    return 0 if total == 0 else (count * _BASIS_POINTS_SCALE) // total


def _has_inspectable_args(graph: SessionGraph, index: int) -> bool:
    payload = graph.nodes[index].payload
    return isinstance(payload, ToolCallPayload) and len(payload.args) > 0


def compute_gauge_report(
    graph: SessionGraph, catalog: Catalog, *, detected_framework: str | None
) -> GaugeReport:
    tool_call_indices = [i for i, n in enumerate(graph.nodes) if n.kind == NodeKind.TOOL_CALL]
    total = len(tool_call_indices)

    inspectable_count = sum(1 for i in tool_call_indices if _has_inspectable_args(graph, i))
    degraded_count = sum(1 for i in tool_call_indices if graph.nodes[i].degraded)

    join_confidence_by_call_index = {j.call_index: j.join_confidence for j in graph.joins}

    def is_verdict_eligible(i: int) -> bool:
        # R3.10: inspectable args ∧ explicit-or-nested join ∧ not degraded.
        confidence = join_confidence_by_call_index.get(i)
        return (
            _has_inspectable_args(graph, i)
            and confidence in (JoinConfidence.EXPLICIT, JoinConfidence.NESTED)
            and not graph.nodes[i].degraded
        )

    eligible_count = sum(1 for i in tool_call_indices if is_verdict_eligible(i))

    confidences = [j.join_confidence for j in graph.joins]
    join_total = len(confidences)
    join_quality = JoinQualitySplit(
        explicit_bp=_basis_points(
            sum(1 for c in confidences if c == JoinConfidence.EXPLICIT), join_total
        ),
        nested_bp=_basis_points(
            sum(1 for c in confidences if c == JoinConfidence.NESTED), join_total
        ),
        heuristic_bp=_basis_points(
            sum(1 for c in confidences if c == JoinConfidence.HEURISTIC), join_total
        ),
    )

    remediation_line = (
        catalog.remediations.get(detected_framework) if detected_framework else None
    )

    return GaugeReport(
        total_tool_call_nodes=total,
        inspectable_args_bp=_basis_points(inspectable_count, total),
        degraded_bp=_basis_points(degraded_count, total),
        join_quality=join_quality,
        evidentiary_coverage_bp=_basis_points(eligible_count, total),
        remediation_line=remediation_line,
    )
