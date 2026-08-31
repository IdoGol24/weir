"""Provenance gauge lines (spec 2026-08-31): the triage/config signal lives in
gauge, not scan. Reports observed untrusted-shaped -> provenance-sink flows
grouped by origin tool, plus attribution coverage. Deterministic."""

from __future__ import annotations

from collections import Counter

from weir.label import LabeledGraph
from weir.schema.trace import ToolCallPayload
from weir.taint.provenance import enumerate_flows


def provenance_gauge_lines(
    labeled: LabeledGraph, *, provenance_sink_names: set[str], untrusted_sources: list[str]
) -> list[str]:
    if not provenance_sink_names:
        if untrusted_sources:
            return [
                "provenance: untrusted_sources declared but no provenance rule "
                "(declare a provenance rule for a must-never sink, or the boundary does nothing)"
            ]
        return []
    graph = labeled.graph
    pairs: Counter[str] = Counter()
    attributable = 0
    total = 0
    for _ri, si, origin, _token in enumerate_flows(labeled):
        payload = graph.nodes[si].payload
        if not isinstance(payload, ToolCallPayload):
            continue
        if payload.tool_name not in provenance_sink_names:
            continue
        total += 1
        pairs[f"{origin or 'unknown'}->{payload.tool_name}"] += 1
        if origin is not None:
            attributable += 1
    if total == 0:
        return []
    grouped = ", ".join(
        f"{lbl} {n}" for lbl, n in sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    lines: list[str] = []
    if untrusted_sources:
        lines.append(f"provenance: YES - {total} flow(s) evaluated ({grouped})")
    else:
        lines.append(
            f"provenance: NO - no trust boundary declared; {total} flow(s) "
            f"observed ({grouped}); declare untrusted_sources to evaluate"
        )
    lines.append(
        f"  {attributable} of {total} tool_result->sink flows attributable to an origin tool"
    )
    return lines
