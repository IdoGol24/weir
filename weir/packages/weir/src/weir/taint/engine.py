"""Taint engine (L15, R5.1-R5.9): LabeledGraph + Catalog -> TaintedGraph.

Pure, O(V+E) reachability per source label (R5.6). `verbatim` is the demo's
only exercised mode (R5.8 default); context-mode propagation (R5.1) is
implemented too — R5.7 requires degraded nodes still carry context taint —
but no rule in this slice consumes it.

R5.9 is the demo, not a soundness footnote: a source value is verbatim-
eligible only if it clears its source class's catalog-declared floor
(weir.catalog.is_verbatim_eligible), checked BEFORE any sink-matching is
attempted. An over-matched but ineligible candidate (e.g. a bare numeral
picked up by the deliberately loose content-pattern) can therefore never
produce a verbatim finding, no matter what it coincidentally resembles at a
sink.

Base canon only (R5.3): uppercase, strip whitespace/hyphens; match mode is
substring containment (the base-canon default — canon v2's token-bounded N2
mode is deferred to M2). Degraded nodes (R5.7) are excluded as either end of
a verbatim match, but still included in context-taint reachability.
"""

from __future__ import annotations

from typing import cast

from weir.catalog import Catalog, is_verbatim_eligible
from weir.label import LabeledGraph
from weir.schema.trace import ToolCallPayload
from weir.taint._types import TaintedGraph, VerbatimMatch
from weir.taint.canon import canon
from weir.taint.reachability import reachable_from


def _flatten_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in cast("dict[str, object]", value).values():
            out.extend(_flatten_string_values(v))
        return out
    if isinstance(value, list):
        out = []
        for item in cast("list[object]", value):
            out.extend(_flatten_string_values(item))
        return out
    return []


def build_tainted_graph(labeled: LabeledGraph, catalog: Catalog) -> TaintedGraph:
    graph = labeled.graph
    sources_by_name = {s.name: s for s in catalog.sources}

    context_tainted: dict[int, list[int]] = {}
    verbatim_matches: list[VerbatimMatch] = []

    for source_label in labeled.source_labels:
        si = source_label.node_index
        source_node = graph.nodes[si]
        reachable = reachable_from(graph, si)
        # R5.1/R5.7: context taint is unconditional on eligibility/degraded.
        context_tainted[si] = sorted(reachable)

        if source_node.degraded:
            continue  # R5.7: degraded nodes excluded from verbatim matching

        source_spec = sources_by_name.get(source_label.source_class)
        if source_spec is None:
            continue
        if not is_verbatim_eligible(source_label.matched_value, source_spec):
            continue  # R5.9: the floor, checked before any sink matching

        canon_value = canon(source_label.matched_value)

        for sink_label in labeled.sink_labels:
            ti = sink_label.node_index
            if ti not in reachable:
                continue
            sink_node = graph.nodes[ti]
            if sink_node.degraded:
                continue  # R5.7
            if not isinstance(sink_node.payload, ToolCallPayload):
                continue
            candidates = _flatten_string_values(sink_node.payload.args)
            if any(canon_value in canon(candidate) for candidate in candidates):
                verbatim_matches.append(
                    VerbatimMatch(
                        source_node_index=si,
                        sink_node_index=ti,
                        source_class=source_label.source_class,
                        matched_value=source_label.matched_value,
                    )
                )

    return TaintedGraph(
        labeled=labeled,
        verbatim_matches=verbatim_matches,
        context_tainted=context_tainted,
    )
