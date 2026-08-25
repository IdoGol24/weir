"""TaintedGraph data model - an internal pipeline artifact (§3.3), minimal
and inline for this demo slice, same treatment as SessionGraph (L12) and
LabeledGraph (L14)."""

from __future__ import annotations

import msgspec

from weir.label import LabeledGraph


class VerbatimMatch(msgspec.Struct, frozen=True):
    source_node_index: int
    sink_node_index: int
    source_class: str
    matched_value: str


class TaintedGraph(msgspec.Struct, frozen=True):
    labeled: LabeledGraph
    verbatim_matches: list[VerbatimMatch]
    # R5.1/R5.7: source_node_index -> sorted reachable node indices,
    # unconditional on R5.9 eligibility or degraded status.
    context_tainted: dict[int, list[int]]
