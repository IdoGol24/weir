"""LabeledGraph data model — an internal pipeline artifact (§3.3), minimal
and inline for this demo slice, same treatment as SessionGraph (L12)."""

from __future__ import annotations

import msgspec

from weir.graph import SessionGraph


class SourceLabel(msgspec.Struct, frozen=True):
    node_index: int
    source_class: str
    matched_value: str


class SinkLabel(msgspec.Struct, frozen=True):
    node_index: int
    tool_name: str
    true_destination: str | None


class LabeledGraph(msgspec.Struct, frozen=True):
    graph: SessionGraph
    source_labels: list[SourceLabel]
    sink_labels: list[SinkLabel]
