"""SessionGraph data model - an internal pipeline artifact (§3.3), not a
seam schema, so it isn't schema-versioned/exported the way CanonicalTrace is
(the demo-slice doc's L3 note applies here too: minimal, inline)."""

from __future__ import annotations

import msgspec

from weir.schema.trace import JoinConfidence, TraceNode


class Edge(msgspec.Struct, frozen=True):
    src: int
    dst: int


class GraphJoin(msgspec.Struct, frozen=True):
    call_index: int
    result_index: int
    join_confidence: JoinConfidence


class SessionGraph(msgspec.Struct, frozen=True):
    nodes: list[TraceNode]
    next_edges: list[Edge]
    spawns_edges: list[Edge]
    joins: list[GraphJoin]
