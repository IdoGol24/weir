"""Graph builder (L12, R2.1-R2.5): CanonicalTrace -> SessionGraph.

Pure function - no I/O, no clock, no randomness (purity core, constitution
#2; enforced by the import-linter contract forbidding this module from
importing cli/adapters). join_confidence is resolved upstream by the adapter
(R1.4) - this layer only carries it through, mapping each JoinRecord's
source_refs to node indices.
"""

from __future__ import annotations

from weir.graph._types import Edge, GraphJoin, SessionGraph
from weir.schema.trace import CanonicalTrace


def build_session_graph(trace: CanonicalTrace) -> SessionGraph:
    nodes = trace.nodes
    next_edges = [Edge(src=i, dst=i + 1) for i in range(len(nodes) - 1)]

    # Multi-agent spawn edges (R2.1) are out of scope for this demo slice -
    # no scenario exercises spawning (multi-agent-spawn was dropped per the
    # demo-slice doc), and no adapter signal exists yet to derive it from.
    # Left empty rather than guessing at a heuristic with no fixture to
    # validate it against.
    spawns_edges: list[Edge] = []

    source_ref_to_index = {node.source_ref: i for i, node in enumerate(nodes)}
    joins: list[GraphJoin] = []
    for join in trace.joins:
        call_index = source_ref_to_index.get(join.tool_call_source_ref)
        result_index = source_ref_to_index.get(join.tool_result_source_ref)
        if call_index is None or result_index is None:
            # R1.3/G9: a join referencing a source_ref with no matching node
            # (corrupt/dangling input) degrades - dropped, never a crash.
            continue
        joins.append(
            GraphJoin(
                call_index=call_index,
                result_index=result_index,
                join_confidence=join.join_confidence,
            )
        )

    return SessionGraph(
        nodes=list(nodes),
        next_edges=next_edges,
        spawns_edges=spawns_edges,
        joins=joins,
    )
