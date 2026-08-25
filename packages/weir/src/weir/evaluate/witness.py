"""Minimal witness construction (R6.4): shortest path (fewest nodes) from a
source node to a sink node over the SessionGraph's forward edges, plus which
of that graph's joins actually lie on it (needed for the §7 clause-2 check:
every join on the witness path must be explicit/nested, never heuristic)."""

from __future__ import annotations

from collections import deque

from weir.graph import GraphJoin, SessionGraph
from weir.taint import reachable_from
from weir.taint.reachability import forward_adjacency


def shortest_witness_path(
    graph: SessionGraph, source_index: int, sink_index: int
) -> list[int] | None:
    if sink_index not in reachable_from(graph, source_index):
        return None
    adjacency = forward_adjacency(graph)
    parent: dict[int, int] = {}
    visited = {source_index}
    queue: deque[int] = deque([source_index])
    while queue:
        current = queue.popleft()
        if current == sink_index:
            break
        for neighbor in adjacency[current]:
            if neighbor not in visited:
                visited.add(neighbor)
                parent[neighbor] = current
                queue.append(neighbor)
    path = [sink_index]
    while path[-1] != source_index:
        path.append(parent[path[-1]])
    path.reverse()
    return path


def joins_on_path(graph: SessionGraph, path: list[int]) -> list[GraphJoin]:
    join_by_pair = {(j.call_index, j.result_index): j for j in graph.joins}
    return [
        join_by_pair[pair]
        for pair in zip(path, path[1:], strict=False)
        if pair in join_by_pair
    ]
