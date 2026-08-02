"""O(V+E) forward reachability over a SessionGraph's next/spawns/join edges
(R5.6): deterministic, total. Shared by verbatim matching and context-taint
propagation."""

from __future__ import annotations

from collections import deque

from weir.graph import SessionGraph


def forward_adjacency(graph: SessionGraph) -> dict[int, list[int]]:
    adjacency: dict[int, list[int]] = {i: [] for i in range(len(graph.nodes))}
    for edge in graph.next_edges:
        adjacency[edge.src].append(edge.dst)
    for edge in graph.spawns_edges:
        adjacency[edge.src].append(edge.dst)
    for join in graph.joins:
        adjacency[join.call_index].append(join.result_index)
    return adjacency


def reachable_from(graph: SessionGraph, start_index: int) -> set[int]:
    adjacency = forward_adjacency(graph)
    visited: set[int] = set()
    queue: deque[int] = deque([start_index])
    while queue:
        current = queue.popleft()
        for neighbor in adjacency[current]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited
