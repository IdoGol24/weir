"""Provenance helpers: origin-tool attribution and the distinctive-token
matcher. The token bound is the precision knob (spec 2026-08-31); it is pinned
by test_provenance_matcher's junk-token rows, not by intuition."""
from __future__ import annotations

import re
from typing import cast

from weir.graph import SessionGraph
from weir.label import LabeledGraph
from weir.schema.trace import ToolCallPayload, ToolResultPayload
from weir.taint.reachability import reachable_from

_MIN_TOKEN_LEN = 8  # pinned by the junk-token fixture; raise if a real trace proves noisy
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]*")


def origin_tool_for(graph: SessionGraph, result_index: int) -> str | None:
    """The tool_name that produced this tool_result, via its join to the
    tool_call. None when unjoined/unattributable."""
    for join in graph.joins:
        if join.result_index == result_index:
            call = graph.nodes[join.call_index]
            if isinstance(call.payload, ToolCallPayload):
                return call.payload.tool_name
    return None


def distinctive_tokens(text: str) -> set[str]:
    """Whole tokens >= _MIN_TOKEN_LEN, excluding bare integers. Deterministic,
    no ML. The bare-numeric exclusion is a documented recall limitation."""
    out: set[str] = set()
    for m in _TOKEN.finditer(text):
        t = m.group(0)
        if len(t) >= _MIN_TOKEN_LEN and not t.isdigit():
            out.add(t)
    return out


def _flatten(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in cast("dict[str, object]", value).values():
            out.extend(_flatten(v))
        return out
    if isinstance(value, list):
        out = []
        for item in cast("list[object]", value):
            out.extend(_flatten(item))
        return out
    return []


def enumerate_flows(labeled: LabeledGraph) -> list[tuple[int, int, str | None, str]]:
    """Yield (result_index, sink_index, origin_tool, token) for every
    untrusted-shaped value reaching a labeled sink's args. Origin gate is
    applied by the caller (taint filters to declared tools; gauge does not).
    Deterministic: results in node order, tokens tried in sorted order."""
    graph = labeled.graph
    sink_indices = [s.node_index for s in labeled.sink_labels]
    flows: list[tuple[int, int, str | None, str]] = []
    for ri, node in enumerate(graph.nodes):
        if node.degraded or not isinstance(node.payload, ToolResultPayload):
            continue
        toks = distinctive_tokens(node.payload.content)
        if not toks:
            continue
        reachable = reachable_from(graph, ri)
        origin = origin_tool_for(graph, ri)
        for si in sink_indices:
            if si not in reachable:
                continue
            sink = graph.nodes[si]
            if sink.degraded or not isinstance(sink.payload, ToolCallPayload):
                continue
            argblob = " ".join(_flatten(sink.payload.args))
            for t in sorted(toks):
                if t in argblob:
                    flows.append((ri, si, origin, t))
                    break
    return flows
