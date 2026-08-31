"""Provenance helpers: origin-tool attribution and the distinctive-token
matcher. The token bound is the precision knob (spec 2026-08-31); it is pinned
by test_provenance_matcher's junk-token rows, not by intuition."""
from __future__ import annotations

import re

from weir.graph import SessionGraph
from weir.schema.trace import ToolCallPayload

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
