"""Compact per-finding text block for `weir scan` output (conversion gate
item 2). Pure over a single Finding plus the graph/rules it was drawn from -
never prints `matched_value` content (it can be a planted secret; only its
length is reported) so terminal/CI logs never leak scanned material."""

from __future__ import annotations

from weir.evaluate import Finding, joins_on_path
from weir.graph import SessionGraph
from weir.rules_commons import RuleSpec
from weir.schema.trace import ToolCallPayload


def finding_lines(
    finding: Finding, graph: SessionGraph, rules_by_id: dict[str, RuleSpec]
) -> list[str]:
    rule = rules_by_id[finding.rule_id]
    source_node = graph.nodes[finding.source_node_index]
    sink_node = graph.nodes[finding.sink_node_index]
    sink_tool = (
        sink_node.payload.tool_name if isinstance(sink_node.payload, ToolCallPayload) else "?"
    )
    tiers = list(
        dict.fromkeys(
            join.join_confidence.value
            for join in joins_on_path(graph, finding.witness_path)
        )
    )
    grade = (
        "yes"
        if finding.is_verdict_grade
        else f"no ({'; '.join(finding.demotion_reasons)})"
    )
    return [
        f"finding: {finding.rule_id}",
        f"  source: {rule.source_class} at node {finding.source_node_index}"
        f" ({source_node.kind.value})",
        f"  sink: {sink_tool} at node {finding.sink_node_index}",
        "  witness path: " + " -> ".join(f"n{i}" for i in finding.witness_path),
        "  join tiers crossed: " + (", ".join(tiers) if tiers else "none"),
        f"  verdict grade: {grade}",
        f"  matched value: {len(finding.matched_value)} chars",
    ]
