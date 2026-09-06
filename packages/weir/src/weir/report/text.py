"""Compact per-finding text block for `weir scan` output (conversion gate
item 2). Pure over a single Finding plus the graph/rules it was drawn from -
never prints `matched_value` content (it can be a planted secret; only its
length is reported) so terminal/CI logs never leak scanned material."""

from __future__ import annotations

from weir._text_safety import flatten_untrusted, plural
from weir.evaluate import ExposureFinding, Finding, joins_on_path
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
    lines = [
        f"finding: {finding.rule_id}",
        f"  source: {rule.source_class} at node {finding.source_node_index}"
        f" ({source_node.kind.value})",
        f"  sink: {sink_tool} at node {finding.sink_node_index}",
        "  witness path: " + " -> ".join(f"n{i}" for i in finding.witness_path),
        "  join tiers crossed: " + (", ".join(tiers) if tiers else "none"),
        f"  verdict grade: {grade}",
        f"  matched value: {len(finding.matched_value)} chars",
    ]
    if finding.kind == "provenance":
        lines.append("  evidence: provenance (untrusted origin)")
    return lines


def exposure_lines(findings: list[ExposureFinding]) -> list[str]:
    """The exposure section of `weir scan`, rendered above the flow findings.

    Verdict-grade findings group by fingerprint; triage findings group by
    class in the review queue with their demotion reason. `prefix...last4` is
    the display convention every credential UI uses; for a bundled class it
    can never fullmatch an eligibility pattern, but a contributed catalog
    makes no such promise, so the value itself is still never printed.
    """
    groups: dict[str | None, list[ExposureFinding]] = {}
    triage: list[ExposureFinding] = []
    for finding in findings:
        if finding.is_verdict_grade:
            groups.setdefault(finding.fingerprint, []).append(finding)
        else:
            triage.append(finding)

    lines: list[str] = []
    for group in groups.values():
        classes = ", ".join(dict.fromkeys(f.source_class for f in group))
        locations = len({(f.span_ref, f.location) for f in group})
        spans = len({f.span_ref for f in group})
        lines.append(
            f"1 credential ({classes}) in {plural(locations, 'location')} "
            f"across {plural(spans, 'span')}"
        )
        for span_ref, span_name, location, prefix, last4 in dict.fromkeys(
            (f.span_ref, f.span_name, f.location, f.prefix, f.last4) for f in group
        ):
            value = f"{prefix}…{last4}" if last4 else prefix
            # span_ref distinguishes rows when several spans share a name -
            # several identically-named agent spans is the leak shape this
            # feature exists for, not an edge case.
            ref = flatten_untrusted(span_ref)[:8]
            lines.append(
                f"  {flatten_untrusted(span_name)} ({ref})  {flatten_untrusted(location)}  "
                f"{flatten_untrusted(value)}"
            )
        for rule_id in dict.fromkeys(f.rule_id for f in group):
            lines.append(f"  rule: {rule_id}")
            lines.append(f'  to demote: set "stage": "shadow" in {rule_id}.json')

    if triage:
        classes = ", ".join(dict.fromkeys(f.source_class for f in triage))
        match_word = "match" if len(triage) == 1 else "matches"
        lines.append(
            f"review queue: {len(triage)} credential-shaped {match_word} ({classes})"
        )
        for finding in triage:
            lines.append(
                f"  {flatten_untrusted(finding.span_name)}  "
                f"{flatten_untrusted(finding.location)}  {flatten_untrusted(finding.prefix)}"
            )
            lines.extend(f"  {reason}" for reason in finding.demotion_reasons)
    return lines
