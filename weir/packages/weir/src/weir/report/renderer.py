"""HTML reporter (L17, R7.1/R7.5/R7.6, G4/G5) - the visible payoff.

Single self-contained HTML file (inline CSS, no external assets, no JS
needed for this slice) so it opens anywhere. Masking is simple truncation
(G4 spirit) - no §8 witness commitments/salts/digests (M2/L22). No SARIF or
JSON evidence-pack output (L21/L22). Non-verdict-grade findings render in a
visually distinct review queue, never mixed with verdict-grade (R7.1) -
this slice's single rule never produces one, but the structure is real, not
a stub. The green state (R7.6) is a designed screen, not a blank page.
"""

from __future__ import annotations

import jinja2

from weir.evaluate import Finding
from weir.gauge import GaugeReport
from weir.graph import SessionGraph
from weir.report._template import REPORT_TEMPLATE
from weir.report.lexicon import find_forbidden_lexicon
from weir.rules_commons import RuleSpec
from weir.schema.trace import ToolCallPayload, TraceNode

_TEMPLATE = jinja2.Environment(
    autoescape=True, trim_blocks=True, lstrip_blocks=True
).from_string(REPORT_TEMPLATE)


def mask(value: str) -> str:
    """Simple truncation masking (G4 spirit) - not a §8 commitment scheme."""
    if len(value) <= 8:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]}"


def _node_summary(node: TraceNode) -> str:
    payload = node.payload
    if isinstance(payload, ToolCallPayload):
        return f"{node.kind.value}: {payload.tool_name}"
    text = payload.content
    shown = text if len(text) <= 80 else f"{text[:80]}…"
    return f"{node.kind.value}: {shown}"


def _finding_sentence(finding: Finding, graph: SessionGraph) -> str:
    sink_node = graph.nodes[finding.sink_node_index]
    sink_tool = (
        sink_node.payload.tool_name if isinstance(sink_node.payload, ToolCallPayload) else "?"
    )
    return (
        f"Untrusted content at step #{finding.source_node_index} flows verbatim to "
        f"{sink_tool} at step #{finding.sink_node_index}, carrying a sensitive value: "
        f"{mask(finding.matched_value)}."
    )


def render_html_report(
    *,
    scenario_name: str,
    graph: SessionGraph,
    gauge: GaugeReport,
    findings: list[Finding],
    rules: list[RuleSpec],
) -> str:
    rules_by_id = {rule.id: rule for rule in rules}
    verdict_grade = [f for f in findings if f.is_verdict_grade]
    review_queue = [f for f in findings if not f.is_verdict_grade]

    def _render(finding: Finding) -> dict[str, object]:
        rule = rules_by_id.get(finding.rule_id)
        return {
            "sentence": _finding_sentence(finding, graph),
            "rule_caption": f"rule: {finding.rule_id} v{rule.version}" if rule else None,
            "witness_steps": [
                {
                    "index": i,
                    "summary": _node_summary(graph.nodes[i]),
                    "highlighted": i in (finding.source_node_index, finding.sink_node_index),
                }
                for i in finding.witness_path
            ],
        }

    html = _TEMPLATE.render(
        scenario_name=scenario_name,
        coverage_pct=gauge.evidentiary_coverage_bp // 100,
        arg_capture_pct=gauge.inspectable_args_bp // 100,
        steps_scanned=len(graph.nodes),
        rules_evaluated=len(rules),
        remediation_line=gauge.remediation_line,
        verdict_grade_findings=[_render(f) for f in verdict_grade],
        review_queue=[_render(f) for f in review_queue],
    )

    violations = find_forbidden_lexicon(html)
    if violations:
        raise ValueError(f"G5 lexicon violation(s) in rendered report: {violations}")
    return html
