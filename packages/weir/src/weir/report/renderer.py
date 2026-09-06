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

from collections.abc import Sequence

import jinja2
from markupsafe import escape

from weir.evaluate import ExposureFinding, Finding
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
    # Masked for EVERY node, not only nodes on a flow path: an exposure hit
    # has no path, and an 80-character raw preview of a chat span would print
    # a key sitting inside gen_ai.input.messages. Orientation, not content.
    return f"{node.kind.value}: {mask(payload.content)} ({len(payload.content)} chars)"


def _masked_value(prefix: str, last4: str | None) -> str:
    """Mirrors the ternary in report/text.py's exposure_lines: a short
    eligible value has no last4, and printing it unguarded renders the
    literal string "None"."""
    return f"{prefix}…{last4}" if last4 else prefix


def _finding_sentence(finding: Finding, graph: SessionGraph, untrusted: list[str]) -> str:
    sink_node = graph.nodes[finding.sink_node_index]
    sink_tool = (
        sink_node.payload.tool_name if isinstance(sink_node.payload, ToolCallPayload) else "?"
    )
    masked_value = mask(finding.matched_value)
    untrusted.append(sink_tool)
    untrusted.append(masked_value)
    return (
        f"Untrusted content at step #{finding.source_node_index} flows verbatim to "
        f"{sink_tool} at step #{finding.sink_node_index}, carrying a sensitive value: "
        f"{masked_value}."
    )


def render_html_report(
    *,
    scenario_name: str,
    graph: SessionGraph,
    gauge: GaugeReport,
    findings: list[Finding],
    rules: list[RuleSpec],
    ladder_lines: Sequence[str] = (),
    exposure_findings: Sequence[ExposureFinding] = (),
) -> str:
    rules_by_id = {rule.id: rule for rule in rules}
    verdict_grade = [f for f in findings if f.is_verdict_grade]
    review_queue = [f for f in findings if not f.is_verdict_grade]

    # G5 lints weir's OWN prose. Span names, attribute key paths, tool
    # names and masked values come off the wire (or a contributed catalog),
    # so a span in a service called "secure-store" must not be able to
    # abort the report - and abort it before the finding has even been
    # printed.
    untrusted_values: list[str] = []

    def _render(finding: Finding) -> dict[str, object]:
        rule = rules_by_id.get(finding.rule_id)
        witness_steps: list[dict[str, object]] = []
        for i in finding.witness_path:
            summary = _node_summary(graph.nodes[i])
            untrusted_values.append(summary)
            witness_steps.append({
                "index": i,
                "summary": summary,
                "highlighted": i in (finding.source_node_index, finding.sink_node_index),
            })
        return {
            "sentence": _finding_sentence(finding, graph, untrusted_values),
            "rule_caption": f"rule: {finding.rule_id} v{rule.version}" if rule else None,
            "witness_steps": witness_steps,
        }

    exposure_verdict: list[dict[str, object]] = []
    for f in exposure_findings:
        if not f.is_verdict_grade:
            continue
        masked_value = _masked_value(f.prefix, f.last4)
        untrusted_values.extend([f.source_class, f.location, f.span_name, masked_value])
        exposure_verdict.append({
            "headline": f"{f.source_class} present in {f.location} of span "
                        f"{f.span_name} ({masked_value})",
            "rule_caption": f"rule: {f.rule_id} v{f.rule_version} - "
                            f'to demote: set "stage": "shadow" in {f.rule_id}.json',
        })

    exposure_triage: list[dict[str, object]] = []
    for f in exposure_findings:
        if f.is_verdict_grade:
            continue
        untrusted_values.extend([f.source_class, f.location, f.span_name, f.prefix])
        exposure_triage.append({
            "headline": f"{f.source_class} shape in {f.location} of span "
                        f"{f.span_name} ({f.prefix})",
            "reasons": list(f.demotion_reasons),
        })

    html = _TEMPLATE.render(
        scenario_name=scenario_name,
        coverage_pct=gauge.evidentiary_coverage_bp // 100,
        arg_capture_pct=gauge.inspectable_args_bp // 100,
        steps_scanned=len(graph.nodes),
        rules_evaluated=len(rules),
        remediation_line=gauge.remediation_line,
        ladder_lines=list(ladder_lines),
        verdict_grade_findings=[_render(f) for f in verdict_grade],
        review_queue=[_render(f) for f in review_queue],
        exposure_verdict=exposure_verdict,
        exposure_triage=exposure_triage,
    )

    scrubbed = html
    for value in untrusted_values:
        if not value:
            continue
        for form in (value, escape(value)):
            scrubbed = scrubbed.replace(str(form), " ")

    violations = find_forbidden_lexicon(scrubbed)
    if violations:
        raise ValueError(f"G5 lexicon violation(s) in rendered report: {violations}")
    return html
