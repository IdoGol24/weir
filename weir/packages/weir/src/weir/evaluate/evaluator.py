"""Rule evaluator (L16, R6.1-R6.9 minimal core): TaintedGraph + rules ->
findings, each with a minimal witness path and the four-clause §7
verdict-grade check:

  1. produced in verbatim mode (B2)              - always true here; only
                                                     VerbatimMatch objects
                                                     reach this loop.
  2. every join on the witness path is
     explicit/nested, never heuristic (B6)
  3. no witness node is degraded:true (B1)
  4. the rule's stage is active (B4)

This is the inline four-clause check the demo-slice doc calls for. The full
R6.9 grade-authoring guard, R6.8's shadow-stage segregation beyond this
check, R6.7 event predicates, and a general rule-expression language are all
out of scope for this slice - our RuleSpec has no rule-authored expression
to interpret at all, so totality (G2: no recursion, no unbounded loops, no
eval) holds trivially: this evaluator iterates fixed-size inputs (rules x
verbatim matches) and does one bounded BFS per match.
"""

from __future__ import annotations

from weir.evaluate._types import EvaluationResult, Finding
from weir.evaluate.witness import joins_on_path, shortest_witness_path
from weir.rules_commons import RuleSpec
from weir.schema.trace import JoinConfidence, ToolCallPayload
from weir.taint import TaintedGraph

_VERDICT_GRADE_JOIN_CONFIDENCES = frozenset({JoinConfidence.EXPLICIT, JoinConfidence.NESTED})


def evaluate(tainted: TaintedGraph, rules: list[RuleSpec]) -> EvaluationResult:
    graph = tainted.labeled.graph
    rules_by_sink_and_class = {
        (rule.sink_tool_name, rule.source_class): rule for rule in rules if rule.mode == "verbatim"
    }

    findings: list[Finding] = []
    for match in tainted.verbatim_matches:
        sink_node = graph.nodes[match.sink_node_index]
        if not isinstance(sink_node.payload, ToolCallPayload):
            continue
        rule = rules_by_sink_and_class.get((sink_node.payload.tool_name, match.source_class))
        if rule is None:
            continue

        path = shortest_witness_path(graph, match.source_node_index, match.sink_node_index)
        if path is None:
            continue  # shouldn't happen: L15 only records matches within the reachable set

        no_degraded_witness_node = not any(graph.nodes[i].degraded for i in path)
        joins_ok = all(
            j.join_confidence in _VERDICT_GRADE_JOIN_CONFIDENCES
            for j in joins_on_path(graph, path)
        )
        rule_active = rule.stage == "active"
        is_verdict_grade = no_degraded_witness_node and joins_ok and rule_active

        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                source_node_index=match.source_node_index,
                sink_node_index=match.sink_node_index,
                matched_value=match.matched_value,
                witness_path=path,
                is_verdict_grade=is_verdict_grade,
            )
        )

    # Deterministic stable ordering, never insertion/iteration-dependent (G1).
    findings.sort(key=lambda f: (f.source_node_index, f.sink_node_index, f.rule_id))
    return EvaluationResult(findings=findings)
