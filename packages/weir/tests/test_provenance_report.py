"""Task 9: a provenance finding's rendered block must be labelled as such,
while a structural finding's block stays exactly as it was (no label)."""

from __future__ import annotations

from weir.evaluate._types import Finding
from weir.graph import SessionGraph
from weir.report import finding_lines
from weir.rules_commons import RuleSpec
from weir.schema.trace import NodeKind, ToolCallPayload, TraceNode


def _node(index: int) -> TraceNode:
    return TraceNode(
        id=f"n{index}",
        kind=NodeKind.TOOL_CALL,
        timestamp="2026-01-01T00:00:00Z",
        actor="agent",
        source_ref=f"s{index}",
        payload=ToolCallPayload(tool_name="send_email", args={}),
    )


def _graph() -> SessionGraph:
    return SessionGraph(
        nodes=[_node(i) for i in range(7)],
        next_edges=[],
        spawns_edges=[],
        joins=[],
    )


def _rules() -> dict[str, RuleSpec]:
    return {
        "r": RuleSpec(
            id="r",
            version="1.0.0",
            stage="active",
            description="test rule",
            source_class="untrusted_origin",
            sink_tool_name="send_email",
            mode="provenance",
        )
    }


def _finding(kind: str) -> Finding:
    return Finding(
        rule_id="r",
        rule_version="1.0.0",
        source_node_index=2,
        sink_node_index=6,
        matched_value="DE89370400440532013000",
        witness_path=[2, 3, 4, 5, 6],
        is_verdict_grade=True,
        demotion_reasons=[],
        kind=kind,
    )


def test_provenance_finding_is_labelled() -> None:
    text = "\n".join(finding_lines(_finding("provenance"), _graph(), _rules()))
    assert "provenance" in text.lower()


def test_structural_finding_has_no_provenance_label() -> None:
    text = "\n".join(finding_lines(_finding("structural"), _graph(), _rules()))
    assert "provenance" not in text.lower()
