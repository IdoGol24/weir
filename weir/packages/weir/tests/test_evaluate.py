from pathlib import Path

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate, shortest_witness_path
from weir.graph import Edge, GraphJoin, SessionGraph, build_session_graph
from weir.label import LabeledGraph, label_graph
from weir.rules_commons import RuleSpec, load_rules
from weir.schema.trace import (
    JoinConfidence,
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceNode,
    UserInputPayload,
    decode_canonical_trace,
)
from weir.taint import TaintedGraph, VerbatimMatch, build_tainted_graph

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_PLANTED_IBAN = "DE89370400440532013000"


def _end_to_end_findings(filename: str):  # noqa: ANN201
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    return evaluate(tainted, load_rules()).findings


def test_red_fixture_end_to_end_produces_one_verdict_grade_finding() -> None:
    (finding,) = _end_to_end_findings("injection-exfil.json")
    assert finding.rule_id == "injection-exfil-to-outbound-sink"
    assert finding.source_node_index == 2
    assert finding.sink_node_index == 6
    assert finding.matched_value == _PLANTED_IBAN
    assert finding.witness_path == [2, 3, 4, 5, 6]
    assert finding.is_verdict_grade is True


def test_benign_fixture_end_to_end_produces_zero_findings() -> None:
    assert _end_to_end_findings("injection-exfil-benign.json") == []


def _node(index: int, kind: NodeKind, payload: object, *, degraded: bool = False) -> TraceNode:
    return TraceNode(
        id=f"n{index}",
        kind=kind,
        timestamp=f"2026-01-01T00:00:0{index}Z",
        actor="agent",
        source_ref=f"s{index}",
        payload=payload,
        degraded=degraded,
    )


def _synthetic_tainted(
    *,
    next_edges: list[Edge],
    joins: list[GraphJoin],
    node_degraded: dict[int, bool] | None = None,
) -> TaintedGraph:
    degraded_by_index = node_degraded or {}
    nodes = [
        _node(
            0,
            NodeKind.USER_INPUT,
            UserInputPayload(content="start"),
            degraded=degraded_by_index.get(0, False),
        ),
        _node(
            1,
            NodeKind.TOOL_RESULT,
            ToolResultPayload(content="middle"),
            degraded=degraded_by_index.get(1, False),
        ),
        _node(
            2,
            NodeKind.TOOL_CALL,
            ToolCallPayload(tool_name="send_email", args={"to": "a@b.com"}),
            degraded=degraded_by_index.get(2, False),
        ),
    ]
    graph = SessionGraph(nodes=nodes, next_edges=next_edges, spawns_edges=[], joins=joins)
    labeled = LabeledGraph(graph=graph, source_labels=[], sink_labels=[])
    match = VerbatimMatch(
        source_node_index=0,
        sink_node_index=2,
        source_class="financial_account_identifier",
        matched_value=_PLANTED_IBAN,
    )
    return TaintedGraph(labeled=labeled, verbatim_matches=[match], context_tainted={0: [1, 2]})


_ACTIVE_RULE = RuleSpec(
    id="test-rule",
    version="1.0.0",
    stage="active",
    description="test",
    source_class="financial_account_identifier",
    sink_tool_name="send_email",
    mode="verbatim",
)


def test_shortest_witness_path_prefers_the_shorter_route() -> None:
    nodes = [
        _node(0, NodeKind.USER_INPUT, UserInputPayload(content="a")),
        _node(1, NodeKind.USER_INPUT, UserInputPayload(content="b")),
        _node(2, NodeKind.USER_INPUT, UserInputPayload(content="c")),
        _node(3, NodeKind.USER_INPUT, UserInputPayload(content="d")),
    ]
    graph = SessionGraph(
        nodes=nodes,
        next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2), Edge(src=2, dst=3)],
        spawns_edges=[],
        joins=[GraphJoin(call_index=0, result_index=3, join_confidence=JoinConfidence.EXPLICIT)],
    )
    assert shortest_witness_path(graph, 0, 3) == [0, 3]


def test_positive_control_finding_is_verdict_grade() -> None:
    tainted = _synthetic_tainted(next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2)], joins=[])
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.is_verdict_grade is True


def test_finding_demoted_when_witness_path_crosses_a_heuristic_join() -> None:
    tainted = _synthetic_tainted(
        next_edges=[Edge(src=1, dst=2)],
        joins=[GraphJoin(call_index=0, result_index=1, join_confidence=JoinConfidence.HEURISTIC)],
    )
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.witness_path == [0, 1, 2]
    assert finding.is_verdict_grade is False


def test_finding_not_demoted_when_witness_path_crosses_an_explicit_join() -> None:
    tainted = _synthetic_tainted(
        next_edges=[Edge(src=1, dst=2)],
        joins=[GraphJoin(call_index=0, result_index=1, join_confidence=JoinConfidence.EXPLICIT)],
    )
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.is_verdict_grade is True


def test_finding_demoted_when_an_intermediate_witness_node_is_degraded() -> None:
    tainted = _synthetic_tainted(
        next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2)],
        joins=[],
        node_degraded={1: True},
    )
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.witness_path == [0, 1, 2]
    assert finding.is_verdict_grade is False


def test_finding_demoted_when_rule_stage_is_shadow() -> None:
    tainted = _synthetic_tainted(next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2)], joins=[])
    shadow_rule = RuleSpec(
        id="test-rule",
        version="1.0.0",
        stage="shadow",
        description="test",
        source_class="financial_account_identifier",
        sink_tool_name="send_email",
        mode="verbatim",
    )
    (finding,) = evaluate(tainted, [shadow_rule]).findings
    assert finding.is_verdict_grade is False


def test_content_mined_edge_demotes_with_stated_reason() -> None:
    tainted = _synthetic_tainted(
        next_edges=[Edge(src=1, dst=2)],
        joins=[
            GraphJoin(
                call_index=0, result_index=1,
                join_confidence=JoinConfidence.CONTENT_MINED,
            )
        ],
    )
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.is_verdict_grade is False
    assert any("content_mined" in r for r in finding.demotion_reasons)


def test_verdict_grade_finding_has_no_demotion_reasons() -> None:
    tainted = _synthetic_tainted(
        next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2)], joins=[]
    )
    (finding,) = evaluate(tainted, [_ACTIVE_RULE]).findings
    assert finding.is_verdict_grade is True
    assert finding.demotion_reasons == []


def test_evaluate_output_is_deterministically_ordered() -> None:
    first = _end_to_end_findings("injection-exfil.json")
    second = _end_to_end_findings("injection-exfil.json")
    assert [f.rule_id for f in first] == [f.rule_id for f in second]


def test_evaluate_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil.json"
    code = (
        "from pathlib import Path\n"
        "from weir.catalog import DEFAULT_CATALOG\n"
        "from weir.graph import build_session_graph\n"
        "from weir.label import label_graph\n"
        "from weir.taint import build_tainted_graph\n"
        "from weir.evaluate import evaluate\n"
        "from weir.rules_commons import load_rules\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)\n"
        "tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)\n"
        "result = evaluate(tainted, load_rules())\n"
        "print([(f.rule_id, f.witness_path, f.is_verdict_grade) for f in result.findings])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
