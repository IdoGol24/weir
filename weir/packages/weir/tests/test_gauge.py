from pathlib import Path

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.gauge import compute_gauge_report
from weir.graph import Edge, GraphJoin, SessionGraph, build_session_graph
from weir.schema.trace import (
    JoinConfidence,
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceNode,
    decode_canonical_trace,
)

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"


def _gauge_for(filename: str, *, detected_framework: str | None = "langchain"):  # noqa: ANN201
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    graph = build_session_graph(trace)
    return compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework=detected_framework)


def test_full_capture_red_fixture_reports_full_coverage() -> None:
    report = _gauge_for("injection-exfil.json")
    assert report.total_tool_call_nodes == 3
    assert report.inspectable_args_bp == 10_000
    assert report.degraded_bp == 0
    assert report.evidentiary_coverage_bp == 10_000


def test_full_capture_fixture_shows_no_remediation_even_with_known_framework() -> None:
    # A remediation line is remediation, not commentary - showing "arguments
    # not captured" advice on a fully-captured trace would be misleading.
    report = _gauge_for("injection-exfil.json", detected_framework="langchain")
    assert report.remediation_line is None


def test_full_capture_benign_fixture_reports_full_coverage() -> None:
    report = _gauge_for("injection-exfil-benign.json")
    assert report.inspectable_args_bp == 10_000
    assert report.evidentiary_coverage_bp == 10_000


def test_degraded_fixture_reports_low_coverage_and_a_real_remediation_line() -> None:
    report = _gauge_for("injection-exfil-benign.degraded.json")
    assert report.total_tool_call_nodes == 3
    assert report.inspectable_args_bp == 3_333  # 1 of 3 tool_call nodes has captured args
    assert report.degraded_bp == 6_666
    assert report.evidentiary_coverage_bp == 3_333
    assert report.remediation_line is not None
    assert report.remediation_line.strip() != ""
    assert "enable content capture" in report.remediation_line.lower()


def test_join_quality_is_fully_explicit_in_this_demos_fixtures() -> None:
    report = _gauge_for("injection-exfil.json")
    assert report.join_quality.explicit_bp == 10_000
    assert report.join_quality.nested_bp == 0
    assert report.join_quality.heuristic_bp == 0


def _node(index: int, kind: NodeKind, payload: object) -> TraceNode:
    return TraceNode(
        id=f"n{index}",
        kind=kind,
        timestamp=f"2026-01-01T00:00:0{index}Z",
        actor="agent",
        source_ref=f"s{index}",
        payload=payload,
        degraded=False,
    )


def test_join_quality_split_reports_content_mined_and_sums_to_full() -> None:
    # One of two joins is content-mined - derive the expected split from that
    # same 1-of-2 ratio rather than restating a literal.
    nodes = [
        _node(0, NodeKind.TOOL_CALL, ToolCallPayload(tool_name="send_email", args={"to": "a"})),
        _node(1, NodeKind.TOOL_RESULT, ToolResultPayload(content="ok")),
        _node(2, NodeKind.TOOL_CALL, ToolCallPayload(tool_name="send_email", args={"to": "b"})),
        _node(3, NodeKind.TOOL_RESULT, ToolResultPayload(content="ok")),
    ]
    graph = SessionGraph(
        nodes=nodes,
        next_edges=[Edge(src=0, dst=1), Edge(src=1, dst=2), Edge(src=2, dst=3)],
        spawns_edges=[],
        joins=[
            GraphJoin(call_index=0, result_index=1, join_confidence=JoinConfidence.EXPLICIT),
            GraphJoin(call_index=2, result_index=3, join_confidence=JoinConfidence.CONTENT_MINED),
        ],
    )
    report = compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework=None)
    jq = report.join_quality
    assert jq.content_mined_bp == 10_000 // 2  # 1 of 2 joins
    assert jq.explicit_bp + jq.nested_bp + jq.content_mined_bp + jq.heuristic_bp == 10_000


def test_remediation_line_absent_when_framework_is_unknown() -> None:
    report = _gauge_for("injection-exfil.json", detected_framework="some-unregistered-framework")
    assert report.remediation_line is None


def test_remediation_line_absent_when_framework_not_detected() -> None:
    report = _gauge_for("injection-exfil.json", detected_framework=None)
    assert report.remediation_line is None


def test_gauge_report_fields_are_all_ints_no_floats() -> None:
    report = _gauge_for("injection-exfil-benign.degraded.json")
    assert isinstance(report.inspectable_args_bp, int)
    assert isinstance(report.degraded_bp, int)
    assert isinstance(report.evidentiary_coverage_bp, int)
    assert isinstance(report.join_quality.explicit_bp, int)


def test_gauge_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil-benign.degraded.json"
    code = (
        "from pathlib import Path\n"
        "from weir.catalog import DEFAULT_CATALOG\n"
        "from weir.graph import build_session_graph\n"
        "from weir.gauge import compute_gauge_report\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "graph = build_session_graph(trace)\n"
        "report = compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework='langchain')\n"
        "print(report.evidentiary_coverage_bp, report.degraded_bp, report.remediation_line)\n"
    )
    assert_byte_identical_across_hash_seeds(code)
