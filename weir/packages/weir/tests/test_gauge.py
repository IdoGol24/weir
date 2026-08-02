from pathlib import Path

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.gauge import compute_gauge_report
from weir.graph import build_session_graph
from weir.schema.trace import decode_canonical_trace

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"


def _gauge_for(filename: str, *, detected_framework: str | None = "langchain"):  # noqa: ANN201
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    graph = build_session_graph(trace)
    return compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework=detected_framework)


def test_full_capture_red_fixture_reports_full_coverage() -> None:
    report = _gauge_for("injection-exfil.json")
    assert report.total_tool_call_nodes == 2
    assert report.inspectable_args_bp == 10_000
    assert report.degraded_bp == 0
    assert report.evidentiary_coverage_bp == 10_000


def test_full_capture_benign_fixture_reports_full_coverage() -> None:
    report = _gauge_for("injection-exfil-benign.json")
    assert report.inspectable_args_bp == 10_000
    assert report.evidentiary_coverage_bp == 10_000


def test_degraded_fixture_reports_low_coverage_and_a_real_remediation_line() -> None:
    report = _gauge_for("injection-exfil-benign.degraded.json")
    assert report.total_tool_call_nodes == 2
    assert report.inspectable_args_bp == 5_000  # 1 of 2 tool_call nodes has captured args
    assert report.degraded_bp == 5_000
    assert report.evidentiary_coverage_bp == 5_000
    assert report.remediation_line is not None
    assert report.remediation_line.strip() != ""
    assert "langchain" in report.remediation_line.lower()


def test_join_quality_is_fully_explicit_in_this_demos_fixtures() -> None:
    report = _gauge_for("injection-exfil.json")
    assert report.join_quality.explicit_bp == 10_000
    assert report.join_quality.nested_bp == 0
    assert report.join_quality.heuristic_bp == 0


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
