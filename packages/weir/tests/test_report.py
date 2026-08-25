from pathlib import Path

import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate
from weir.gauge import GaugeReport, JoinQualitySplit, compute_gauge_report
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.report import find_forbidden_lexicon, mask, render_html_report
from weir.rules_commons import load_rules
from weir.schema.trace import decode_canonical_trace
from weir.taint import build_tainted_graph

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_PLANTED_IBAN = "DE89370400440532013000"


def _render_for(filename: str) -> str:
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    rules = load_rules()
    findings = evaluate(tainted, rules).findings
    gauge = compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework="langchain")
    return render_html_report(
        scenario_name=filename, graph=graph, gauge=gauge, findings=findings, rules=rules
    )


def test_red_report_shows_one_highlighted_finding_not_the_green_screen() -> None:
    html = _render_for("injection-exfil.json")
    assert "0 verdict-grade findings" not in html
    assert 'class="finding"' in html
    assert "#2" in html and "#6" in html
    assert "send_email" in html


def test_red_report_masks_the_planted_iban_never_shows_it_in_plaintext() -> None:
    html = _render_for("injection-exfil.json")
    assert _PLANTED_IBAN not in html
    assert mask(_PLANTED_IBAN) in html


def test_benign_report_shows_the_designed_green_screen() -> None:
    html = _render_for("injection-exfil-benign.json")
    assert "0 verdict-grade findings" in html
    assert "steps scanned" in html
    assert "rules evaluated" in html
    assert "argument capture" in html
    assert 'class="finding"' not in html


def test_red_report_includes_remediation_line() -> None:
    html = _render_for("injection-exfil-benign.degraded.json")
    assert "capture mechanisms vary by instrumentation package" in html


def test_reports_pass_the_g5_lexicon_lint() -> None:
    for filename in ("injection-exfil.json", "injection-exfil-benign.json"):
        html = _render_for(filename)
        assert find_forbidden_lexicon(html) == []


def test_report_is_a_self_contained_single_file() -> None:
    html = _render_for("injection-exfil.json")
    assert "<link" not in html
    assert "src=" not in html
    assert "http://" not in html
    assert "https://" not in html


def test_render_raises_if_a_forbidden_word_reaches_the_template() -> None:
    trace = decode_canonical_trace(
        (_FIXTURES_DIR / "injection-exfil-benign.json").read_bytes()
    )
    graph = build_session_graph(trace)
    rigged_gauge = GaugeReport(
        total_tool_call_nodes=1,
        inspectable_args_bp=10_000,
        degraded_bp=0,
        join_quality=JoinQualitySplit(
            explicit_bp=10_000, nested_bp=0, content_mined_bp=0, heuristic_bp=0
        ),
        evidentiary_coverage_bp=10_000,
        remediation_line="this trace is completely safe and secure",
    )
    with pytest.raises(ValueError, match="G5 lexicon violation"):
        render_html_report(
            scenario_name="rigged", graph=graph, gauge=rigged_gauge, findings=[], rules=[]
        )


def test_mask_truncates_long_values_and_short_values_differently() -> None:
    assert mask(_PLANTED_IBAN) == "DE89…3000"
    assert mask("short") == "sh…"


def test_report_rendering_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil.json"
    code = (
        "from pathlib import Path\n"
        "from weir.catalog import DEFAULT_CATALOG\n"
        "from weir.graph import build_session_graph\n"
        "from weir.label import label_graph\n"
        "from weir.taint import build_tainted_graph\n"
        "from weir.evaluate import evaluate\n"
        "from weir.gauge import compute_gauge_report\n"
        "from weir.report import render_html_report\n"
        "from weir.rules_commons import load_rules\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "graph = build_session_graph(trace)\n"
        "labeled = label_graph(graph, DEFAULT_CATALOG)\n"
        "tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)\n"
        "rules = load_rules()\n"
        "findings = evaluate(tainted, rules).findings\n"
        "gauge = compute_gauge_report(graph, DEFAULT_CATALOG, detected_framework='langchain')\n"
        "html = render_html_report(scenario_name='x', graph=graph, gauge=gauge,"
        " findings=findings, rules=rules)\n"
        "import sys; sys.stdout.write(html)\n"
    )
    assert_byte_identical_across_hash_seeds(code)
