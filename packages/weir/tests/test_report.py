from pathlib import Path

import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import ExposureFinding, evaluate
from weir.gauge import GaugeReport, JoinQualitySplit, compute_gauge_report
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.report import find_forbidden_lexicon, mask, render_html_report
from weir.report.text import exposure_lines
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


def _exposure_finding(**over) -> ExposureFinding:
    base = dict(rule_id="openai-api-key-in-telemetry", rule_version="1.0.0",
                severity="high", source_class="openai_api_key", span_ref="aa",
                span_name="crew.agent", location="attributes.acme.agent.llm",
                value_len=48, prefix="sk-proj-", last4="7Ri4",
                fingerprint="0123456789ab", is_verdict_grade=True)
    base.update(over)
    return ExposureFinding(**base)


def test_exposure_block_groups_by_fingerprint_and_names_the_locations() -> None:
    findings = [_exposure_finding(location=f"attributes.acme.agent.{k}")
                for k in ("llm", "executor")]
    lines = exposure_lines(findings)
    assert lines[0] == "1 credential (openai_api_key) in 2 locations across 1 span"
    assert "  crew.agent  attributes.acme.agent.llm  sk-proj-…7Ri4" in lines
    assert "  rule: openai-api-key-in-telemetry" in lines
    assert '  to demote: set "stage": "shadow" in openai-api-key-in-telemetry.json' in lines


def test_exposure_block_never_prints_a_whole_value() -> None:
    lines = "\n".join(exposure_lines([_exposure_finding()]))
    assert "sk-proj-…7Ri4" in lines
    assert "sk-proj-Qh7" not in lines


def test_triage_findings_group_with_their_demotion_reason() -> None:
    triage = _exposure_finding(
        source_class="credential_field", rule_id="credential-field-in-telemetry",
        prefix="password", last4=None, fingerprint=None, is_verdict_grade=False,
        demotion_reasons=["value shape not eligible for credential_field"])
    lines = exposure_lines([triage])
    assert lines[0] == "review queue: 1 credential-shaped match (credential_field)"
    assert "  value shape not eligible for credential_field" in lines


def test_no_findings_render_nothing() -> None:
    assert exposure_lines([]) == []


def test_two_active_rules_on_one_hit_count_as_one_location() -> None:
    # evaluate_exposure emits one finding per (hit x rule); two active rules
    # matching the same class at the same hit must still render as one
    # location, not one per rule.
    findings = [
        _exposure_finding(rule_id="openai-api-key-in-telemetry"),
        _exposure_finding(rule_id="openai-api-key-in-telemetry-v2"),
    ]
    lines = exposure_lines(findings)
    assert lines[0] == "1 credential (openai_api_key) in 1 location across 1 span"
    location_lines = [line for line in lines if line.startswith("  crew.agent")]
    assert len(location_lines) == 1


def test_last4_none_never_renders_the_word_none() -> None:
    # Task 4's floor: an eligible value under the minimum length carries no
    # last4. Falling back to prefix-only must not print "prefix…None".
    finding = _exposure_finding(last4=None)
    lines = exposure_lines([finding])
    assert "  crew.agent  attributes.acme.agent.llm  sk-proj-" in lines
    assert not any("None" in line for line in lines)


def test_control_chars_in_span_name_cannot_forge_a_report_line() -> None:
    # span_name, location and prefix all come off the wire (or a contributed
    # catalog's key-name match) unsanitised. A newline in any of them must
    # not fabricate an extra line that reads like weir's own verdict.
    forged_name = "crew.agent\n1 credential (nothing) in 0 locations across 0 spans"
    forged_location = "attributes.acme.agent.llm\x0b\x0c"
    forged_prefix = "sk-proj-\x85 "
    finding = _exposure_finding(
        span_name=forged_name, location=forged_location, prefix=forged_prefix)
    lines = exposure_lines([finding])
    # One finding: a group-header line and exactly one location line, plus
    # the two rule lines - never more because of embedded separators.
    assert len(lines) == 4
    rendered = "\n".join(lines)
    assert rendered.count("\n") == len(lines) - 1
    assert "1 credential (nothing) in 0 locations across 0 spans" not in lines[0]


def test_exposure_lines_location_order_is_hash_seed_independent() -> None:
    # The per-location dedupe must use dict.fromkeys (insertion order), not a
    # plain set - swapping it for one keeps every count correct but reorders
    # the location lines under a different PYTHONHASHSEED.
    code = (
        "from weir.evaluate import ExposureFinding\n"
        "from weir.report.text import exposure_lines\n"
        "findings = [\n"
        "    ExposureFinding(rule_id='r', rule_version='1.0.0', severity='high',"
        " source_class='openai_api_key', span_ref='aa', span_name='a',"
        " location='attributes.k1', value_len=48, prefix='sk-proj-', last4='7Ri4',"
        " fingerprint='0123456789ab', is_verdict_grade=True),\n"
        "    ExposureFinding(rule_id='r', rule_version='1.0.0', severity='high',"
        " source_class='openai_api_key', span_ref='bb', span_name='b',"
        " location='attributes.k2', value_len=48, prefix='sk-proj-', last4='8Ri5',"
        " fingerprint='0123456789ab', is_verdict_grade=True),\n"
        "]\n"
        "import sys; sys.stdout.write('\\n'.join(exposure_lines(findings)))\n"
    )
    assert_byte_identical_across_hash_seeds(code)
