"""End to end: an OTLP export with a key in a vendor attribute fails the
build, and --fail-on gates it by the rule's severity."""

import json
from pathlib import Path

import msgspec
import pytest
from click.testing import CliRunner

import weir.cli.main as cli
from weir.cli.main import main
from weir.rules_commons import load_rules

_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"
_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"


def _export(value: str) -> str:
    return json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{
        "spanId": "aa" * 8, "name": "crew.agent",
        "attributes": [{"key": "acme.agent.llm", "value": {"stringValue": value}}],
    }]}]}]})


def _run(args, files=None):
    runner = CliRunner()
    with runner.isolated_filesystem():
        for name, body in (files or {}).items():
            Path(name).write_text(body, encoding="utf-8")
        return runner.invoke(main, args)


def test_scan_exits_one_on_a_key_in_an_attribute() -> None:
    result = _run(["scan", "export.json"], {"export.json": _export(f"LLM(api_key='{_KEY}')")})
    assert result.exit_code == 1
    assert "1 credential (openai_api_key) in 1 location across 1 span" in result.output
    assert _KEY not in result.output
    assert "sk-proj-…7Ri4" in result.output


def test_the_exposure_section_renders_above_the_flow_line() -> None:
    result = _run(["scan", "export.json"], {"export.json": _export(_KEY)})
    assert result.output.index("1 credential") < result.output.index("verdict-grade")


def test_an_exposure_only_export_never_reads_as_a_bare_all_clear() -> None:
    # A credential finding above and an unqualified "0 verdict-grade
    # findings" below would contradict the exit code - one screen, two
    # opposite claims.
    result = _run(["scan", "export.json"], {"export.json": _export(_KEY)})
    assert result.exit_code == 1
    assert "0 verdict-grade findings" not in result.output
    assert "0 verdict-grade flow findings" in result.output

    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(_export(_KEY), encoding="utf-8")
        html_result = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        html = Path("r.html").read_text(encoding="utf-8")
    assert html_result.exit_code == 1
    assert 'class="green-screen"' not in html


def test_a_placeholder_key_exits_zero_and_lands_in_triage() -> None:
    body = _export("api_key='sk-proj-REDACTEDREDACTEDREDACTEDREDACTED'")
    result = _run(["scan", "export.json"], {"export.json": body})
    assert result.exit_code == 0
    assert "review queue" in result.output
    assert "not eligible" in result.output


def test_fail_on_low_still_fails_on_a_high_severity_rule() -> None:
    result = _run(["scan", "export.json", "--fail-on", "low"], {"export.json": _export(_KEY)})
    assert result.exit_code == 1


def test_gauge_prints_the_exposure_block() -> None:
    result = _run(["gauge", "export.json"], {"export.json": _export(_KEY)})
    assert result.exit_code == 0
    assert "exposure scan: 1 spans, 1 strings" in result.output
    assert "credentials: 1 distinct (openai_api_key)" in result.output


def test_gauge_on_native_input_says_not_applicable() -> None:
    result = _run(["gauge", str(_FIXTURES_DIR / "injection-exfil.json")])
    assert result.exit_code == 0
    assert "exposure scan: not applicable - native input carries no attributes" in result.output


def test_scan_on_native_input_prints_no_exposure_section() -> None:
    # The hero SVG is generated from exactly this command; an unconditional
    # exposure line here would silently restyle the README's animation.
    result = _run(["scan", str(_FIXTURES_DIR / "injection-exfil.json")])
    assert "exposure" not in result.output
    assert result.output.startswith("1 verdict-grade finding(s)")


def test_a_non_ascii_span_name_renders_without_raising() -> None:
    # span_name and location come off the wire filtered only for
    # non-printable characters, so anything printable non-ASCII - here a
    # Japanese span name - has to reach stdout without a UnicodeEncodeError.
    body = json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{
        "spanId": "aa" * 8, "name": "crew.日本",
        "attributes": [{"key": "acme.agent.llm", "value": {"stringValue": _KEY}}],
    }]}]}]})
    result = _run(["scan", "export.json"], {"export.json": body})
    assert result.exit_code == 1
    assert "crew.日本" in result.output


def test_the_html_report_carries_the_exposure_section_masked() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(_export(_KEY), encoding="utf-8")
        result = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        html = Path("r.html").read_text(encoding="utf-8")
    assert result.exit_code == 1
    assert _KEY not in html
    assert "sk-proj-…7Ri4" in html
    assert "attributes.acme.agent.llm" in html


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        ("high", "high", True), ("high", "medium", True), ("high", "low", True),
        ("medium", "high", False), ("medium", "medium", True), ("medium", "low", True),
        ("low", "high", False), ("low", "medium", False), ("low", "low", True),
    ],
)
def test_severity_gate(severity: str, threshold: str, expected: bool) -> None:
    assert cli._severity_at_or_above(severity, threshold) is expected


def test_a_finding_below_the_threshold_is_reported_but_does_not_fail_the_build(
    monkeypatch,
) -> None:
    # Every bundled rule is severity "high", so this is the only way to
    # exercise the gate rejecting a finding. The finding must still appear -
    # --fail-on changes the exit code, never what weir tells you it saw.
    low = [
        r if r.mode != "exposure" or r.source_class != "openai_api_key"
        else msgspec.structs.replace(r, severity="low")
        for r in load_rules()
    ]
    monkeypatch.setattr(cli, "load_rules", lambda: low)
    result = _run(["scan", "export.json", "--fail-on", "high"], {"export.json": _export(_KEY)})
    assert result.exit_code == 0
    assert "1 credential (openai_api_key)" in result.output
