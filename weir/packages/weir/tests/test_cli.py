import json
from pathlib import Path

from click.testing import CliRunner

from weir.cli.main import main

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_PLANTED_IBAN = "DE89370400440532013000"
_OTLP_FIXTURE = Path(__file__).parents[3] / "fixtures" / "otlp" / "injection-exfil.full.json"


def test_gauge_on_full_capture_trace_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["gauge", str(_FIXTURES_DIR / "injection-exfil.json")])
    assert result.exit_code == 0
    assert "evidentiary coverage: 100%" in result.output


def test_gauge_on_degraded_trace_shows_remediation_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["gauge", str(_FIXTURES_DIR / "injection-exfil-benign.degraded.json")]
    )
    assert result.exit_code == 0
    assert "evidentiary coverage: 33%" in result.output
    assert "enable content capture" in result.output.lower()


def test_gauge_json_output_is_valid_json_with_expected_fields() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["gauge", "--json", str(_FIXTURES_DIR / "injection-exfil.json")]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["evidentiary_coverage_bp"] == 10_000


def test_gauge_on_malformed_trace_exits_two() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("bad.json").write_text("not json at all")
        result = runner.invoke(main, ["gauge", "bad.json"])
    assert result.exit_code == 2


def test_gauge_on_missing_file_exits_two() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["gauge", "does-not-exist.json"])
    assert result.exit_code == 2


def test_scan_red_trace_exits_one_and_reports_the_finding() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["scan", str(_FIXTURES_DIR / "injection-exfil.json"), "--report", "red.html"],
        )
        assert result.exit_code == 1
        assert "1 verdict-grade finding" in result.output
        html = Path("red.html").read_text(encoding="utf-8")
    assert "0 verdict-grade findings" not in html
    assert _PLANTED_IBAN not in html  # masked, never plaintext


def test_scan_benign_trace_exits_zero_and_shows_green_screen() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "scan",
                str(_FIXTURES_DIR / "injection-exfil-benign.json"),
                "--report",
                "green.html",
            ],
        )
        assert result.exit_code == 0
        assert "0 verdict-grade findings" in result.output
        html = Path("green.html").read_text(encoding="utf-8")
    assert "0 verdict-grade findings" in html


def test_scan_on_malformed_trace_exits_two() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("bad.json").write_text("{}")
        result = runner.invoke(main, ["scan", "bad.json"])
    assert result.exit_code == 2


def test_scan_without_report_flag_does_not_write_a_file() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", str(_FIXTURES_DIR / "injection-exfil.json")])
        assert result.exit_code == 1
        assert not Path("report.html").exists()


def test_the_three_demo_commands_run_end_to_end() -> None:
    """The plan's literal done-definition, run live via the CLI."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        gauge_result = runner.invoke(
            main, ["gauge", str(_FIXTURES_DIR / "injection-exfil-benign.degraded.json")]
        )
        assert gauge_result.exit_code == 0
        assert "evidentiary coverage:" in gauge_result.output
        assert "enable content capture" in gauge_result.output.lower()

        red_result = runner.invoke(
            main,
            ["scan", str(_FIXTURES_DIR / "injection-exfil.json"), "--report", "red.html"],
        )
        assert red_result.exit_code == 1
        red_html = Path("red.html").read_text(encoding="utf-8")
        assert "0 verdict-grade findings" not in red_html

        green_result = runner.invoke(
            main,
            [
                "scan",
                str(_FIXTURES_DIR / "injection-exfil-benign.json"),
                "--report",
                "green.html",
            ],
        )
        assert green_result.exit_code == 0
        green_html = Path("green.html").read_text(encoding="utf-8")
        assert "0 verdict-grade findings" in green_html


def test_gauge_sniffs_otlp_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["gauge", str(_OTLP_FIXTURE)])
    assert result.exit_code == 0
    assert "evidentiary coverage" in result.output
    assert "at your current telemetry" in result.output


def test_scan_sniffs_otlp_and_exits_one_on_injection() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(_OTLP_FIXTURE)])
    assert result.exit_code == 1  # the injection scenario has a verdict finding


def test_input_format_native_rejects_otlp_file() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["gauge", str(_OTLP_FIXTURE), "--input-format", "native"]
    )
    assert result.exit_code == 2


def test_scan_report_includes_the_capability_ladder_footer() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main, ["scan", str(_OTLP_FIXTURE), "--report", "report.html"]
        )
        html = Path("report.html").read_text(encoding="utf-8")
    assert result.exit_code == 1
    assert "at your current telemetry" in html


def test_gauge_sniffs_otlp_when_the_first_line_is_corrupt_mid_write() -> None:
    good_line = json.dumps(json.loads(_OTLP_FIXTURE.read_bytes()))
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("bad-first-line.jsonl").write_text(
            "{corrupt mid-write\n" + good_line + "\n"
        )
        result = runner.invoke(main, ["gauge", "bad-first-line.jsonl"])
    assert result.exit_code == 0


def test_gauge_sample_runs_with_zero_setup() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["gauge", "--sample"])
    assert result.exit_code == 0
    assert "at your current telemetry" in result.output


def test_gauge_with_no_argument_and_no_sample_flag_is_a_usage_error() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["gauge"])
    assert result.exit_code == 2


def test_scan_red_trace_finding_block_shows_witness_path_without_leaking_the_iban() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(_FIXTURES_DIR / "injection-exfil.json")])
    assert result.exit_code == 1
    assert "finding: injection-exfil-to-outbound-sink" in result.output
    assert "witness path:" in result.output
    assert "join tiers crossed:" in result.output
    assert _PLANTED_IBAN not in result.output


def test_scan_benign_trace_prints_no_finding_blocks() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(_FIXTURES_DIR / "injection-exfil-benign.json")]
    )
    assert result.exit_code == 0
    assert "finding:" not in result.output
