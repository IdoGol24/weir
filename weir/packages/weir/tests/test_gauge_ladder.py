from weir.gauge._types import GaugeReport, JoinQualitySplit
from weir.gauge.ladder import capability_ladder_lines


def _report(inspectable_bp: int, explicit_bp: int = 10_000) -> GaugeReport:
    return GaugeReport(
        total_tool_call_nodes=2,
        inspectable_args_bp=inspectable_bp,
        degraded_bp=0,
        join_quality=JoinQualitySplit(
            explicit_bp=explicit_bp, nested_bp=0, content_mined_bp=0,
            heuristic_bp=0,
        ),
        evidentiary_coverage_bp=inspectable_bp,
        remediation_line=None,
    )


def test_content_off_telemetry_reads_as_a_ladder_not_a_bare_number() -> None:
    lines = capability_ladder_lines(_report(0), remediations=["enable capture"])
    text = "\n".join(lines)
    assert "coverage YES" in text and "taint/scan NO" in text
    assert "enable capture" in text


def test_full_telemetry_has_no_unlock_line() -> None:
    lines = capability_ladder_lines(_report(10_000), remediations=[])
    assert all("unlock" not in line for line in lines)
