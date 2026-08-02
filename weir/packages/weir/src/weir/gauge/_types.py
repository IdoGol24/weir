"""GaugeReport data model - minimal, inline for this demo slice (the demo-
slice doc's L13 notes defer R3.6-R3.9/R3.11; only the headline coverage
number, the arg-capture/degraded/join-quality metrics behind it, and the
R3.4 remediation line are in scope). §3.3: seam artifacts carry no floats -
percentages are integer basis points (1/100 of a percent; 10000 = 100%)."""

from __future__ import annotations

import msgspec


class JoinQualitySplit(msgspec.Struct, frozen=True):
    explicit_bp: int
    nested_bp: int
    heuristic_bp: int


class GaugeReport(msgspec.Struct, frozen=True):
    total_tool_call_nodes: int
    inspectable_args_bp: int
    degraded_bp: int
    join_quality: JoinQualitySplit
    evidentiary_coverage_bp: int
    remediation_line: str | None
