"""The capability ladder (M4 design section 5): what this telemetry supports
now, and what unlocks the next rung. Pure over the GaugeReport plus plain
remediation strings - the adapter's Degradation type never crosses into the
gauge (the purity contract forbids it), so the CLI passes strings."""

from __future__ import annotations

from collections.abc import Sequence

from weir.gauge._types import GaugeReport

_FULL = 10_000


def capability_ladder_lines(
    report: GaugeReport, *, remediations: Sequence[str] = ()
) -> list[str]:
    jq = report.join_quality
    if jq.explicit_bp == _FULL:
        linkage = "explicit (gen_ai.tool.call.id present)"
    elif jq.explicit_bp + jq.nested_bp == _FULL:
        linkage = "structural (parent/child nesting)"
    elif jq.content_mined_bp > 0:
        linkage = "content-mined (low confidence; ids recovered from payloads)"
    else:
        linkage = "absent"
    taint_capable = report.inspectable_args_bp > 0
    lines = [
        f"  linkage: {linkage}",
        "  payloads: "
        + ("present" if taint_capable else "absent - content capture is off"),
        "at your current telemetry: coverage YES - taint/scan "
        + ("YES" if taint_capable else "NO"),
    ]
    if not taint_capable:
        lines.append(
            "to unlock cross-step analysis: enable gen_ai.input.messages, "
            "gen_ai.output.messages capture in your instrumentation"
        )
    # Deduplicate while preserving order; each remediation appears once.
    lines.extend(dict.fromkeys(remediations))
    return lines
