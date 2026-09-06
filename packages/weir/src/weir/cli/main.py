"""Minimal CLI surface (L18): `weir gauge` and `weir scan` only.

Thin argument parsing over the pure pipeline functions - no logic of its
own. `weir test`/`validate`/`verify`/`feedback`/`rules list`/`events import`
are all deferred (not on the demo path, per the demo-slice doc's L18 notes).

A `--mode verbatim|context` scan flag is NOT exposed here: the one bundled
rule (L11) is verbatim-only, and no context-mode finding path exists yet in
the evaluator (L16) - adding the flag without real behavior behind it would
imply a capability this slice doesn't have. Revisit once a context-mode
rule exists.
"""

from __future__ import annotations

import importlib.resources
import json as _json
import sys
from pathlib import Path

import click
import msgspec

from weir.adapters.otel import REMEDIATION, OtlpRejectError, decode_input, map_wire
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate
from weir.evaluate.exposure import evaluate_exposure
from weir.exposure import ExposureScan, classify_exposure
from weir.gauge import compute_gauge_report
from weir.gauge.exposure import exposure_gauge_lines
from weir.gauge.ladder import capability_ladder_lines
from weir.gauge.provenance import provenance_gauge_lines
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.report import exposure_lines, finding_lines, render_html_report
from weir.rules_commons import load_rules
from weir.schema.exposure import ExposureSurface
from weir.schema.trace import CanonicalTrace, decode_canonical_trace
from weir.taint import build_tainted_graph

_BOM = b"\xef\xbb\xbf"

# --fail-on is real for every finding family now (spec section 3): a finding
# counts toward exit 1 when it is verdict-grade AND its rule's severity is at
# or above the threshold. RuleSpec.severity defaults to "high", so every
# bundled rule fails CI at the default threshold and today's behavior holds.
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _severity_at_or_above(severity: str, threshold: str) -> bool:
    """Does a rule of this severity count toward exit 1 at this --fail-on?

    Extracted from scan_command so it is reachable by a test: every bundled
    rule is "high", the top rank, so an end-to-end fixture can never
    demonstrate the gate rejecting anything.
    """
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[threshold]


@click.group()
def main() -> None:
    # `weir scan` renders wire-controlled span names and attribute keys, so
    # its stdout is not ASCII-safe. A cp437 console would otherwise abort the
    # command mid-report with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def _looks_like_otlp(data: bytes) -> bool:
    text = data.removeprefix(_BOM).decode("utf-8", errors="replace")
    try:
        parsed = _json.loads(text)
    except _json.JSONDecodeError:
        parsed = None
        for line in text.splitlines():
            try:
                parsed = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            break
    if isinstance(parsed, dict):
        return "resourceSpans" in parsed or "resource_spans" in parsed
    return False


_NO_SURFACE = ExposureSurface(applicable=False, spans_scanned=0, strings=[])
_NO_EXPOSURE = classify_exposure(_NO_SURFACE, DEFAULT_CATALOG)


def _load_input_or_exit(
    trace_path: str | None, input_format: str, *, data: bytes | None = None
) -> tuple[CanonicalTrace, list[str], ExposureScan]:
    """Returns (trace, remediation strings from the adapter ledger, exposure
    scan). The scan reads the WIRE batch, before the GenAI span filter, which
    is why this decodes in two steps rather than calling adapt_otlp."""
    if data is None:
        assert trace_path is not None
        try:
            data = Path(trace_path).read_bytes()
        except OSError as exc:
            click.echo(f"error: cannot read trace file {trace_path!r}: {exc}", err=True)
            raise SystemExit(2) from exc
    use_otlp = input_format == "otlp" or (
        input_format == "auto" and _looks_like_otlp(data)
    )
    if use_otlp:
        try:
            wire = decode_input(data)
        except OtlpRejectError as exc:
            click.echo(f"error: invalid OTLP input: {exc}", err=True)
            raise SystemExit(2) from exc
        result = map_wire(wire)
        remediations = list(
            dict.fromkeys(REMEDIATION[d.reason] for d in result.degradations)
        )
        exposure = classify_exposure(scan_surface(wire), DEFAULT_CATALOG)
        return result.trace, remediations, exposure
    try:
        return decode_canonical_trace(data), [], _NO_EXPOSURE
    except (msgspec.ValidationError, msgspec.DecodeError) as exc:
        click.echo(f"error: invalid trace: {exc}", err=True)
        raise SystemExit(2) from exc


@main.command("gauge")
@click.argument("trace_path", type=click.Path(exists=False), required=False)
@click.option(
    "--sample",
    is_flag=True,
    help="Run on the bundled sample export (a content-off OTLP trace) - zero setup.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON (R3.8 seed).")
@click.option(
    "--framework",
    "detected_framework",
    default="langchain",
    show_default=True,
    help="Framework to key the R3.4 remediation line off of.",
)
@click.option(
    "--input-format",
    type=click.Choice(["auto", "native", "otlp"]),
    default="auto",
    show_default=True,
    help="Input format; auto sniffs for a resourceSpans key.",
)
def gauge_command(
    trace_path: str | None,
    sample: bool,
    as_json: bool,
    detected_framework: str,
    input_format: str,
) -> None:
    """Standalone (R3.5): no rules, no catalog customization needed."""
    if sample:
        sample_bytes = importlib.resources.files("weir.data").joinpath(
            "sample-export.json"
        ).read_bytes()
        trace, remediations, exposure = _load_input_or_exit(None, input_format, data=sample_bytes)
    elif trace_path:
        trace, remediations, exposure = _load_input_or_exit(trace_path, input_format)
    else:
        raise click.UsageError("provide a trace file or --sample")
    graph = build_session_graph(trace)
    report = compute_gauge_report(
        graph,
        DEFAULT_CATALOG,
        detected_framework=detected_framework,
        instrumentation_scope=trace.metadata.instrumentation_scope,
    )

    if as_json:
        click.echo(msgspec.json.encode(report).decode())
    else:
        click.echo(f"evidentiary coverage: {report.evidentiary_coverage_bp // 100}%")
        click.echo(f"argument capture: {report.inspectable_args_bp // 100}%")
        click.echo(f"degraded: {report.degraded_bp // 100}%")
        if report.remediation_line:
            click.echo(report.remediation_line)
        for line in capability_ladder_lines(report, remediations=remediations):
            click.echo(line)
        # The loader guarantees a provenance rule has a sink; narrow for the
        # type checker rather than trusting it silently.
        prov_sinks = {
            r.sink_tool_name
            for r in load_rules()
            if r.mode == "provenance" and r.sink_tool_name is not None
        }
        if prov_sinks or DEFAULT_CATALOG.untrusted_sources:
            labeled = label_graph(graph, DEFAULT_CATALOG)
            for line in provenance_gauge_lines(
                labeled,
                provenance_sink_names=prov_sinks,
                untrusted_sources=DEFAULT_CATALOG.untrusted_sources,
            ):
                click.echo(line)
        for line in exposure_gauge_lines(exposure):
            click.echo(line)
    raise SystemExit(0)


@main.command("scan")
@click.argument("trace_path", type=click.Path(exists=False))
@click.option(
    "--report", "report_path", type=click.Path(), default=None, help="Write an HTML report here."
)
@click.option(
    "--fail-on",
    type=click.Choice(sorted(_SEVERITY_RANK, key=_SEVERITY_RANK.__getitem__, reverse=True)),
    default="high",
    show_default=True,
    help="Exit 1 only for verdict-grade findings whose rule severity is at or above"
    " this level (G6). Every bundled rule is 'high'.",
)
@click.option(
    "--framework",
    "detected_framework",
    default="langchain",
    show_default=True,
    help="Framework to key the R3.4 remediation line off of.",
)
@click.option(
    "--input-format",
    type=click.Choice(["auto", "native", "otlp"]),
    default="auto",
    show_default=True,
    help="Input format; auto sniffs for a resourceSpans key.",
)
def scan_command(
    trace_path: str,
    report_path: str | None,
    fail_on: str,
    detected_framework: str,
    input_format: str,
) -> None:
    trace, remediations, exposure = _load_input_or_exit(trace_path, input_format)
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    rules = load_rules()
    rules_by_id = {rule.id: rule for rule in rules}
    findings = evaluate(tainted, rules).findings
    exposure_findings = evaluate_exposure(exposure, rules)
    gauge_report = compute_gauge_report(
        graph,
        DEFAULT_CATALOG,
        detected_framework=detected_framework,
        instrumentation_scope=trace.metadata.instrumentation_scope,
    )

    def _fails(rule_id: str) -> bool:
        rule = rules_by_id.get(rule_id)
        return rule is not None and _severity_at_or_above(rule.severity, fail_on)

    verdict_grade_findings = [f for f in findings if f.is_verdict_grade]
    failing = [f for f in verdict_grade_findings if _fails(f.rule_id)] + [
        f for f in exposure_findings
        if f.is_verdict_grade and _severity_at_or_above(f.severity, fail_on)
    ]

    if report_path is not None:
        ladder = capability_ladder_lines(gauge_report, remediations=remediations)
        html = render_html_report(
            scenario_name=Path(trace_path).stem,
            graph=graph,
            gauge=gauge_report,
            findings=findings,
            rules=rules,
            ladder_lines=ladder,
            exposure_findings=exposure_findings,
        )
        Path(report_path).write_text(html, encoding="utf-8")

    # Exposure renders ABOVE the flow findings, and only when there is
    # something to say: `weir scan` on a native trace must stay byte-identical
    # (the README's hero SVG is generated from it).
    for line in exposure_lines(exposure_findings):
        click.echo(line)

    if verdict_grade_findings:
        click.echo(f"{len(verdict_grade_findings)} verdict-grade finding(s)")
    elif any(f.is_verdict_grade for f in exposure_findings):
        # A credential finding above with an unqualified "0 verdict-grade
        # findings" below would read as an all-clear next to a live
        # exposure - "flow" makes clear which family is actually at zero.
        click.echo("0 verdict-grade flow findings")
    else:
        click.echo("0 verdict-grade findings")

    for finding in findings:
        for line in finding_lines(finding, graph, rules_by_id):
            click.echo(line)

    raise SystemExit(1 if failing else 0)


if __name__ == "__main__":
    main()
