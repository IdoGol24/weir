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
from pathlib import Path

import click
import msgspec

from weir.adapters.otel import REMEDIATION, OtlpRejectError, adapt_otlp
from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate
from weir.gauge import compute_gauge_report
from weir.gauge.ladder import capability_ladder_lines
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.report import finding_lines, render_html_report
from weir.rules_commons import load_rules
from weir.schema.trace import CanonicalTrace, decode_canonical_trace
from weir.taint import build_tainted_graph

_BOM = b"\xef\xbb\xbf"


@click.group()
def main() -> None:
    pass


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


def _load_input_or_exit(
    trace_path: str | None, input_format: str, *, data: bytes | None = None
) -> tuple[CanonicalTrace, list[str]]:
    """Returns (trace, remediation strings from the adapter ledger). Pass
    `data` directly (e.g. the bundled `--sample` bytes) to skip the filesystem
    read; otherwise `trace_path` is read from disk."""
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
            result = adapt_otlp(data)
        except OtlpRejectError as exc:
            click.echo(f"error: invalid OTLP input: {exc}", err=True)
            raise SystemExit(2) from exc
        remediations = list(
            dict.fromkeys(REMEDIATION[d.reason] for d in result.degradations)
        )
        return result.trace, remediations
    try:
        return decode_canonical_trace(data), []
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
        trace, remediations = _load_input_or_exit(None, input_format, data=sample_bytes)
    elif trace_path:
        trace, remediations = _load_input_or_exit(trace_path, input_format)
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
    raise SystemExit(0)


@main.command("scan")
@click.argument("trace_path", type=click.Path(exists=False))
@click.option(
    "--report", "report_path", type=click.Path(), default=None, help="Write an HTML report here."
)
@click.option(
    "--fail-on",
    type=click.Choice(["high", "medium", "low"]),
    default="high",
    show_default=True,
    help="G6: exit 1 iff at least one verdict-grade finding exists (this slice has no severity"
    " gradient below verdict-grade, so every level behaves the same).",
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
    fail_on: str,  # noqa: ARG001 - accepted for CLI-surface fidelity (G6); see help text
    detected_framework: str,
    input_format: str,
) -> None:
    trace, remediations = _load_input_or_exit(trace_path, input_format)
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    rules = load_rules()
    findings = evaluate(tainted, rules).findings
    gauge_report = compute_gauge_report(
        graph,
        DEFAULT_CATALOG,
        detected_framework=detected_framework,
        instrumentation_scope=trace.metadata.instrumentation_scope,
    )

    verdict_grade_findings = [f for f in findings if f.is_verdict_grade]

    if report_path is not None:
        ladder = capability_ladder_lines(gauge_report, remediations=remediations)
        html = render_html_report(
            scenario_name=Path(trace_path).stem,
            graph=graph,
            gauge=gauge_report,
            findings=findings,
            rules=rules,
            ladder_lines=ladder,
        )
        Path(report_path).write_text(html, encoding="utf-8")

    if verdict_grade_findings:
        click.echo(f"{len(verdict_grade_findings)} verdict-grade finding(s)")
        exit_code = 1
    else:
        click.echo("0 verdict-grade findings")
        exit_code = 0

    rules_by_id = {rule.id: rule for rule in rules}
    for finding in findings:
        for line in finding_lines(finding, graph, rules_by_id):
            click.echo(line)

    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
