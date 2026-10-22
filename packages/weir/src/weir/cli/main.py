"""Minimal CLI surface (L18): `weir gauge`, `weir scan`, `weir inventory`,
`weir audit`, `weir statusline` and `weir canary judge`.

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

import functools
import importlib.resources
import json as _json
import os
import sys
from collections.abc import Callable
from pathlib import Path

import click
import msgspec

from weir.adapters.otel import REMEDIATION, OtlpRejectError, decode_input, map_wire
from weir.adapters.otel.exposure import scan_surface
from weir.audit import AuditInputError, audit_paths, load_inputs
from weir.audit import encode_report as encode_audit_report
from weir.audit import report_lines as audit_report_lines
from weir.canary import (
    CaptureError,
    CaptureFile,
    LedgerError,
    Report,
    Role,
    judge_capture,
    judge_paths,
    parse_ledger,
    report_lines,
)
from weir.canary import encode_report as encode_canary_report
from weir.catalog import DEFAULT_CATALOG
from weir.evaluate import evaluate
from weir.evaluate.exposure import evaluate_exposure
from weir.exposure import ExposureScan, classify_exposure
from weir.gauge import compute_gauge_report
from weir.gauge.exposure import exposure_gauge_lines
from weir.gauge.ladder import capability_ladder_lines
from weir.gauge.provenance import provenance_gauge_lines
from weir.graph import build_session_graph
from weir.inventory import (
    InventoryInputError,
    InventoryInputs,
    default_key_path,
    encode_report,
    encode_store,
    take_inventory,
)
from weir.inventory.core import write_private
from weir.inventory.text import inventory_lines, unknown_list_lines
from weir.label import label_graph
from weir.report import exposure_lines, finding_lines, render_html_report
from weir.rules_commons import load_rules
from weir.schema.exposure import ExposureSurface
from weir.schema.trace import CanonicalTrace, decode_canonical_trace
from weir.statusline import setup as statusline_setup
from weir.statusline import valid_session_id, withholder
from weir.statusline.compose import run_beside
from weir.statusline.report import report_lines as session_report_lines
from weir.statusline.segment import read_session
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
    use_otlp = input_format == "otlp" or (input_format == "auto" and _looks_like_otlp(data))
    if use_otlp:
        try:
            wire = decode_input(data)
        except OtlpRejectError as exc:
            click.echo(f"error: invalid OTLP input: {exc}", err=True)
            raise SystemExit(2) from exc
        result = map_wire(wire)
        remediations = list(dict.fromkeys(REMEDIATION[d.reason] for d in result.degradations))
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
        sample_bytes = (
            importlib.resources.files("weir.data").joinpath("sample-export.json").read_bytes()
        )
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
        f
        for f in exposure_findings
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
    # something to say: `weir scan` on a native trace, which carries no
    # attributes, prints no exposure section at all.
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


def _write_output(path: Path, data: bytes) -> None:
    try:
        write_private(path, data)
    except OSError as exc:
        click.echo(f"error: cannot write {path}: {exc.strerror}", err=True)
        raise SystemExit(2) from exc


@main.command("inventory")
@click.option(
    "--home",
    "home",
    type=click.Path(file_okay=False, path_type=Path),
    required=True,
    help="Home directory to inventory. Required: there is no default, so a run"
    " never reads a real home by accident.",
)
@click.option(
    "--project",
    "project",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("."),
    show_default=True,
    help="Project directory; its .weir/reach.yml is the approved map.",
)
@click.option(
    "--env-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="The agent's launch environment as NAME=value lines (or `env -0` output).",
)
@click.option(
    "--process-env",
    is_flag=True,
    help="Use this process's own environment as the launch environment.",
)
@click.option(
    "--gitleaks",
    "gitleaks_reports",
    type=click.Path(dir_okay=False, path_type=Path),
    multiple=True,
    help="Import a gitleaks JSON report (repeatable).",
)
@click.option(
    "--trufflehog",
    "trufflehog_reports",
    type=click.Path(dir_okay=False, path_type=Path),
    multiple=True,
    help="Import a trufflehog JSON report (repeatable).",
)
@click.option(
    "--key",
    "key_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Fingerprint key file, created when missing [default: HOME/.weir/fingerprint.key].",
)
@click.option(
    "--unknown-list",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write unknown variable names [default: HOME/.weir/unknown-env.txt].",
)
@click.option(
    "--store",
    "store_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write keyed fingerprints plus offsets here (never values).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the weir-inventory/1 JSON report.")
@click.option("--strict", is_flag=True, help="Exit 1 when any environment variable is unknown.")
def inventory_command(
    home: Path,
    project: Path,
    env_file: Path | None,
    process_env: bool,
    gitleaks_reports: tuple[Path, ...],
    trufflehog_reports: tuple[Path, ...],
    key_path: Path | None,
    unknown_list: Path | None,
    store_path: Path | None,
    as_json: bool,
    strict: bool,
) -> None:
    """(experimental) List credentials by name, source and location. Never prints a value."""
    if env_file is not None and process_env:
        raise click.UsageError("--env-file and --process-env are mutually exclusive")
    inputs = InventoryInputs(
        home=home,
        project=project,
        key_path=key_path or default_key_path(home.absolute()),
        env_file=env_file,
        process_env=dict(os.environ) if process_env else None,
        gitleaks_reports=gitleaks_reports,
        trufflehog_reports=trufflehog_reports,
    )
    try:
        result = take_inventory(inputs)
    except InventoryInputError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    report = result.report
    unknown_path = unknown_list or home.absolute() / ".weir" / "unknown-env.txt"
    body = "".join(line + "\n" for line in unknown_list_lines(report.env_unknown))
    _write_output(unknown_path, body.encode("utf-8"))
    if store_path is not None:
        _write_output(store_path, encode_store(result.store))
    if as_json:
        click.echo(encode_report(report).decode(), nl=False)
    else:
        for line in inventory_lines(report, unknown_list_path=unknown_path.as_posix()):
            click.echo(line)
    raise SystemExit(1 if strict and report.counts.env_unknown else 0)


@main.command("audit")
@click.option(
    "--inventory",
    "report_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="The weir-inventory/1 report (weir inventory --json).",
)
@click.option(
    "--store",
    "store_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="The fingerprint store from the same weir inventory run (--store).",
)
@click.option(
    "--key",
    "key_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="The fingerprint key that run used. Never created: a new key matches nothing.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the weir-audit/1 JSON report.")
@click.argument("paths", metavar="PATH...", nargs=-1, required=True)
def audit_command(
    report_path: Path, store_path: Path, key_path: Path, as_json: bool, paths: tuple[str, ...]
) -> None:
    """(experimental) Report which inventoried credentials entered an agent's
    context or were sent out in a tool call, in Claude Code session files or
    OTLP telemetry (PATH: files or directories). Never prints a value.
    CLAUDE_CONFIG_DIR, when set, names a Claude config directory whose
    projects folder counts like ~/.claude/projects.

    Exit 0 clean, 1 exposed, 2 unusable input, 3 unknown."""
    try:
        # The command line reads the one variable the audit honours and hands
        # it in, so weir.audit itself stays a function of its arguments.
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
        report = audit_paths(
            report_path, store_path, key_path, paths, (config_dir,) if config_dir else ()
        )
    except AuditInputError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    if as_json:
        click.echo(encode_audit_report(report).decode(), nl=False)
    else:
        for line in audit_report_lines(report):
            click.echo(line)
    raise SystemExit(report.exit_code)


# --- weir statusline -------------------------------------------------------------

_SEGMENT_ERROR = "weir: error, run /weir"


def _inventory_options[F: Callable[..., object]](required: bool) -> Callable[[F], F]:
    """--inventory, --store and --key, as `weir audit` takes them."""

    def apply(command: F) -> F:
        for name, flag, help_text in reversed((
            ("report_path", "--inventory", "The weir-inventory/1 report (weir inventory --json)."),
            ("store_path", "--store", "The fingerprint store from the same weir inventory run."),
            ("key_path", "--key", "The fingerprint key that run used. Never created."),
        )):
            command = click.option(
                flag, name, type=click.Path(dir_okay=False, path_type=Path), required=required,
                help=help_text,
            )(command)
        return command

    return apply


def _claude_config_dirs() -> tuple[str, ...]:
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    return (config_dir,) if config_dir else ()


def _claude_dir(given: Path | None) -> Path:
    """The Claude config directory: --claude-dir, else CLAUDE_CONFIG_DIR,
    else HOME/.claude."""
    if given is not None:
        return given
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(config_dir) if config_dir else Path.home() / ".claude"


def _default_cache() -> Path:
    return Path.home() / ".weir" / "statusline"


def _segment(
    stdin: bytes, report_path: Path, store_path: Path, key_path: Path, cache: Path,
    budget_ms: int,
) -> str:
    """One status line run. A status line shows nothing when its command
    fails, so every failure is a short word on the line instead."""
    try:
        session = _json.loads(stdin)
        session_id, transcript = session.get("session_id"), session.get("transcript_path")
    except (ValueError, AttributeError):
        return "weir: no session"
    if not isinstance(session_id, str) or not isinstance(transcript, str) or not transcript:
        return "weir: no session"
    try:
        inputs = load_inputs(report_path, store_path, key_path)
        inputs_bytes = report_path.read_bytes() + b"\0" + store_path.read_bytes()
        return read_session(
            inputs, inputs_bytes, cache, transcript,
            session_id if valid_session_id(session_id) else "",
            _claude_config_dirs(), budget_ms / 1000,
        )
    except Exception:  # the status line must always print a line
        return _SEGMENT_ERROR


@main.group("statusline", invoke_without_command=True)
@_inventory_options(required=False)
@click.option(
    "--cache", type=click.Path(file_okay=False, path_type=Path), default=None,
    help="Directory for what earlier runs read (credential ids and offsets, never values).",
)
@click.option(
    "--inner", default=None,
    help="The status line command already in the settings: run beside, its output first.",
)
@click.option(
    "--budget-ms", type=click.IntRange(min=0), default=500, show_default=True,
    help="Reading time per run; a longer session is read over several runs.",
)
@click.pass_context
def statusline_group(
    ctx: click.Context, report_path: Path | None, store_path: Path | None,
    key_path: Path | None, cache: Path | None, inner: str | None, budget_ms: int,
) -> None:
    """(experimental) A Claude Code status-line segment: reads the session
    JSON Claude Code passes on stdin and prints how many inventoried
    credentials entered the session's context and how many were sent in a
    tool call, by value or by name. "unknown" when a file is not one it can
    read. Never prints a value. Always exits 0."""
    if ctx.invoked_subcommand is not None:
        return
    if report_path is None or store_path is None or key_path is None or cache is None:
        raise click.UsageError("weir statusline needs --inventory, --store, --key and --cache")
    stdin = click.get_binary_stream("stdin").read()
    line = run_beside(
        inner, stdin,
        lambda: _segment(stdin, report_path, store_path, key_path, cache, budget_ms),
    )
    click.echo(line)


@statusline_group.command("report")
@_inventory_options(required=True)
@click.option("--session", "session_id", required=True, help="The Claude Code session id.")
@click.option(
    "--claude-dir", type=click.Path(file_okay=False, path_type=Path), default=None,
    help="The Claude config directory [default: CLAUDE_CONFIG_DIR, else HOME/.claude].",
)
def statusline_report_command(
    report_path: Path, store_path: Path, key_path: Path, session_id: str,
    claude_dir: Path | None,
) -> None:
    """(experimental) The /weir report: per credential that reached the
    session, its source, the turn and tool call, where it now sits, and
    advice. Never prints a value."""
    if not valid_session_id(session_id):
        click.echo("error: --session: not a session id", err=True)
        raise SystemExit(2)
    projects = _claude_dir(claude_dir) / "projects"
    found = sorted(projects.glob(f"*/{session_id}.jsonl"))
    if len(found) != 1:
        many = "more than one transcript" if found else "no transcript"
        click.echo(f"error: {many} for session {session_id} under {projects}", err=True)
        raise SystemExit(2)
    try:
        inputs = load_inputs(report_path, store_path, key_path)
        lines = session_report_lines(inputs, str(found[0]), session_id, _claude_config_dirs())
    except AuditInputError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    for line in lines:
        click.echo(line)


def _confirmed() -> bool:
    click.echo("Type yes to apply: ", nl=False)
    answer = click.get_text_stream("stdin").readline()
    click.echo("")
    return statusline_setup.confirmed(lambda: answer)


@statusline_group.command("setup")
@_inventory_options(required=True)
@click.option(
    "--cache", type=click.Path(file_okay=False, path_type=Path), default=None,
    help="The segment's cache and the undo record [default: HOME/.weir/statusline].",
)
@click.option(
    "--claude-dir", type=click.Path(file_okay=False, path_type=Path), default=None,
    help="The Claude config directory [default: CLAUDE_CONFIG_DIR, else HOME/.claude].",
)
@click.option("--dry-run", is_flag=True, help="Show the change and write nothing.")
def statusline_setup_command(
    report_path: Path, store_path: Path, key_path: Path, cache: Path | None,
    claude_dir: Path | None, dry_run: bool,
) -> None:
    """(experimental) Add the weir segment beside the status line in
    Claude Code's user settings and install the /weir command. Shows the
    exact change, then writes only after you type yes."""
    paths = statusline_setup.Paths(
        claude_dir=_claude_dir(claude_dir), report=report_path, store=store_path, key=key_path,
        cache=cache or _default_cache(),
    )
    try:
        inputs = load_inputs(report_path, store_path, key_path)
        plan = statusline_setup.plan_setup(paths)
    except AuditInputError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    except statusline_setup.SetupError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(exc.code) from exc
    click.echo("weir statusline setup will make this change:")
    for line in statusline_setup.describe_setup(plan, withholder(inputs)):
        click.echo(line)
    undo = "weir statusline undo" + ("" if cache is None else f" --cache {paths.cache}")
    click.echo(f"undo: {undo} puts every file back as it was, byte for byte")
    if dry_run:
        click.echo("dry run: nothing written")
        return
    if not _confirmed():
        click.echo("not applied: nothing written")
        return
    statusline_setup.apply_setup(paths, plan)
    click.echo(f"applied; to undo: {undo}")


@statusline_group.command("undo")
@click.option(
    "--cache", type=click.Path(file_okay=False, path_type=Path), default=None,
    help="Where setup kept its undo record [default: HOME/.weir/statusline].",
)
@click.option("--dry-run", is_flag=True, help="Show what undo restores and write nothing.")
def statusline_undo_command(cache: Path | None, dry_run: bool) -> None:
    """(experimental) Put back every file `weir statusline setup` changed,
    byte for byte. Refuses when one changed after setup."""
    try:
        plan = statusline_setup.plan_undo(cache or _default_cache())
    except statusline_setup.SetupError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(exc.code) from exc
    if plan is None:
        click.echo("nothing to undo: weir statusline setup has not been applied")
        return
    click.echo("weir statusline undo will:")
    for line in statusline_setup.describe_undo(plan):
        click.echo(line)
    if dry_run:
        click.echo("dry run: nothing written")
        return
    if not _confirmed():
        click.echo("not applied: nothing written")
        return
    statusline_setup.apply_undo(plan)
    click.echo("restored")


@main.group("canary")
def canary_group() -> None:
    """Canary checks: did a planted fake credential leave the user's control?"""


_CANARY_SAMPLE = "canary-sample"


def _judge_canary_sample() -> Report:
    """Judge the bundled sample: a ledger and an OTLP capture shipped as
    package data, holding prefix-free fake values only. They are read from
    the package rather than from paths, so the ledger's mode-0600 rule does
    not apply: an installed wheel's files are world-readable by design, and
    these values guard nothing."""
    sample = importlib.resources.files("weir.data").joinpath(_CANARY_SAMPLE)
    ledger = parse_ledger(
        sample.joinpath("ledger.jsonl").read_bytes(), f"{_CANARY_SAMPLE}/ledger.jsonl"
    )
    capture = CaptureFile(
        path=f"{_CANARY_SAMPLE}/otlp.jsonl",
        role=Role.TELEMETRY,
        data=sample.joinpath("otlp.jsonl").read_bytes(),
    )
    return judge_capture(ledger, [capture])


@canary_group.command("judge")
@click.option(
    "--ledger",
    "ledger_path",
    metavar="FILE",
    help="The canary ledger (canary-ledger/1, docs/canary.md). Required unless --sample.",
)
@click.option(
    "--otlp",
    "otlp_paths",
    metavar="PATH",
    multiple=True,
    help="A telemetry file or directory of OTLP/JSON export requests, one per line"
    " (repeatable). Only these count toward completeness. Required unless --sample.",
)
@click.option(
    "--requests",
    "request_paths",
    metavar="PATH",
    multiple=True,
    help="A request capture file or directory (canary-requests/1): every request the"
    " mock received (repeatable). A planted value in a request to anything but its"
    " own provider is a leak to that request's sink.",
)
@click.option(
    "--sample",
    is_flag=True,
    help="Judge the bundled sample (a fake ledger and a capture with one leak) - zero setup.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the canary-report/1 JSON report.")
@click.argument("paths", metavar="[PATH]...", nargs=-1)
def canary_judge_command(
    ledger_path: str | None,
    otlp_paths: tuple[str, ...],
    request_paths: tuple[str, ...],
    sample: bool,
    as_json: bool,
    paths: tuple[str, ...],
) -> None:
    """Report every placement whose value, or an encoded form of it, appears
    in the capture, or in a request to anything but its own provider. PATHS
    are further files or directories swept for canaries. Prints placement
    ids, locations and sinks, never a value.

    Exit 0 clean, 1 leak, 2 unusable input, 3 incomplete."""
    if sample:
        if ledger_path is not None or otlp_paths or request_paths or paths:
            raise click.UsageError("--sample takes no --ledger, --otlp, --requests or PATH")
        judge = _judge_canary_sample
    elif ledger_path is None:
        raise click.UsageError("Missing option '--ledger' (or use --sample).")
    elif not otlp_paths:
        raise click.UsageError("Missing option '--otlp' (or use --sample).")
    else:
        judge = functools.partial(judge_paths, ledger_path, otlp_paths, paths, request_paths)
    try:
        report = judge()
    except (LedgerError, CaptureError) as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    if as_json:
        click.echo(encode_canary_report(report).decode(), nl=False)
    else:
        for line in report_lines(report):
            click.echo(line)
    raise SystemExit(report.exit_code)


if __name__ == "__main__":
    main()
