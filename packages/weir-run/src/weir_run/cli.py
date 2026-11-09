"""`weir-run run`: one check run from a maintainer's config; `weir-run
verify` and `weir-run predicate` (docs/verify.md).

Exit codes are the run's verdict (0 clean, 1 a finding: a leak or an
unmediated tool call, 3 incomplete; `weir_run.verdict`), and 2 for a
usage, configuration or input error, the runner's own or the judge's, and
for any other failure of the run (docs/canary.md, "Exit codes"). A runner
fault never exits 1, which would read as a finding.
"""

from __future__ import annotations

import json
import re
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import NoReturn

import click

from weir_run import config, evidence, verify
from weir_run import judge as judge_cli
from weir_run.check import run_spec
from weir_run.ledger import LedgerError
from weir_run.spec import SpecError

USAGE_ERROR = 2


@click.group()
def main() -> None:
    # Flow output and judge reports can hold any text the program wrote.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


@main.command("run")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="The check's TOML config: placements, flows and mocked endpoints.",
)
@click.option(
    "--report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Also write the run's JSON report (canary-report/2) here.",
)
@click.option(
    "--seed",
    type=int,
    help="Draw canary values from a seeded stream, for local reproduction only.",
)
@click.option(
    "--weir",
    "weir_path",
    help="The weir executable to judge with. Default: the one beside this Python, else PATH.",
)
@click.option(
    "--require-isolation",
    is_flag=True,
    help="Make a run whose flows could not be isolated from the network incomplete (exit 3).",
)
def run_command(
    config_path: Path,
    report: Path | None,
    seed: int | None,
    weir_path: str | None,
    require_isolation: bool,
) -> None:
    """Plant canaries, run every flow against the loopback mock, judge the capture.

    On Linux, flows run in a network namespace whose only network is
    loopback, so a client that ignores the proxy settings reaches nothing,
    and its attempt is reported."""

    def work() -> int:
        if report is not None and not report.parent.is_dir():
            raise SpecError(f"--report {report}: no such directory {report.parent}")
        spec = config.load(config_path)
        command = judge_cli.resolve(weir_path)
        judge_cli.check_available(command)
        return run_spec(
            spec,
            command,
            out=sys.stdout,
            err=sys.stderr,
            seed=seed,
            json_report=report,
            require_isolation=require_isolation,
        )

    _guarded(work)


def _guarded(work: Callable[[], int]) -> NoReturn:
    """Exit with work's code; any failure of the run exits 2, never 1."""
    # A CI cancel or timeout sends SIGTERM: stop the same way as Ctrl-C, so
    # the flow's processes are stopped and the ledger and capture deleted.
    previous = signal.signal(signal.SIGTERM, _terminate)
    try:
        code = work()
    except (SpecError, LedgerError, OSError, subprocess.SubprocessError, RuntimeError) as exc:
        click.echo(f"weir-run: {exc}", err=True)
        sys.exit(USAGE_ERROR)
    except KeyboardInterrupt:
        click.echo("weir-run: interrupted", err=True)
        sys.exit(USAGE_ERROR)
    except Exception as exc:
        click.echo(f"weir-run: the run failed ({type(exc).__name__})", err=True)
        sys.exit(USAGE_ERROR)
    finally:
        signal.signal(signal.SIGTERM, previous)
    sys.exit(code)


@main.command("verify")
@click.option(
    "--target",
    required=True,
    type=click.Choice(sorted(verify.TARGETS)),
    help="The credential swap or sandbox to check.",
)
@click.option(
    "--target-command",
    help="The target's executable. Default: the target's own command on PATH.",
)
@click.option(
    "--evidence",
    "evidence_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the evidence record (weir-verify-evidence/2) here.",
)
@click.option(
    "--image-digest",
    help="The digest of the image this result is for (sha256:<64 hex>), kept in the record.",
)
@click.option(
    "--weir",
    "weir_path",
    help="The weir executable to judge with. Default: the one beside this Python, else PATH.",
)
def verify_command(
    target: str,
    target_command: str | None,
    evidence_path: Path | None,
    image_digest: str | None,
    weir_path: str | None,
) -> None:
    """Check that a credential swap or sandbox keeps a planted key out of the
    model, telemetry, console output and outbound requests.

    Exit 0 clean, 1 a finding (a leak or an unmediated tool call), 3
    incomplete: anything the run could not check, isolation included, is
    incomplete."""

    def work() -> int:
        if image_digest is not None and not re.fullmatch("sha256:[0-9a-f]{64}", image_digest):
            raise SpecError(f"--image-digest {image_digest}: not an image digest (sha256:<64 hex>)")
        if evidence_path is not None and not evidence_path.parent.is_dir():
            raise SpecError(f"--evidence {evidence_path}: no such directory")
        command = judge_cli.resolve(weir_path)
        judge_cli.check_available(command)
        code, record = verify.verify(
            target,
            command,
            out=sys.stdout,
            err=sys.stderr,
            target_command=target_command,
            image_digest=image_digest,
        )
        if evidence_path is not None:
            evidence_path.write_bytes(record)
        return code

    _guarded(work)


@main.command("predicate")
@click.option(
    "--evidence",
    "evidence_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="The evidence record `weir-run verify --evidence` wrote.",
)
@click.option("--url", help="A link to the run that made the record, kept in the predicate.")
def predicate_command(evidence_path: Path, url: str | None) -> None:
    """Print the in-toto test-result predicate for an evidence record
    (weir-verify-evidence/2, or /1 as weir-run 0.3.0 wrote it): PASSED for
    clean, FAILED for a finding or incomplete. A record that breaks its
    schema, or whose verdict its fields do not support, is refused (exit 2)."""
    try:
        doc = evidence.predicate(evidence_path.read_bytes(), url)
    except (evidence.EvidenceError, OSError):
        click.echo(f"weir-run: {evidence_path}: not a valid evidence record", err=True)
        sys.exit(USAGE_ERROR)
    click.echo(json.dumps(doc, indent=2))


def _terminate(signum: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    main()
