"""`weir-run run`: one check run from a maintainer's config.

Exit codes are the judge's (0 clean, 1 leak, 3 incomplete), and 2 for a
usage, configuration or input error, the runner's own or the judge's, and
for any other failure of the run (docs/canary.md, "Exit codes"). A runner
fault never exits 1, which would read as a leak.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from weir_run import config
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
    help="Also write the judge's JSON report (canary-report/1) here.",
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
def run_command(
    config_path: Path, report: Path | None, seed: int | None, weir_path: str | None
) -> None:
    """Plant canaries, run every flow against the loopback mock, judge the capture."""
    try:
        if report is not None and not report.parent.is_dir():
            raise SpecError(f"--report {report}: no such directory {report.parent}")
        spec = config.load(config_path)
        command = judge_cli.resolve(weir_path)
        judge_cli.check_available(command)
        code = run_spec(
            spec, command, out=sys.stdout, err=sys.stderr, seed=seed, json_report=report
        )
    except (SpecError, LedgerError, OSError, subprocess.SubprocessError, RuntimeError) as exc:
        click.echo(f"weir-run: {exc}", err=True)
        sys.exit(USAGE_ERROR)
    except KeyboardInterrupt:
        click.echo("weir-run: interrupted", err=True)
        sys.exit(USAGE_ERROR)
    except Exception as exc:
        click.echo(f"weir-run: the run failed ({type(exc).__name__})", err=True)
        sys.exit(USAGE_ERROR)
    sys.exit(code)


if __name__ == "__main__":
    main()
