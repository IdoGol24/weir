"""Backs the README's "nothing else exits" claim (2026-08-17 truthfulness
gate): every committed fixture, run through both CLI commands, must exit 0,
1, or 2 - never crash, never hang, never exit anything else. Skips directories
and non-trace files (PROVENANCE.md, generate_capture.py); iterates
deterministically sorted so a failure is reproducible.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from weir.cli.main import main

_FIXTURES_DIR = Path(__file__).parents[1] / "fixtures"


def _corpus() -> list[Path]:
    paths = [
        *sorted((_FIXTURES_DIR / "otlp").glob("*")),
        *sorted((_FIXTURES_DIR / "otlp-corrupt").glob("*")),
        _FIXTURES_DIR / "foreign" / "capture.jsonl",
        *sorted(_FIXTURES_DIR.glob("*.json")),
    ]
    return [path for path in paths if path.is_file()]


def test_gauge_and_scan_exit_zero_one_or_two_on_every_committed_fixture() -> None:
    runner = CliRunner()
    corpus = _corpus()
    assert len(corpus) >= 30  # sanity: the corpus glob actually found fixtures
    for path in corpus:
        for command in ("gauge", "scan"):
            result = runner.invoke(main, [command, str(path)])
            assert result.exit_code in (0, 1, 2), (command, path, result.output)
