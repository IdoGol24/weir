"""`weir canary judge --sample`: the bundled sample shows one leak, offline,
in one command (docs/canary.md).

Every expectation is derived from the bundled sample's own bytes: the test
reads the ledger's planted values, finds in the capture which span and
attribute holds one, and builds the report line the contract's text format
says the judge prints for that hit. Nothing here restates the sample's ids,
names or values as literals.
"""

from __future__ import annotations

import importlib.resources
import json
import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import canary_fixtures as fx
import pytest
from click.testing import CliRunner

from weir.cli.main import main

_SAMPLE = importlib.resources.files("weir.data").joinpath("canary-sample")
_PACKAGE_ROOT = Path(__file__).parents[1]


@dataclass(frozen=True)
class _Expected:
    placement: str
    otlp_name: str
    line: int
    span: str
    location: str


def _records(name: str) -> list[dict[str, Any]]:
    text = _SAMPLE.joinpath(name).read_bytes().decode("utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _values() -> dict[str, str]:
    records = _records("ledger.jsonl")
    return {r["id"]: r["value"] for r in records if r.get("type") == "placement"}


def _expected_leaks() -> list[_Expected]:
    """Every (placement, span, attribute) where the capture holds a planted
    value verbatim, read with plain json from the bundled bytes."""
    values = _values()
    found: list[_Expected] = []
    for line, request in enumerate(_records("otlp.jsonl"), start=1):
        for resource in request["resourceSpans"]:
            for scope in resource["scopeSpans"]:
                for span in scope["spans"]:
                    for attribute in span.get("attributes", []):
                        text = attribute["value"].get("stringValue", "")
                        for placement, value in values.items():
                            if value in text:
                                found.append(
                                    _Expected(
                                        placement,
                                        "otlp.jsonl",
                                        line,
                                        span["name"],
                                        f"attributes.{attribute['key']}",
                                    )
                                )
    return found


def _run(*extra: str) -> fx.Run:
    result = CliRunner().invoke(main, ["canary", "judge", "--sample", *extra])
    return fx.Run(result.exit_code, result.stdout, result.stderr)


def test_the_sample_plants_exactly_one_leak() -> None:
    # The sample's purpose: one clear leak, and at least one placement that
    # was used and stayed clean, so the report shows the difference.
    assert len(_expected_leaks()) == 1
    assert len(_values()) > 1


def test_sample_reports_the_one_leak_by_placement_span_and_location() -> None:
    (want,) = _expected_leaks()
    run = _run()
    assert run.exit_code == 1
    (leak,) = fx.leak_lines(run)
    prefix, _, path = leak.partition(" file=")
    assert prefix == f"LEAK {want.placement}"
    assert path.split(":", 1)[0].endswith(want.otlp_name)
    assert f":{want.line} signal=traces span={json.dumps(want.span)} " in leak
    assert leak.endswith(f" at={want.location} form=raw")
    assert run.lines[-1] == "result: leak"


def test_sample_json_report_names_the_same_hit() -> None:
    (want,) = _expected_leaks()
    run = _run("--json")
    assert run.exit_code == 1
    report = run.report
    assert report["result"] == "leak" and report["exit_code"] == 1
    (hit,) = report["hits"]
    assert (hit["placement"], hit["span"], hit["location"], hit["line"]) == (
        want.placement,
        want.span,
        want.location,
        want.line,
    )


@pytest.mark.parametrize("extra", [(), ("--json",)])
def test_sample_never_prints_a_planted_value_or_a_fragment(extra: tuple[str, ...]) -> None:
    run = _run(*extra)
    fx.assert_value_free(run.stdout + run.stderr, _values().values())


@pytest.mark.parametrize(
    "args",
    [
        ["--sample", "--ledger", "ledger.jsonl"],
        ["--sample", "--otlp", "otlp.jsonl"],
        ["--sample", "capture.txt"],
        [],
        ["--otlp", "otlp.jsonl"],
        ["--ledger", "ledger.jsonl"],
    ],
)
def test_sample_excludes_other_inputs_and_inputs_are_required_without_it(
    args: list[str],
) -> None:
    result = CliRunner().invoke(main, ["canary", "judge", *args])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_sample_runs_from_the_built_wheel(tmp_path: Path) -> None:
    """Build the wheel, unpack it, and run the sample from the unpacked
    copy with an isolated interpreter and an empty environment: the sample
    must ship as package data, not be read from the source tree."""
    from hatchling.builders.wheel import WheelBuilder

    dist = tmp_path / "dist"
    (wheel,) = WheelBuilder(str(_PACKAGE_ROOT)).build(directory=str(dist), versions=["standard"])
    site = tmp_path / "site"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(site)

    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(site)!r})\n"
        "import weir\n"
        f"assert weir.__file__.startswith({str(site)!r}), weir.__file__\n"
        "from weir.cli.main import main\n"
        "sys.argv = ['weir', 'canary', 'judge', '--sample']\n"
        "main()\n"
    )
    # An empty environment, save what Windows needs to start Python at all.
    env = {k: os.environ[k] for k in ("SYSTEMROOT",) if k in os.environ}
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        encoding="utf-8",  # text mode: Windows' "\r\n" reads back as "\n"
        check=False,
    )
    stdout, stderr = result.stdout, result.stderr
    assert result.returncode == 1, stderr
    assert stdout == CliRunner().invoke(main, ["canary", "judge", "--sample"]).stdout
    (want,) = _expected_leaks()
    assert stdout.startswith(f"LEAK {want.placement} ")
    fx.assert_value_free(stdout + stderr, _values().values())
