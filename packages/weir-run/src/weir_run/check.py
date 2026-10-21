"""One check run, start to finish (docs/canary.md, "What the runner owes
the judge"):

1. plant one fresh unique value per placement and write the ledger before
   any flow starts;
2. start the mock on 127.0.0.1 and run each flow against it, recording one
   `flow` record per flow (the mock records minted values, credential-field
   evidence and unexpected credentials as they happen);
3. stop the mock, relay each flow's output with every needle replaced;
4. call the judge, then delete the ledger and the capture.

The CLI runs a whole config through `run_spec`; the pytest plugin drives a
`CheckRun` call by call.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from weir_run import flows
from weir_run import judge as judge_cli
from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock import Mock
from weir_run.shapes import ByteSource, shaped
from weir_run.spec import FlowSpec, RunSpec, SpecError, validate


@dataclass
class FlowOutcome:
    id: str
    status: str
    stdout: Path = field(repr=False)
    stderr: Path = field(repr=False)


class CheckRun:
    def __init__(
        self,
        spec: RunSpec,
        judge: Sequence[str],
        *,
        seed: int | None = None,
        python: str = sys.executable,
        validate_spec: bool = True,
    ) -> None:
        if validate_spec:
            validate(spec)
        self.spec = spec
        self.judge_command = list(judge)
        self.python = python
        self.source = ByteSource(seed)
        self.outcomes: list[FlowOutcome] = []
        self.verdict: judge_cli.Verdict | None = None
        self.json_verdict: judge_cli.Verdict | None = None
        # 0700, private to this user: it holds the ledger and the capture.
        self.run_dir = Path(tempfile.mkdtemp(prefix="canary-run-"))
        self._flow_dirs = Path(tempfile.mkdtemp(prefix="canary-flows-"))
        try:
            self.ledger = Ledger(self.run_dir / judge_cli.LEDGER, self.source, spec.reserved_ids())
            self.capture = Capture(self.run_dir / "capture")
            self.planted: dict[str, str] = {}
            for p in spec.placements:
                made = shaped(self.source, p.shape)
                self.planted[p.variable] = self.ledger.plant(p.id, p.kind, made, p.required).value
            self.mock = Mock(spec.mock, self.ledger, self.capture, spec.placements, self.source)
            self.mock.start()
        except BaseException:
            for directory in (self.run_dir, self._flow_dirs):
                shutil.rmtree(directory, ignore_errors=True)
            raise
        self._stopped = False

    @property
    def mock_url(self) -> str:
        return self.mock.url

    def run_flow(self, flow: FlowSpec) -> FlowOutcome:
        if self._stopped:
            raise RuntimeError("the check run has already been judged")
        if any(o.id == flow.id for o in self.outcomes):
            raise SpecError(f"flow id {flow.id} is defined twice")
        index = len(self.outcomes) + 1
        home = self._flow_dirs / f"{index:02d}" / "home"
        tmp = self._flow_dirs / f"{index:02d}" / "tmp"
        home.mkdir(parents=True)
        tmp.mkdir()
        env = flows.flow_environment(self.mock_url, self.planted, flow.env, home, tmp)
        stdout, stderr = self.capture.flow_streams(index, flow.id)
        status = flows.run(flow, env, stdout, stderr, self.python)
        self.ledger.flow(flow.id, status)
        outcome = FlowOutcome(flow.id, status, stdout, stderr)
        self.outcomes.append(outcome)
        return outcome

    def stop(self) -> None:
        if not self._stopped:
            self._stopped = True
            self.mock.stop()
            self.ledger.close()

    def safe(self, text: str) -> str:
        """Program-derived text, printed only if it holds no trace of a value."""
        return "[withheld]" if self.ledger.withheld(text) else text

    def relay(self, out: TextIO) -> None:
        """Each flow's own output, every needle replaced by `<canary:ID>`."""
        for o in self.outcomes:
            out.write(f"flow {o.id}: {o.status}\n")
            for name, path in (("stdout", o.stdout), ("stderr", o.stderr)):
                data = path.read_bytes() if path.exists() else b""
                if not data:
                    continue
                out.write(f"--- flow {o.id} {name} (canaries redacted) ---\n")
                text = self.ledger.redact(data).decode("utf-8", "replace")
                out.write(text if text.endswith("\n") else text + "\n")
                out.write(f"--- end of flow {o.id} {name} ---\n")
        mock = self.mock
        for host, count in sorted(mock.egress.items()):
            out.write(f"mock: refused egress to {self.safe(host)} ({count}x)\n")
        for request, count in sorted(mock.unmocked.items()):
            out.write(f"mock: no mock for {self.safe(request)} ({count}x), answered 404\n")
        if mock.errors:
            out.write(f"mock: {mock.errors} request(s) failed inside the mock, answered 500\n")

    def judge(self, *, json_report: bool = False) -> judge_cli.Verdict:
        self.stop()
        self.verdict = judge_cli.judge(self.judge_command, self.run_dir)
        if json_report:
            self.json_verdict = judge_cli.judge(self.judge_command, self.run_dir, json_report=True)
        return self.verdict

    def redacted(self, data: bytes) -> str:
        """Judge output is value-free by contract; redact it all the same."""
        return self.ledger.redact(data).decode("utf-8", "replace")

    def cleanup(self) -> list[str]:
        """Delete the ledger, the capture and the flows' homes. Returns the
        directories that could not be removed."""
        self.stop()
        failed: list[str] = []
        for directory in (self.run_dir, self._flow_dirs):
            shutil.rmtree(directory, ignore_errors=True)
            if directory.exists():
                failed.append(str(directory))
        return failed


def run_spec(
    spec: RunSpec,
    judge: Sequence[str],
    *,
    out: TextIO,
    err: TextIO,
    seed: int | None = None,
    json_report: Path | None = None,
    python: str = sys.executable,
) -> int:
    """Run every flow of spec, judge, clean up. Returns the exit code."""
    run = CheckRun(spec, judge, seed=seed, python=python)
    try:
        for flow in spec.flows:
            run.run_flow(flow)
        run.stop()
        run.relay(err)
        verdict = run.judge(json_report=json_report is not None)
        out.write(run.redacted(verdict.stdout))
        if verdict.stderr:
            err.write(run.redacted(verdict.stderr))
        if json_report is not None and run.json_verdict is not None:
            json_report.write_text(run.redacted(run.json_verdict.stdout), encoding="utf-8")
        return verdict.code
    finally:
        for directory in run.cleanup():
            err.write(f"weir-run: could not delete {directory}; delete it by hand\n")
