"""One check run, start to finish (docs/canary.md, "What the runner owes
the judge"):

1. plant one fresh unique value per placement and write the ledger before
   any flow starts;
2. start the mock on 127.0.0.1 and run each flow against it, inside a
   loopback-only network namespace where one can be made (`isolation`),
   recording one `flow` record per flow (the mock records minted values
   and unexpected credentials as they happen, and every request it
   receives in the request capture);
3. stop the mock, record whether the run was isolated and each direct
   connection attempt the namespace blocked, relay each flow's output with
   every needle replaced;
4. call the judge, then delete the ledger and the capture.

The CLI runs a whole config through `run_spec`; the pytest plugin drives a
`CheckRun` call by call.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from weir_run import flows, isolation
from weir_run import judge as judge_cli
from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock import Mock
from weir_run.mock.intercept import Stub
from weir_run.shapes import ByteSource, shaped
from weir_run.spec import FlowSpec, RunSpec, SpecError, validate

_DIRECT_WORDS = {"tcp": "tcp connection to", "udp": "udp datagram to", "dns": "dns lookup of"}


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
        require_isolation: bool = False,
        stub: bool = False,
    ) -> None:
        """With stub, the flows run with the name and TLS stub, which
        needs the isolated network: without it the run cannot start."""
        if validate_spec:
            validate(spec)
        self.spec = spec
        self.judge_command = list(judge)
        self.python = python
        self.source = ByteSource(seed)
        self.outcomes: list[FlowOutcome] = []
        self.verdict: judge_cli.Verdict | None = None
        self.json_verdict: judge_cli.Verdict | None = None
        self.jail: isolation.Jail | None = None
        self.not_isolated: str | None = None
        self.stub: Stub | None = None
        # (flow, protocol, target) -> attempts; datagram payloads by flow.
        self.direct: dict[tuple[str, str, str], int] = {}
        self._direct_payloads: dict[str, list[bytes]] = {}
        # 0700, private to this user: it holds the ledger and the capture.
        self.run_dir = Path(tempfile.mkdtemp(prefix="canary-run-"))
        self._flow_dirs = Path(tempfile.mkdtemp(prefix="canary-flows-"))
        try:
            try:
                self.jail = isolation.jail(stub=True) if stub else isolation.jail()
            except isolation.Unavailable as exc:
                if stub:
                    raise SpecError(f"this check needs an isolated network: {exc}") from None
                self.not_isolated = str(exc)
            self.ledger = Ledger(self.run_dir / judge_cli.LEDGER, self.source, spec.reserved_ids())
            self.ledger.network(isolated=self.jail is not None, required=require_isolation)
            self.capture = Capture(self.run_dir / "capture")
            self.planted: dict[str, str] = {}
            for p in spec.placements:
                made = shaped(self.source, p.shape)
                providers = () if p.provider is None else (p.provider,)
                placement = self.ledger.plant(
                    p.id, p.kind, made, p.required, providers, p.provider_host
                )
                if p.kind in ("env", "code"):
                    self.planted[p.variable] = placement.value
            self.mock = Mock(spec.mock, self.ledger, self.capture, self.source)
            self.mock.start(None if self.jail is None else self.jail.listener)
            if stub and self.jail is not None:
                directory = self.run_dir / "stub"
                directory.mkdir()
                self.stub = Stub(self.mock, self.jail.stub, directory)
                self.stub.start()
        except BaseException:
            if self.jail is not None:
                self.jail.close()
            for directory in (self.run_dir, self._flow_dirs):
                shutil.rmtree(directory, ignore_errors=True)
            raise
        self._stopped = False

    @property
    def mock_url(self) -> str:
        return self.mock.url

    def run_flow(self, flow: FlowSpec, env: Mapping[str, str] | None = None) -> FlowOutcome:
        """Run flow with the runner's flow environment, or with env as its
        whole environment when given."""
        if self._stopped:
            raise RuntimeError("the check run has already been judged")
        if any(o.id == flow.id for o in self.outcomes):
            raise SpecError(f"flow id {flow.id} is defined twice")
        index = len(self.outcomes) + 1
        home = self._flow_dirs / f"{index:02d}" / "home"
        tmp = self._flow_dirs / f"{index:02d}" / "tmp"
        home.mkdir(parents=True)
        tmp.mkdir()
        if env is None:
            env = flows.flow_environment(self.mock_url, self.planted, flow.env, home, tmp)
        stdout, stderr = self.capture.flow_streams(index, flow.id)
        status = flows.run(flow, env, stdout, stderr, self.python, self.jail)
        self.ledger.flow(flow.id, status, telemetry=flow.telemetry)
        self._observe(flow.id)
        outcome = FlowOutcome(flow.id, status, stdout, stderr)
        self.outcomes.append(outcome)
        return outcome

    def _observe(self, flow_id: str) -> None:
        """Attribute the attempts seen so far to flow_id: flows run one at a
        time, and each one's packets are all seen once it has exited."""
        if self.jail is None:
            return
        for attempt in self.jail.collect():
            if attempt.payload:
                self._direct_payloads.setdefault(flow_id, []).append(attempt.payload)
            # A lookup the name stub answered is no direct connection: what
            # the flow did with the answer reached the stub on loopback.
            if attempt.answered:
                continue
            key = (flow_id, attempt.protocol, attempt.target)
            self.direct[key] = self.direct.get(key, 0) + 1

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        try:
            if self.stub is not None:
                self.stub.stop()
            self.mock.stop()
            if self.jail is not None:
                try:
                    # A process a flow left behind may still have sent one.
                    if self.outcomes:
                        self._observe(self.outcomes[-1].id)
                finally:
                    self.jail.close()
            for (flow_id, protocol, target), attempts in sorted(self.direct.items()):
                self.ledger.direct(flow_id, protocol, target, attempts)
            # What a blocked datagram carried is capture like any other
            # output: a canary in it is a leak the namespace stopped.
            for flow_id, payloads in self._direct_payloads.items():
                self.capture.swept_file(f"direct-{flow_id}", b"\n".join(payloads), ".udp")
        finally:
            self.ledger.close()

    def safe(self, text: str) -> str:
        """Program-derived text, printed only if it holds no trace of a value."""
        return "[withheld]" if self.ledger.withheld(text) else text

    def relay(self, out: TextIO, streams: Sequence[str] = ("stdout", "stderr")) -> None:
        """Each flow's own output, every needle replaced by `<canary:ID>`."""
        for o in self.outcomes:
            out.write(f"flow {o.id}: {o.status}\n")
            for name, path in (("stdout", o.stdout), ("stderr", o.stderr)):
                if name not in streams:
                    continue
                data = path.read_bytes() if path.exists() else b""
                if not data:
                    continue
                out.write(f"--- flow {o.id} {name} (canaries redacted) ---\n")
                text = self.ledger.redact(data).decode("utf-8", "replace")
                out.write(text if text.endswith("\n") else text + "\n")
                out.write(f"--- end of flow {o.id} {name} ---\n")
        if self.jail is not None:
            out.write("network: isolated, loopback only\n")
        else:
            out.write(f"network: not isolated ({self.not_isolated})\n")
        if self.stub is not None:
            for name, count in sorted(self.stub.names.items()):
                out.write(
                    f"network: name lookup of {self.safe(name)} answered by the stub ({count}x)\n"
                )
        for (flow_id, protocol, target), count in sorted(self.direct.items()):
            what = _DIRECT_WORDS[protocol]
            out.write(
                f"network: blocked direct {what} {self.safe(target)} from flow {flow_id}"
                f" ({count}x)\n"
            )
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
        """Judge output is value-free by contract; redact it all the same.
        The judge ends its lines the way its platform does; the text here
        ends them with `\n`, which the stream it is written to translates."""
        return self.ledger.redact(data).decode("utf-8", "replace").replace("\r\n", "\n")

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


def warn_unowned(spec: RunSpec, err: TextIO) -> None:
    """Name each placement with neither a provider nor a provider host: it
    belongs in no request, so any request that holds it is a leak
    (docs/canary.md, "A placement's own provider"). Printed before any flow
    runs; it names the id, never a value."""
    for p in spec.placements:
        if p.provider is None and p.provider_host is None:
            err.write(
                f"placement {p.id} has no provider: any request holding it counts as a leak\n"
            )


def run_spec(
    spec: RunSpec,
    judge: Sequence[str],
    *,
    out: TextIO,
    err: TextIO,
    seed: int | None = None,
    json_report: Path | None = None,
    python: str = sys.executable,
    require_isolation: bool = False,
) -> int:
    """Run every flow of spec, judge, clean up. Returns the exit code."""
    warn_unowned(spec, err)
    run = CheckRun(spec, judge, seed=seed, python=python, require_isolation=require_isolation)
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
