"""The pytest plugin, subprocess mode: a canary check inside a test.

    def test_quickstart_exports_no_credentials(canary_check):
        search = canary_check.endpoint("search", reply='{"results": []}')
        canary_check.env("SEARCH_API_KEY", required=True, provider="search")
        canary_check.run(["{python}", "examples/quickstart.py"], env={"SEARCH_BASE_URL": search})
        # teardown judges; the test fails on a leak or an incomplete run

Declare mocked endpoints, then placements, first; the first `run` (or the
first read of `mock_url`) plants the canaries, writes the ledger and starts
the mock, after which declarations are closed. Each `run` is one flow under
the same allowlisted environment as `weir-run run`. At teardown the
plugin judges, prints the redacted flow output and the value-free report,
deletes the ledger and the capture, and fails the test unless the result is
clean. Call `judge()` yourself to assert on the result instead.

The judge is `weir` beside this interpreter or on PATH; override the
`canary_judge_command` fixture to use another.

Flows run in a loopback-only network namespace where one can be made, as
under `weir-run run`. `pytest --canary-require-isolation` makes a check
whose flows could not be isolated incomplete.
"""

from __future__ import annotations

import io
import sys
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from weir_run import judge as judge_cli
from weir_run.check import CheckRun
from weir_run.spec import (
    CredentialField,
    EndpointSpec,
    FlowSpec,
    MockSpec,
    PlacementSpec,
    RunSpec,
    default_variable,
    validate,
)

EXIT_CLEAN = 0


@dataclass(frozen=True)
class CanaryResult:
    code: int
    report: str
    output: str

    @property
    def clean(self) -> bool:
        return self.code == EXIT_CLEAN


class CanaryCheck:
    def __init__(
        self,
        judge_command: Sequence[str],
        cwd: Path,
        *,
        require_isolation: bool = False,
    ) -> None:
        self._judge_command = list(judge_command)
        self._cwd = cwd
        self._require_isolation = require_isolation
        self._placements: list[PlacementSpec] = []
        self._mock = MockSpec()
        self._run: CheckRun | None = None
        self._flows = 0
        self.result: CanaryResult | None = None

    # -- declarations --------------------------------------------------

    def _declare(self, placement: PlacementSpec) -> None:
        if self._run is not None:
            raise RuntimeError("declare every placement before the first run")
        placements = (*self._placements, placement)
        validate(RunSpec(placements, (), self._mock), require_flows=False)
        self._placements.append(placement)

    def env(
        self,
        variable: str,
        *,
        id: str | None = None,  # noqa: A002 - the contract's word
        shape: str = "generic",
        required: bool = False,
        provider: str | None = None,
        provider_host: str | None = None,
    ) -> str:
        """Plant a canary in each flow's environment as `variable`. Returns
        the placement id. `provider` is the mocked endpoint it belongs to
        (declare a configured endpoint first)."""
        pid = id or f"env.{variable}"
        self._declare(PlacementSpec(pid, "env", variable, shape, required, provider_host, provider))
        return pid

    def code(
        self,
        id: str,  # noqa: A002 - the contract's word
        *,
        variable: str | None = None,
        shape: str = "generic",
        required: bool = False,
        provider: str | None = None,
        provider_host: str | None = None,
    ) -> str:
        """A canary the flow passes explicitly; it reads it from the returned
        variable name. `provider` is the mocked endpoint it belongs to."""
        name = variable or default_variable(id, "code")
        self._declare(PlacementSpec(id, "code", name, shape, required, provider_host, provider))
        return name

    def endpoint(
        self,
        id: str,  # noqa: A002 - the contract's word
        *,
        credential_fields: Sequence[str] = (),
        reply: str = "{}",
        status: int = 200,
        content_type: str = "application/json",
        capture: bool = False,
    ) -> str:
        """Mock one of the program's own APIs. Returns its URL as
        `{mock}/ep/<id>`, ready for a flow's env."""
        fields = tuple(CredentialField.parse(f) for f in credential_fields)
        spec = EndpointSpec(id, fields, status, reply, content_type, capture)
        self.mock(endpoints=(*self._mock.endpoints, spec))
        return f"{{mock}}/ep/{id}"

    def mock(
        self,
        *,
        oauth: bool | None = None,
        model_reply: str | None = None,
        tool_calls: str | None = None,
        credential_fields: Mapping[str, Sequence[str]] | None = None,
        endpoints: Sequence[EndpointSpec] | None = None,
    ) -> None:
        if self._run is not None:
            raise RuntimeError("configure the mock before the first run")
        m = self._mock
        mock = replace(
            m,
            oauth=m.oauth if oauth is None else oauth,
            model_reply=m.model_reply if model_reply is None else model_reply,
            tool_calls=m.tool_calls if tool_calls is None else tool_calls,
            credential_fields=m.credential_fields
            if credential_fields is None
            else {
                k: tuple(CredentialField.parse(f) for f in v) for k, v in credential_fields.items()
            },
            endpoints=m.endpoints if endpoints is None else tuple(endpoints),
        )
        validate(RunSpec(tuple(self._placements), (), mock), require_flows=False)
        self._mock = mock

    # -- running -------------------------------------------------------

    def _started(self) -> CheckRun:
        if self.result is not None:
            raise RuntimeError("this check has already been judged")
        if self._run is None:
            judge_cli.check_available(self._judge_command)
            spec = RunSpec(tuple(self._placements), (), self._mock)
            self._run = CheckRun(
                spec,
                self._judge_command,
                validate_spec=False,
                require_isolation=self._require_isolation,
            )
        return self._run

    @property
    def started(self) -> bool:
        return self._run is not None

    @property
    def mock_url(self) -> str:
        return self._started().mock_url

    def run(
        self,
        command: Sequence[str],
        *,
        id: str | None = None,  # noqa: A002 - the contract's word
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 300.0,
    ) -> str:
        """Run one flow to completion; returns its status (`ok`, `failed`,
        `timeout`). `{python}` in command is this interpreter; `{mock}` in an
        env value is the mock's base URL."""
        run = self._started()
        self._flows += 1
        flow = FlowSpec(
            id=id or f"flow-{self._flows}",
            command=tuple(command),
            cwd=Path(cwd).resolve() if cwd is not None else self._cwd,
            timeout_seconds=timeout,
            env=dict(env or {}),
        )
        validate(RunSpec(tuple(self._placements), (flow,), self._mock))
        return run.run_flow(flow).status

    def judge(self) -> CanaryResult:
        """Stop the mock, judge, delete the ledger and the capture."""
        if self.result is not None:
            return self.result
        run = self._started()
        if not run.outcomes:
            raise RuntimeError("no flow was run, so there is nothing to judge")
        try:
            run.stop()
            output = io.StringIO()
            run.relay(output)
            verdict = run.judge()
            report = run.redacted(verdict.stdout) + run.redacted(verdict.stderr)
            self.result = CanaryResult(verdict.code, report, output.getvalue())
        finally:
            run.cleanup()
        return self.result

    def close(self) -> None:
        if self._run is not None:
            self._run.cleanup()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("weir-run", "canary checks (weir-run)")
    group.addoption(
        "--canary-require-isolation",
        action="store_true",
        help="Make a canary check whose flows could not be isolated from the network incomplete.",
    )


@pytest.fixture
def canary_judge_command() -> list[str]:
    """The judge's command prefix; override to judge with another weir."""
    return judge_cli.resolve()


@pytest.fixture
def canary_check(
    canary_judge_command: list[str], request: pytest.FixtureRequest
) -> Generator[CanaryCheck]:
    check = CanaryCheck(
        canary_judge_command,
        Path(str(request.path)).parent,
        require_isolation=bool(request.config.getoption("canary_require_isolation")),
    )
    try:
        yield check
        if check.started and check.result is None:
            result = check.judge()
            sys.stdout.write(result.output)
            sys.stdout.write(result.report)
            if not result.clean:
                pytest.fail(f"canary check exited {result.code}:\n{result.report}", pytrace=False)
    finally:
        check.close()
