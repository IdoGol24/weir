"""What one check run is made of: placements, flows and the mock's endpoints.

The CLI reads these from a maintainer's TOML file (`weir_run.config`);
the pytest plugin builds them call by call. Both hand the same `RunSpec` to
`weir_run.check`. A spec never holds a canary value: values are drawn
when the run plants them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from weir_run.shapes import SHAPES

ID_RE = re.compile(r"[A-Za-z0-9._:#/-]{1,128}")
VARIABLE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ENDPOINT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")
FIELD_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
HOST_RE = re.compile(r"[A-Za-z0-9._:-]{1,253}")

# The mock's own endpoints. A configured endpoint takes any other id.
BUILTIN_ENDPOINTS = ("model", "oauth", "otlp")
# docs/canary.md, "Attribution": the sink of a request to a path the mock
# does not mock. No configured endpoint may take it.
UNMOCKED = "unmocked"
PLANTED_KINDS = ("env", "code")
TOOL_CALL_MODES = ("each-offered-tool-once", "none")
FIELD_LOCATIONS = ("header", "query", "body")
# The credentials the mock's OAuth endpoints issue (docs/canary.md, kinds).
OAUTH_TOKENS = ("code", "device_code", "access_token", "refresh_token", "id_token")

# Variables the runner sets for every flow. A placement or a flow's own
# environment may not take one of these names.
RUNNER_VARIABLES = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "SYSTEMROOT",
        "PATHEXT",
        "PYTHONUTF8",
        "CANARY_MOCK_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "ANTHROPIC_BASE_URL",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)


class SpecError(Exception):
    """A usage or configuration error: the runner exits 2."""


@dataclass(frozen=True)
class CredentialField:
    location: str
    name: str

    @classmethod
    def parse(cls, text: str) -> CredentialField:
        location, sep, name = text.partition(":")
        if not sep or location not in FIELD_LOCATIONS or not FIELD_NAME_RE.fullmatch(name):
            raise SpecError(
                f"credential field {text!r}: expected header:<name>, query:<name> or body:<name>"
            )
        return cls(location, name.lower() if location == "header" else name)


# The credential fields a built-in endpoint always declares, before any the
# config adds: the Anthropic Messages API sends its key in `x-api-key`.
BUILTIN_FIELDS: dict[str, tuple[CredentialField, ...]] = {
    "model": (CredentialField("header", "x-api-key"),),
}


@dataclass(frozen=True)
class EndpointSpec:
    """A mocked API of the program's own, served at `{mock}/ep/<id>/...`."""

    id: str
    credential_fields: tuple[CredentialField, ...] = ()
    status: int = 200
    reply: str = "{}"
    content_type: str = "application/json"
    capture: bool = False


@dataclass(frozen=True)
class ScriptStep:
    """One tool call the mock's model asks for, in order: `tool` is the
    name of a tool the program offers, `input` its arguments."""

    tool: str
    input: Mapping[str, object]


@dataclass(frozen=True)
class MockSpec:
    oauth: bool = False
    model_reply: str = "Done."
    tool_calls: str = "each-offered-tool-once"
    # The Messages API's script: with steps, each turn asks for the next
    # step whose tool the program offers, one at a time, in place of every
    # offered tool once; once no step is left it answers model_reply.
    script: tuple[ScriptStep, ...] = ()
    credential_fields: dict[str, tuple[CredentialField, ...]] = field(
        default_factory=dict[str, tuple[CredentialField, ...]]
    )
    endpoints: tuple[EndpointSpec, ...] = ()

    def fields_for(self, endpoint: str) -> tuple[CredentialField, ...]:
        for ep in self.endpoints:
            if ep.id == endpoint:
                return ep.credential_fields
        builtin = BUILTIN_FIELDS.get(endpoint, ())
        added = self.credential_fields.get(endpoint, ())
        return builtin + tuple(f for f in added if f not in builtin)


@dataclass(frozen=True)
class PlacementSpec:
    id: str
    kind: str
    variable: str
    shape: str = "generic"
    required: bool = False
    provider_host: str | None = None
    # The mocked endpoint this placement belongs to: `model`, `oauth`,
    # `otlp` or a configured endpoint's id (docs/canary.md, "A placement's
    # own provider"). A request anywhere else that holds it is a leak.
    provider: str | None = None


@dataclass(frozen=True)
class FlowSpec:
    id: str
    command: tuple[str, ...]
    cwd: Path
    timeout_seconds: float = 300.0
    env: dict[str, str] = field(default_factory=dict[str, str])
    skip: str | None = None
    # False when the flow's program has its telemetry off, so an empty
    # telemetry capture says nothing about it.
    telemetry: bool = True


# Whose key the model key is (docs: the Claude Code check). "anthropic": an
# Anthropic API key, whose own host is ANTHROPIC_HOST; "gateway": a key for
# the gateway at the base URL, which has no other host.
KEY_OWNERS = ("anthropic", "gateway")
ANTHROPIC_HOST = "api.anthropic.com"


@dataclass(frozen=True)
class ClaudeCodeSpec:
    """A `[claude_code]` check: Claude Code run headless in a scratch
    project and home, with the settings under test."""

    # None when the config does not say: the run is then not judged.
    key_owner: str | None
    project: Path
    # A settings file applied as the user's own settings, beside the
    # project's .claude/settings.json.
    user_settings: Path | None = None
    trust_project: bool = True
    executable: str = "claude"
    timeout_seconds: float = 300.0


@dataclass(frozen=True)
class RunSpec:
    placements: tuple[PlacementSpec, ...]
    flows: tuple[FlowSpec, ...]
    mock: MockSpec = MockSpec()
    claude_code: ClaudeCodeSpec | None = None

    def reserved_ids(self) -> list[str]:
        """Every id the run will print, or the stem of one it mints later."""
        ids = [p.id for p in self.placements] + [f.id for f in self.flows]
        ids += [f"runtime.oauth.{t}" for t in OAUTH_TOKENS]
        endpoints = [*BUILTIN_ENDPOINTS, *(e.id for e in self.mock.endpoints)]
        ids += [f"unexpected.{e}.authorization" for e in endpoints]
        ids += [f"unexpected.{e}.proxy-authorization" for e in endpoints]
        ids += [f"unexpected.{e}.{f.name}" for e in endpoints for f in self.mock.fields_for(e)]
        # Printed as sinks: `<host> (blocked)` and `unmocked`.
        ids += [p.provider_host for p in self.placements if p.provider_host]
        ids.append(UNMOCKED)
        return ids


def default_variable(placement_id: str, kind: str) -> str:
    """`env.SEARCH_API_KEY` reads `SEARCH_API_KEY`; a `code` placement is read
    from `CANARY_CODE_<ID>`, the id upper-cased with non-word characters as `_`."""
    if kind == "env":
        name = placement_id.removeprefix("env.")
    else:
        name = "CANARY_CODE_" + re.sub(r"\W", "_", placement_id.removeprefix("code.")).upper()
    return name


def validate(spec: RunSpec, *, require_flows: bool = True) -> None:
    """Every rule a spec must meet before anything is planted or started."""
    seen: set[str] = set()
    variables: set[str] = set()
    for p in spec.placements:
        if not ID_RE.fullmatch(p.id):
            raise SpecError(f"placement id {p.id!r} breaks the id rule")
        if p.id in seen:
            raise SpecError(f"placement id {p.id} is defined twice")
        seen.add(p.id)
        if p.kind not in PLANTED_KINDS:
            raise SpecError(
                f"placement {p.id}: kind {p.kind!r} cannot be planted; "
                "this release plants env and code (mock-oauth values are minted by the mock)"
            )
        if p.shape not in SHAPES:
            raise SpecError(f"placement {p.id}: unknown shape {p.shape!r}")
        if not VARIABLE_RE.fullmatch(p.variable):
            raise SpecError(f"placement {p.id}: {p.variable!r} is not a variable name")
        if p.variable in RUNNER_VARIABLES or p.variable in variables:
            raise SpecError(f"placement {p.id}: variable {p.variable} is already taken")
        variables.add(p.variable)
        if p.provider_host is not None and not HOST_RE.fullmatch(p.provider_host):
            raise SpecError(f"placement {p.id}: provider_host {p.provider_host!r} is not a host")
        endpoints = {*BUILTIN_ENDPOINTS, *(e.id for e in spec.mock.endpoints)}
        if p.provider is not None and p.provider not in endpoints:
            raise SpecError(
                f"placement {p.id}: provider {p.provider!r} is not an endpoint;"
                " expected model, oauth, otlp or a [[mock.endpoint]] id"
            )
        if p.provider == "oauth" and not spec.mock.oauth:
            raise SpecError(f"placement {p.id}: provider 'oauth' needs oauth = true in [mock]")
    flow_ids: set[str] = set()
    for f in spec.flows:
        if not ID_RE.fullmatch(f.id):
            raise SpecError(f"flow id {f.id!r} breaks the id rule")
        if f.id in flow_ids:
            raise SpecError(f"flow id {f.id} is defined twice")
        flow_ids.add(f.id)
        if not f.command:
            raise SpecError(f"flow {f.id}: command is empty")
        if f.timeout_seconds <= 0:
            raise SpecError(f"flow {f.id}: timeout_seconds must be positive")
        for name in f.env:
            if not VARIABLE_RE.fullmatch(name):
                raise SpecError(f"flow {f.id}: {name!r} is not a variable name")
            if name in RUNNER_VARIABLES or name in variables:
                raise SpecError(f"flow {f.id}: variable {name} is set by the runner")
    if require_flows and not spec.flows:
        raise SpecError("no flow is defined")
    endpoint_ids: set[str] = set()
    for e in spec.mock.endpoints:
        if not ENDPOINT_ID_RE.fullmatch(e.id) or e.id in (*BUILTIN_ENDPOINTS, UNMOCKED):
            raise SpecError(f"endpoint id {e.id!r} is not usable")
        if e.id in endpoint_ids:
            raise SpecError(f"endpoint id {e.id} is defined twice")
        endpoint_ids.add(e.id)
        if not 100 <= e.status <= 599:
            raise SpecError(f"endpoint {e.id}: status {e.status} is not an HTTP status")
    for name, fields in spec.mock.credential_fields.items():
        if name not in BUILTIN_ENDPOINTS:
            raise SpecError(
                f"credential fields for {name!r}: built-in endpoints are model, oauth and otlp"
            )
        if name == "otlp" and any(f.location == "body" for f in fields):
            raise SpecError("credential fields for 'otlp': an OTLP export has no body: fields")
    if spec.mock.tool_calls not in TOOL_CALL_MODES:
        raise SpecError(f"tool_calls {spec.mock.tool_calls!r}: expected one of {TOOL_CALL_MODES}")
