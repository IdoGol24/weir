"""The maintainer's config file: TOML in, a validated `RunSpec` out.

Strict on purpose: an unknown table or key is a usage error, never ignored,
so a typo cannot quietly drop a placement or a flow from the check. Paths
are relative to the config file's directory.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from weir_run.spec import (
    CredentialField,
    EndpointSpec,
    FlowSpec,
    MockSpec,
    PlacementSpec,
    RunSpec,
    SpecError,
    default_variable,
    validate,
)

_TOP = {"mock", "placement", "flow"}
_MOCK = {"oauth", "model_reply", "tool_calls", "credential_fields", "endpoint"}
_ENDPOINT = {"id", "credential_fields", "status", "reply", "content_type", "capture"}
_PLACEMENT = {"id", "kind", "variable", "shape", "required", "provider_host"}
_FLOW = {"id", "command", "cwd", "timeout_seconds", "env", "skip"}


def _table(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SpecError(f"{where}: expected a table")
    return cast(dict[str, object], value)


def _tables(value: object, where: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise SpecError(f"{where}: expected an array of tables ([[{where}]])")
    return [_table(v, where) for v in cast(list[object], value)]


def _keys(table: Mapping[str, object], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise SpecError(f"{where}: unknown key {unknown[0]!r}")


def _str(table: Mapping[str, object], key: str, where: str, default: str | None = None) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise SpecError(f"{where}: {key} must be a string")
    return value


def _opt_str(table: Mapping[str, object], key: str, where: str) -> str | None:
    return None if key not in table else _str(table, key, where)


def _bool(table: Mapping[str, object], key: str, where: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise SpecError(f"{where}: {key} must be true or false")
    return value


def _str_list(table: Mapping[str, object], key: str, where: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(
        isinstance(v, str) for v in cast(list[object], value)
    ):
        raise SpecError(f"{where}: {key} must be an array of strings")
    return cast(list[str], value)


def _fields(table: Mapping[str, object], key: str, where: str) -> tuple[CredentialField, ...]:
    return tuple(CredentialField.parse(f) for f in _str_list(table, key, where))


def _endpoint(t: dict[str, object]) -> EndpointSpec:
    where = f"mock.endpoint {t.get('id', '?')}"
    _keys(t, _ENDPOINT, where)
    status = t.get("status", 200)
    if not isinstance(status, int) or isinstance(status, bool):
        raise SpecError(f"{where}: status must be an integer")
    return EndpointSpec(
        id=_str(t, "id", where),
        credential_fields=_fields(t, "credential_fields", where),
        status=status,
        reply=_str(t, "reply", where, "{}"),
        content_type=_str(t, "content_type", where, "application/json"),
        capture=_bool(t, "capture", where, False),
    )


def _mock(t: dict[str, object]) -> MockSpec:
    _keys(t, _MOCK, "mock")
    fields = _table(t.get("credential_fields", {}), "mock.credential_fields")
    return MockSpec(
        oauth=_bool(t, "oauth", "mock", False),
        model_reply=_str(t, "model_reply", "mock", "Done."),
        tool_calls=_str(t, "tool_calls", "mock", "each-offered-tool-once"),
        credential_fields={
            name: _fields(fields, name, "mock.credential_fields") for name in fields
        },
        endpoints=tuple(_endpoint(e) for e in _tables(t.get("endpoint", []), "mock.endpoint")),
    )


def _placement(t: dict[str, object]) -> PlacementSpec:
    where = f"placement {t.get('id', '?')}"
    _keys(t, _PLACEMENT, where)
    pid = _str(t, "id", where)
    kind = _str(t, "kind", where)
    variable = _opt_str(t, "variable", where)
    if variable is None:
        if kind == "env" and not pid.startswith("env."):
            raise SpecError(
                f"{where}: an env placement whose id does not start with env. names its variable"
            )
        variable = default_variable(pid, kind)
    return PlacementSpec(
        id=pid,
        kind=kind,
        variable=variable,
        shape=_str(t, "shape", where, "generic"),
        required=_bool(t, "required", where, False),
        provider_host=_opt_str(t, "provider_host", where),
    )


def _flow(t: dict[str, object], base: Path) -> FlowSpec:
    where = f"flow {t.get('id', '?')}"
    _keys(t, _FLOW, where)
    timeout = t.get("timeout_seconds", 300)
    if not isinstance(timeout, int | float) or isinstance(timeout, bool):
        raise SpecError(f"{where}: timeout_seconds must be a number")
    env = _table(t.get("env", {}), f"{where} env")
    if not all(isinstance(v, str) for v in env.values()):
        raise SpecError(f"{where}: env values must be strings")
    return FlowSpec(
        id=_str(t, "id", where),
        command=tuple(_str_list(t, "command", where)),
        cwd=(base / _str(t, "cwd", where, ".")).resolve(),
        timeout_seconds=float(timeout),
        env=cast(dict[str, str], env),
        skip=_opt_str(t, "skip", where),
    )


def load(path: Path) -> RunSpec:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SpecError(f"cannot read config {path}: {exc.strerror}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise SpecError(f"config {path} is not valid TOML: {exc}") from None
    _keys(raw, _TOP, str(path))
    base = path.resolve().parent
    spec = RunSpec(
        placements=tuple(_placement(p) for p in _tables(raw.get("placement", []), "placement")),
        flows=tuple(_flow(f, base) for f in _tables(raw.get("flow", []), "flow")),
        mock=_mock(_table(raw.get("mock", {}), "mock")),
    )
    validate(spec)
    return spec
