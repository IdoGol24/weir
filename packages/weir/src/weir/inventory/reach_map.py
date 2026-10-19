"""Source 4: the approved map, <project>/.weir/reach.yml.

The map's one producer is the weir-reach-discovery onboarding skill, which
writes a proposal that a person reviews, edits and approves. This reads that
shape, version 2:

    version: 2
    status: approved          # proposed | approved; only approved counts
    approved_by: null
    extra_locations:          # places secrets are loaded from that discovery misses
      - location: ~/.config/examplevendor/creds.toml
        kind: file            # file | dir | env_var
        exists: true          # true | false | unknown
        git: outside          # tracked | ignored | untracked | outside
        routes: {...}         # grep_tool, read_tool, cat, grep_r: hidden | reachable
        evidence: [src/vendor_client.py:12]
        reason: the vendor client loads its API credentials from this file
    intended_gaps:            # same entry shape: secrets the agent's work needs
      - location: env:TEST_DATABASE_URL
        kind: env_var
        exists: unknown
        evidence: [tests/conftest.py:8]
        reason: the test suite the agent runs connects to the local test database
    unknown_env:              # variables the code reads; a person marks them fine
      - location: env:PORT
        evidence: [src/server.py:3]
        reason: parsed as the listening port
        mark: review          # review | fine

A `proposed` map changes nothing. The schema is strict: an unknown key is an
error, not a silent no-op, so a typo never reads as an approval.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import msgspec

from weir.inventory._types import MapKind, MapStatus

MAP_RELATIVE_PATH = Path(".weir") / "reach.yml"
MAP_VERSION = 2
# msgspec's `- at `$.extra_locations[0]`` suffix: built from this schema's
# own field names and list indices (it has no mappings), never from the map.
_SCHEMA_PATH = re.compile(r" - at `(\$[^`]*)`$")
_ENV_LOCATION = re.compile(r"env:([A-Za-z_][A-Za-z0-9_]*)")


class MapError(Exception):
    pass


RouteState = Literal["hidden", "reachable"]


class MapRoutes(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    grep_tool: RouteState
    read_tool: RouteState
    cat: RouteState
    grep_r: RouteState


class MapLocation(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    location: str
    kind: MapKind
    exists: bool | Literal["unknown"] = "unknown"
    git: Literal["tracked", "ignored", "untracked", "outside"] | None = None
    routes: MapRoutes | None = None
    evidence: list[str] = msgspec.field(default_factory=list[str])
    reason: str | None = None


class MapUnknownEnv(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    location: str
    mark: Literal["review", "fine"]
    evidence: list[str] = msgspec.field(default_factory=list[str])
    reason: str | None = None


class ReachMap(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    version: int
    status: MapStatus
    approved_by: str | None = None
    extra_locations: list[MapLocation] = msgspec.field(default_factory=list[MapLocation])
    intended_gaps: list[MapLocation] = msgspec.field(default_factory=list[MapLocation])
    unknown_env: list[MapUnknownEnv] = msgspec.field(default_factory=list[MapUnknownEnv])

    @property
    def approved(self) -> bool:
        return self.status is MapStatus.APPROVED

    def fine_env(self) -> list[str]:
        """Names a person marked fine. Empty unless the map is approved."""
        if not self.approved:
            return []
        return [
            name for u in self.unknown_env
            if u.mark == "fine" and (name := env_name(u.location)) is not None
        ]


def env_name(location: str) -> str | None:
    """`env:NAME` -> NAME; None for any other location."""
    match = _ENV_LOCATION.fullmatch(location)
    return match.group(1) if match else None


def _check(path: Path, reach: ReachMap) -> None:
    """The rules the schema types cannot carry. Messages name the entry by
    list and index, never by its content."""
    if reach.version != MAP_VERSION:
        raise MapError(f"{path}: unsupported version (expected {MAP_VERSION})")
    for section, items in (
        ("extra_locations", reach.extra_locations), ("intended_gaps", reach.intended_gaps),
    ):
        for i, item in enumerate(items):
            is_env = env_name(item.location) is not None
            if (item.kind is MapKind.ENV_VAR) != is_env:
                raise MapError(
                    f"invalid {path}: {section}[{i}]: env_var locations are written "
                    "env:NAME, and only those"
                )
            if section == "extra_locations" and is_env:
                raise MapError(
                    f"invalid {path}: {section}[{i}]: an environment variable is never "
                    "an extra location"
                )
            if not is_env and not item.location.strip():
                raise MapError(f"invalid {path}: {section}[{i}].location is empty")
    for i, unknown in enumerate(reach.unknown_env):
        if env_name(unknown.location) is None:
            raise MapError(f"invalid {path}: unknown_env[{i}].location must be env:NAME")


def load_map(project: Path) -> tuple[Path, ReachMap] | None:
    path = project / MAP_RELATIVE_PATH
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MapError(f"cannot read {path}: {exc.strerror}") from exc
    # Never surface the parser's message: YAML errors quote the offending line
    # and schema errors quote the unknown key, either of which can be a value.
    try:
        parsed = msgspec.yaml.decode(data, type=ReachMap)
    except msgspec.ValidationError as exc:
        where = _SCHEMA_PATH.search(str(exc))
        at = f" at {where.group(1)}" if where else ""
        raise MapError(f"invalid {path}: does not match the map schema{at}") from None
    except msgspec.DecodeError:
        raise MapError(f"invalid {path}: not valid YAML") from None
    _check(path, parsed)
    return path, parsed


def resolve_entry(raw: str, *, home: Path, project: Path) -> Path:
    if raw == "~" or raw.startswith(("~/", "~\\")):
        return home / raw[2:]
    path = Path(raw)
    return path if path.is_absolute() else project / path
