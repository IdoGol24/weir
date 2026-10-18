"""Source 4: the approved map, <project>/.weir/reach.yml.

A person declares here what discovery cannot know: credential locations it
would not find on its own, and unknown environment variables that are fine.
The schema is strict - an unknown key is an error, not a silent no-op, so a
typo never reads as an approval.

    version: 1
    credentials:
      - path: config/creds.go      # project-relative, ~/home-relative or absolute
        name: PAYMENTS_SIGNING_KEY # optional label; defaults to the field or file name
        field: signing_key         # optional: only the value assigned to this key
    env:
      fine: [BUILD_TAG, CI_RUNNER] # unknown variables a person marked fine
"""

from __future__ import annotations

import re
from pathlib import Path

import msgspec

MAP_RELATIVE_PATH = Path(".weir") / "reach.yml"
MAP_VERSION = 1
# msgspec's `- at `$.credentials[0]`` suffix: built from this schema's own
# field names and list indices (it has no mappings), never from the map.
_SCHEMA_PATH = re.compile(r" - at `(\$[^`]*)`$")


class MapError(Exception):
    pass


class MapCredential(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    path: str
    name: str | None = None
    field: str | None = None


class MapEnv(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    fine: list[str] = msgspec.field(default_factory=list[str])


class ReachMap(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    version: int
    credentials: list[MapCredential] = msgspec.field(default_factory=list[MapCredential])
    env: MapEnv = msgspec.field(default_factory=MapEnv)


def load_map(project: Path) -> tuple[Path, ReachMap] | None:
    path = project / MAP_RELATIVE_PATH
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MapError(f"cannot read {path}: {exc.strerror}") from exc
    if not data.strip():
        return path, ReachMap(version=MAP_VERSION)
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
    if parsed.version != MAP_VERSION:
        raise MapError(f"{path}: unsupported version (expected {MAP_VERSION})")
    return path, parsed


def resolve_entry(raw: str, *, home: Path, project: Path) -> Path:
    if raw == "~" or raw.startswith(("~/", "~\\")):
        return home / raw[2:]
    path = Path(raw)
    return path if path.is_absolute() else project / path
