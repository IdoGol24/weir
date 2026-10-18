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

from pathlib import Path

import msgspec

MAP_RELATIVE_PATH = Path(".weir") / "reach.yml"
MAP_VERSION = 1


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
    try:
        parsed = msgspec.yaml.decode(data, type=ReachMap)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise MapError(f"invalid {path}: {exc}") from exc
    if parsed.version != MAP_VERSION:
        raise MapError(f"{path}: unsupported version {parsed.version} (expected {MAP_VERSION})")
    return path, parsed


def resolve_entry(raw: str, *, home: Path, project: Path) -> Path:
    if raw == "~" or raw.startswith(("~/", "~\\")):
        return home / raw[2:]
    path = Path(raw)
    return path if path.is_absolute() else project / path
