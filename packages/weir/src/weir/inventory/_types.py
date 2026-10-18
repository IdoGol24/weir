"""Inventory records (weir-inventory/1): which credentials exist and where.

Every struct in this module is VALUE-FREE by construction. None of them has a
field that can hold a credential value, a fragment of one, a masked form
(`prefix...last4`) or a fingerprint. The report is safe to print, to write
as `weir inventory --json`, and to hand to a consumer such as the guard
settings generator. What a stored record carries is in `StoredRecord`: a keyed
fingerprint plus offsets, never the value. The value itself stays in process
memory, in `KnownValues` (see `weir.inventory.values`).

Contract for consumers: docs/inventory.md. The JSON Schema artifact is
packages/weir/schema_artifacts/inventory.v1.schema.json, generated from
`inventory_json_schema()` and drift-tested.
"""

from __future__ import annotations

import enum

import msgspec

INVENTORY_SCHEMA = "weir-inventory/1"
STORE_SCHEMA = "weir-inventory-store/1"


class Source(enum.StrEnum):
    """The four inventory sources (design brief, "Component specs: Inventory")."""

    # The fixed, versioned list of standard credential locations under the
    # home directory (cloud SDK files, package-registry tokens, git and gh).
    STANDARD_LOCATION = "standard_location"
    # Project files: imported gitleaks or trufflehog results plus Weir's own
    # catalog and assignment detectors run over the project tree.
    PROJECT_SCAN = "project_scan"
    # The agent's launch environment, plus the shell startup files that
    # re-export a variable into it.
    ENVIRONMENT = "environment"
    # The approved map, <project>/.weir/reach.yml.
    MAP = "map"


class Reason(enum.StrEnum):
    """Why a record counts as a credential."""

    LOCATION = "location"  # a credential field of a standard credential file
    NAME = "name"  # the field or variable name suggests a secret
    SHAPE = "shape"  # a local check of the value's shape says so
    SCANNER = "scanner"  # an imported gitleaks or trufflehog result
    MAP = "map"  # a person approved it into .weir/reach.yml


class ValueState(enum.StrEnum):
    """Whether weir holds the value in memory for this record."""

    # The value was read; it is in `KnownValues` and its keyed fingerprint is
    # in the store. Nothing about it is in this report.
    LITERAL = "literal"
    # The assignment is a shell expansion or command substitution
    # (`export TOKEN=$(pass show x)`): a credential by name, value unknown.
    DYNAMIC = "dynamic"
    # A whole-file credential whose value is not extracted: a binary token
    # database, or a file a person approved into the map with no field.
    ABSENT = "absent"


class LocationKind(enum.StrEnum):
    FILE = "file"
    LAUNCH_ENV = "launch_env"


class Location(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    kind: LocationKind
    # How the location is written for a person and for Claude Code rules:
    # `~/.aws/credentials` under the home, `./.env` under the project, an
    # absolute path elsewhere, `launch env` for the launch environment.
    # Always forward slashes.
    display: str
    # Absolute path, forward slashes. None for the launch environment when
    # it came from the running process rather than an env file.
    path: str | None = None
    # 1-based line of the first occurrence, when the format has lines.
    line: int | None = None
    # A scanner result from git history names the commit it was found in.
    commit: str | None = None


class Credential(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    # Stable identifier: 16 base32 characters of a digest over the record's
    # non-secret identity (source, display location, line, name, scope,
    # commit), never over the value. Joins this record to its StoredRecord
    # and to KnownValues.
    id: str
    # Credential name: the field or variable name (`aws_secret_access_key`,
    # `ACME_API_KEY`), the catalog class (`github_token`) or the scanner rule
    # (`gitleaks:github-pat`). Flattened to one printable line.
    name: str
    source: Source
    reason: Reason
    location: Location
    value_state: ValueState
    # Every detector that found this record, sorted (`location:aws`,
    # `catalog:github_token`, `assignment`, `gitleaks:generic-api-key`, ...).
    detectors: list[str]
    # Profile, section, host or server the field belongs to (`default`,
    # `github.com`, `mcpServers.acme-search.env`). None when the format has none.
    scope: str | None = None
    # True when a .gitignore rule covers the file. Ignoring a file is NOT
    # coverage: see `Inventory.git_ignored`.
    git_ignored: bool = False


class EnvVarName(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """An environment variable by NAME only: an unknown, or one marked fine."""

    name: str
    location: Location


class RouteStatus(enum.StrEnum):
    HIDDEN = "hidden"
    REACHABLE = "reachable"


class Route(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    # `grep_tool`, `read_tool`, `cat`, `grep_r`
    route: str
    status: RouteStatus
    note: str


class GitIgnoredFile(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """A project file holding a credential that .gitignore covers. Ignored
    files are not protected; this reports what ignoring does per route."""

    display: str
    path: str
    routes: list[Route]


class NotScannedReason(enum.StrEnum):
    BINARY = "binary"
    TOO_LARGE = "too_large"
    UNREADABLE = "unreadable"
    UNDECODABLE = "undecodable"  # a standard file whose format did not parse
    VENDORED_DIR = "vendored_dir"  # a dependency directory, skipped whole
    MISSING = "missing"  # a map entry or scanner result names a file that is not there


class NotScanned(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Something the inventory did not read, stated rather than hidden."""

    display: str
    reason: NotScannedReason
    path: str | None = None


class EnvSource(enum.StrEnum):
    FILE = "file"  # --env-file
    PROCESS = "process"  # --process-env: the running process's environment
    NONE = "none"  # not given: only shell startup files were read


class Inputs(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    home: str
    project: str
    env_source: EnvSource
    env_file: str | None
    gitleaks_reports: list[str]
    trufflehog_reports: list[str]
    # <project>/.weir/reach.yml when it exists, else None.
    map_file: str | None
    location_list_version: int


class Counts(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    credentials: int
    standard_location: int
    project_scan: int
    environment: int
    map: int
    env_not_secret: int
    env_unknown: int
    env_fine: int
    git_ignored_files: int
    not_scanned: int


class Inventory(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """The value-free inventory report: `weir inventory --json` emits exactly
    this, and `take_inventory()` returns it as `InventoryResult.report`."""

    schema: str
    inputs: Inputs
    counts: Counts
    # Sorted by (source, location display, line, name, scope).
    credentials: list[Credential]
    # Unknown environment variables, names only, sorted. On screen they are
    # a count; the full list goes to a file.
    env_unknown: list[EnvVarName]
    # Variables the map marks fine (`env: {fine: [...]}`) that were present.
    env_fine: list[EnvVarName]
    git_ignored: list[GitIgnoredFile]
    not_scanned: list[NotScanned]


class StoredRecord(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """What the inventory may store about one value: a keyed fingerprint
    (HMAC-SHA256 under the local key) plus where the value sits. No value,
    no fragment, no unkeyed hash."""

    credential_id: str
    fingerprint: str  # lowercase hex HMAC-SHA256
    fingerprint_v: int
    # Absolute path the offsets index into; None for the process environment.
    path: str | None
    # [start, end) byte offsets of each occurrence in that file. Empty when
    # the value's position is not known (a scanner result whose file moved).
    offsets: list[tuple[int, int]]


class Store(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: str
    records: list[StoredRecord]


def inventory_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for `Inventory` (weir-inventory/1)."""
    return msgspec.json.schema(Inventory)


def store_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for `Store` (weir-inventory-store/1)."""
    return msgspec.json.schema(Store)
