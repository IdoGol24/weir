"""The `weir-audit/1` report (docs/audit.md, "The JSON report").

The JSON Schema artifact packages/weir/schema_artifacts/audit.v1.schema.json
is generated from these structs and drift-tested.

Every struct is VALUE-FREE by construction: no field can hold a credential
value, a fragment of one, a masked form, a hash or a fingerprint. Credentials
are named by their inventory id, name, location display and scope.
"""

from __future__ import annotations

import enum

import msgspec

from weir.canary import Form, Signal

AUDIT_SCHEMA = "weir-audit/1"

__all__ = [
    "AUDIT_SCHEMA",
    "Coverage",
    "CredentialResult",
    "FileResult",
    "Form",
    "Format",
    "Hit",
    "Kind",
    "NotScannedReason",
    "Report",
    "Result",
    "Signal",
    "State",
    "Unknown",
    "UnknownReason",
]


class Kind(enum.Enum):
    """What a hit means (docs/audit.md, "What a hit means"). Declared most
    severe first: hits sort in this order."""

    TOOL_CALL = "tool_call"
    CONTEXT = "context"
    UNKNOWN = "unknown"
    STORED = "stored"


class Format(enum.Enum):
    """A file's format (docs/audit.md, "Files and formats"), in report order."""

    CLAUDE_CODE = "claude-code"
    CLAUDE_CODE_TOOL_RESULTS = "claude-code-tool-results"
    CLAUDE_CODE_MEMORY = "claude-code-memory"
    CLAUDE_CODE_SUBAGENT_META = "claude-code-subagent-meta"
    OTLP = "otlp"
    UNKNOWN = "unknown"


class State(enum.Enum):
    """A credential's state, in precedence order (docs/audit.md)."""

    NOT_CHECKABLE = "not_checkable"
    IN_TOOL_CALL = "in_tool_call"
    IN_CONTEXT = "in_context"
    UNKNOWN = "unknown"
    STORED = "stored"
    NOT_FOUND = "not_found"


class Result(enum.Enum):
    CLEAN = "clean"
    EXPOSED = "exposed"
    UNKNOWN = "unknown"


class UnknownReason(enum.Enum):
    """Why the audit is incomplete, in report order."""

    NO_FILES_READ = "no_files_read"
    UNRECOGNISED_FORMAT = "unrecognised_format"
    UNPARSED_LINE = "unparsed_line"
    NOT_SCANNED = "not_scanned"
    UNKNOWN_KIND = "unknown_kind"


class NotScannedReason(enum.Enum):
    """Why a file was not scanned (docs/audit.md, "Running it")."""

    COMPRESSED = "compressed"
    SYMLINK = "symlink"
    MISSING = "missing"


EXIT_CODES = {Result.CLEAN: 0, Result.EXPOSED: 1, Result.UNKNOWN: 3}


class CredentialResult(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: str
    name: str
    source: str
    display: str
    scope: str | None
    value_state: str
    state: State
    tool_call: int
    context: int
    stored: int
    unknown: int


class Hit(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    credential: str
    kind: Kind
    file: str
    line: int
    format: Format
    record: str | None
    signal: Signal | None
    span: str | None
    span_id: str | None
    log_record: int | None
    metric: str | None
    tool: str | None
    argument: str | None
    location: str | None
    form: Form


class FileResult(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    file: str
    format: Format | None
    records: int
    unrecognised_records: int
    unparsed_lines: int
    strings: int
    bytes: int
    not_scanned: NotScannedReason | None


class Unknown(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    reason: UnknownReason
    # None for `no_files_read`, which is about the whole audit
    subject: str | None


class Coverage(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    credentials: int
    checkable: int
    not_checkable: int
    files: int
    claude_code_files: int
    claude_code_tool_results_files: int
    claude_code_memory_files: int
    claude_code_subagent_meta_files: int
    otlp_files: int
    unknown_files: int
    not_scanned: int
    records: int
    unrecognised_records: int
    unparsed_lines: int
    strings: int
    bytes: int


class Report(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: str
    result: Result
    exit_code: int
    credentials: list[CredentialResult]
    hits: list[Hit]
    files: list[FileResult]
    unknown: list[Unknown]
    coverage: Coverage


def report_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for `Report` (weir-audit/1)."""
    return msgspec.json.schema(Report)
