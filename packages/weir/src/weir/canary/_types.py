"""Canary ledger (canary-ledger/1) and report (canary-report/1) records.

The contract for both is docs/canary.md. The JSON Schema artifacts in
packages/weir/schema_artifacts/ (canary-ledger.v1, canary-report.v1) are
generated from these structs and drift-tested.

Every report struct is VALUE-FREE by construction: no field can hold a
canary value, a fragment of one, a masked form, a hash or a fingerprint.
Only the ledger's `Placement.value` holds a value, and the ledger is input.
"""

from __future__ import annotations

import enum
from typing import Annotated, Literal

import msgspec

LEDGER_SCHEMA = "canary-ledger/1"
REPORT_SCHEMA = "canary-report/1"

# An id is printed in both reports, so it is restricted to characters that
# can neither break a line nor quote anything. The no-value rule (no run of 8
# consecutive characters of any ledger value) is checked across the whole
# ledger, so it is not expressible here.
ID_PATTERN = "^[A-Za-z0-9._:#/-]{1,128}$"
MIN_VALUE_LENGTH = 16

Id = Annotated[str, msgspec.Meta(min_length=1, max_length=128, pattern=ID_PATTERN)]

Kind = Literal["env", "code", "mock-oauth"]
Evidence = Literal["request", "minted", "egress"]
FlowStatus = Literal["ok", "failed", "timeout", "skipped"]


class LedgerHeader(msgspec.Struct, forbid_unknown_fields=True):
    """The first line of every ledger."""

    schema: Literal["canary-ledger/1"]


class Placement(msgspec.Struct, tag_field="type", tag="placement", forbid_unknown_fields=True):
    """One place a credential can live, holding one fake value."""

    id: Id
    kind: Kind
    value: Annotated[str, msgspec.Meta(min_length=MIN_VALUE_LENGTH)]
    required: bool = False


class Exercised(msgspec.Struct, tag_field="type", tag="exercised", forbid_unknown_fields=True):
    placement: Id
    evidence: Evidence


class Flow(msgspec.Struct, tag_field="type", tag="flow", forbid_unknown_fields=True):
    id: Id
    status: FlowStatus


class Unexpected(msgspec.Struct, tag_field="type", tag="unexpected", forbid_unknown_fields=True):
    """A credential field the mock received that held no needle. Never a value."""

    id: Id


LedgerRecord = Placement | Exercised | Flow | Unexpected
RECORD_TYPES: tuple[type[LedgerRecord], ...] = (Placement, Exercised, Flow, Unexpected)


class Ledger(msgspec.Struct, frozen=True):
    """A parsed, validated ledger. Record order is ledger line order."""

    placements: tuple[Placement, ...]
    exercised: tuple[Exercised, ...]
    flows: tuple[Flow, ...]
    unexpected: tuple[Unexpected, ...]


class Form(enum.StrEnum):
    """The encoded forms, in the contract's table order (docs/canary.md)."""

    RAW = "raw"
    JSON = "json"
    JSON2 = "json2"
    URL = "url"
    BASE64 = "base64"
    BASE64URL = "base64url"
    HEX = "hex"


class Signal(enum.StrEnum):
    TRACES = "traces"
    LOGS = "logs"
    METRICS = "metrics"
    RAW = "raw"


class State(enum.StrEnum):
    LEAKED = "leaked"
    EXERCISED = "exercised"
    NOT_EXERCISED = "not_exercised"


class Result(enum.StrEnum):
    CLEAN = "clean"
    LEAK = "leak"
    INCOMPLETE = "incomplete"


# docs/canary.md "Exit codes": 2 is unusable input and carries no report.
EXIT_CODES: dict[Result, int] = {Result.CLEAN: 0, Result.LEAK: 1, Result.INCOMPLETE: 3}


class NotScannedReason(enum.StrEnum):
    COMPRESSED = "compressed"
    SYMLINK = "symlink"


class IncompleteReason(enum.StrEnum):
    REQUIRED_NOT_EXERCISED = "required_not_exercised"
    FLOW_NOT_OK = "flow_not_ok"
    UNEXPECTED_CREDENTIAL = "unexpected_credential"
    NOT_SCANNED = "not_scanned"
    UNPARSED_RECORD = "unparsed_record"
    EMPTY_CAPTURE = "empty_capture"


class Hit(msgspec.Struct, frozen=True):
    placement: str
    kind: str
    file: str
    line: int
    signal: Signal
    span: str | None
    span_id: str | None
    log_record: int | None
    metric: str | None
    location: str | None
    form: Form


class PlacementState(msgspec.Struct, frozen=True):
    id: str
    kind: str
    required: bool
    state: State
    evidence: list[str]
    hits: int


class FlowState(msgspec.Struct, frozen=True):
    id: str
    status: str


class NotScanned(msgspec.Struct, frozen=True):
    file: str
    reason: NotScannedReason


class Incomplete(msgspec.Struct, frozen=True):
    reason: IncompleteReason
    subject: str | None


class Coverage(msgspec.Struct, frozen=True):
    placements: int
    leaked: int
    exercised: int
    not_exercised: int
    required: int
    flows: int
    flows_ok: int
    files: int
    files_not_scanned: int
    spans: int
    log_records: int
    metric_data_points: int
    unparsed_records: int
    strings: int
    bytes: int


class Report(msgspec.Struct, frozen=True):
    """canary-report/1: what `weir canary judge --json` prints."""

    schema: Literal["canary-report/1"]
    result: Result
    exit_code: int
    hits: list[Hit]
    placements: list[PlacementState]
    flows: list[FlowState]
    not_scanned: list[NotScanned]
    incomplete: list[Incomplete]
    coverage: Coverage


def ledger_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for one ledger line (canary-ledger/1).

    A line is the header or one record; which one is fixed by position (the
    header is line 1), so the schema accepts any of them.
    """
    (header_ref, record_ref), components = msgspec.json.schema_components(
        [LedgerHeader, LedgerRecord]
    )
    return {"$defs": components, "anyOf": [header_ref, record_ref]}


def report_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for `Report` (canary-report/1)."""
    return msgspec.json.schema(Report)
