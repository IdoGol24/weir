"""Canary ledger (canary-ledger/1), request capture (canary-requests/1) and
report (canary-report/1) records.

The contract for all three is docs/canary.md. The JSON Schema artifacts in
packages/weir/schema_artifacts/ (canary-ledger.v1, canary-requests.v1,
canary-report.v1) are generated from these structs and drift-tested.

Every report struct is VALUE-FREE by construction: no field can hold a
canary value, a fragment of one, a masked form, a hash or a fingerprint.
Only the ledger's `Placement.value` and a request record hold a value, and
both are input.
"""

from __future__ import annotations

import enum
from typing import Annotated, Literal

import msgspec

LEDGER_SCHEMA = "canary-ledger/1"
REQUESTS_SCHEMA = "canary-requests/1"
REPORT_SCHEMA = "canary-report/1"

# An id is printed in both reports, so it is restricted to characters that
# can neither break a line nor quote anything. The no-value rule (no run of
# RUN consecutive characters of any ledger value) is checked across the
# whole ledger, so it is not expressible here.
ID_PATTERN = "^[A-Za-z0-9._:#/-]{1,128}$"
ENDPOINT_PATTERN = "^[A-Za-z0-9_-]{1,40}$"
HOST_PATTERN = "^[A-Za-z0-9._:-]{1,253}$"
MIN_VALUE_LENGTH = 16
# docs/canary.md: nothing printed holds a run of this many consecutive
# characters of any ledger value.
RUN = 6

Id = Annotated[str, msgspec.Meta(min_length=1, max_length=128, pattern=ID_PATTERN)]
EndpointId = Annotated[str, msgspec.Meta(min_length=1, max_length=40, pattern=ENDPOINT_PATTERN)]
Host = Annotated[str, msgspec.Meta(min_length=1, max_length=253, pattern=HOST_PATTERN)]

Kind = Literal["env", "code", "mock-oauth"]
Evidence = Literal["request", "minted", "egress"]
FlowStatus = Literal["ok", "failed", "timeout", "skipped"]
DirectProtocol = Literal["tcp", "udp", "dns"]

# A direct record's target: an address and port, or a DNS name. The runner
# writes only these characters, so a target can neither break a line nor
# quote anything; the judge still prints it under the capture-text rule.
TARGET_PATTERN = r"^[A-Za-z0-9._:\[\]-]{1,260}$"
Target = Annotated[str, msgspec.Meta(min_length=1, max_length=260, pattern=TARGET_PATTERN)]


class LedgerHeader(msgspec.Struct, forbid_unknown_fields=True):
    """The first line of every ledger."""

    schema: Literal["canary-ledger/1"]


class Placement(msgspec.Struct, tag_field="type", tag="placement", forbid_unknown_fields=True):
    """One place a credential can live, holding one fake value."""

    id: Id
    kind: Kind
    value: Annotated[str, msgspec.Meta(min_length=MIN_VALUE_LENGTH)]
    required: bool = False
    # Its own provider (docs/canary.md, "A placement's own provider").
    providers: list[EndpointId] = []
    provider_host: Host | None = None


class Exercised(msgspec.Struct, tag_field="type", tag="exercised", forbid_unknown_fields=True):
    placement: Id
    evidence: Evidence


class Flow(msgspec.Struct, tag_field="type", tag="flow", forbid_unknown_fields=True):
    id: Id
    status: FlowStatus


class Unexpected(msgspec.Struct, tag_field="type", tag="unexpected", forbid_unknown_fields=True):
    """A credential field the mock received that held no needle. Never a value."""

    id: Id


class Network(msgspec.Struct, tag_field="type", tag="network", forbid_unknown_fields=True):
    """Whether the flows ran with no route out but loopback. At most one."""

    isolated: bool
    required: bool = False


class Direct(msgspec.Struct, tag_field="type", tag="direct", forbid_unknown_fields=True):
    """A connection a flow tried to open around the mock, blocked by
    isolation. Never content: a protocol, a target and a count."""

    flow: Id
    protocol: DirectProtocol
    target: Target
    attempts: Annotated[int, msgspec.Meta(ge=1)]


LedgerRecord = Placement | Exercised | Flow | Unexpected | Network | Direct
RECORD_TYPES: tuple[type[LedgerRecord], ...] = (
    Placement,
    Exercised,
    Flow,
    Unexpected,
    Network,
    Direct,
)


class RequestsHeader(msgspec.Struct, forbid_unknown_fields=True):
    """The first line of every request capture file."""

    schema: Literal["canary-requests/1"]


class Request(msgspec.Struct, forbid_unknown_fields=True):
    """One request the mock received (docs/canary.md, "The request capture").

    Every field is required: a record that leaves one out is not a request
    record, so the judge cannot attribute it.
    """

    outcome: Literal["served", "refused", "connect"]
    endpoint: EndpointId | None
    host: str
    port: Annotated[int, msgspec.Meta(ge=0, le=65535)]
    method: str
    path: str | None
    query: str | None
    headers: list[tuple[str, str]]
    body: str | None
    unread: Literal["encoding", "too_large", "error"] | None


class Ledger(msgspec.Struct, frozen=True):
    """A parsed, validated ledger. Record order is ledger line order."""

    placements: tuple[Placement, ...]
    exercised: tuple[Exercised, ...]
    flows: tuple[Flow, ...]
    unexpected: tuple[Unexpected, ...]
    # None when the ledger has no network record: nothing says the flows
    # were isolated, so they were not.
    network: Network | None
    direct: tuple[Direct, ...]


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
    REQUESTS = "requests"
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


class BlockedKind(enum.StrEnum):
    CONNECTION = "connection"
    REQUEST = "request"


class IncompleteReason(enum.StrEnum):
    REQUIRED_NOT_EXERCISED = "required_not_exercised"
    FLOW_NOT_OK = "flow_not_ok"
    UNEXPECTED_CREDENTIAL = "unexpected_credential"
    NOT_SCANNED = "not_scanned"
    UNPARSED_RECORD = "unparsed_record"
    EMPTY_CAPTURE = "empty_capture"
    NETWORK_NOT_ISOLATED = "network_not_isolated"
    DIRECT_CONNECTION = "direct_connection"


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
    sink: str | None
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


class Blocked(msgspec.Struct, frozen=True):
    """A destination the mock refused, by kind; never a leak by itself."""

    kind: BlockedKind
    host: str
    port: int
    count: int


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
    request_files: int
    requests: int
    requests_refused: int
    connections_blocked: int


class DirectEntry(msgspec.Struct, frozen=True):
    flow: str
    protocol: str
    target: str
    attempts: int


class NetworkState(msgspec.Struct, frozen=True):
    isolated: bool
    required: bool
    direct: list[DirectEntry]


class Report(msgspec.Struct, frozen=True):
    """canary-report/1: what `weir canary judge --json` prints."""

    schema: Literal["canary-report/1"]
    result: Result
    exit_code: int
    hits: list[Hit]
    placements: list[PlacementState]
    flows: list[FlowState]
    not_scanned: list[NotScanned]
    blocked: list[Blocked]
    incomplete: list[Incomplete]
    coverage: Coverage
    network: NetworkState


def ledger_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for one ledger line (canary-ledger/1).

    A line is the header or one record; which one is fixed by position (the
    header is line 1), so the schema accepts any of them.
    """
    (header_ref, record_ref), components = msgspec.json.schema_components(
        [LedgerHeader, LedgerRecord]
    )
    return {"$defs": components, "anyOf": [header_ref, record_ref]}


def requests_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for one request capture line
    (canary-requests/1): the header or one request record."""
    (header_ref, record_ref), components = msgspec.json.schema_components([RequestsHeader, Request])
    return {"$defs": components, "anyOf": [header_ref, record_ref]}


def report_json_schema() -> dict[str, object]:
    """The committed JSON Schema artifact for `Report` (canary-report/1)."""
    return msgspec.json.schema(Report)
