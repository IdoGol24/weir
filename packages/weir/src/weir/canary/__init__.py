"""The canary judge: `weir canary judge` (docs/canary.md).

A canary check plants unique fake credentials, runs a program's flows with
its telemetry and outbound requests captured, and asks whether any planted
value reached a place outside the user's control. This package is the judge
half only: it reads a ledger and capture files and reports placement ids,
locations and sinks, never a value. It opens no
socket and starts no process; the runner that plants, mocks and captures is
a separate package that weir never imports.
"""

from weir.canary._types import (
    EXIT_CODES,
    LEDGER_SCHEMA,
    REPORT_SCHEMA,
    REQUESTS_SCHEMA,
    Blocked,
    BlockedKind,
    Coverage,
    Direct,
    DirectEntry,
    Exercised,
    Flow,
    FlowState,
    Form,
    Hit,
    Incomplete,
    IncompleteReason,
    Ledger,
    LedgerHeader,
    Network,
    NetworkState,
    NotScanned,
    NotScannedReason,
    Placement,
    PlacementState,
    Report,
    Request,
    RequestsHeader,
    Result,
    Signal,
    State,
    Unexpected,
    ledger_json_schema,
    report_json_schema,
    requests_json_schema,
)
from weir.canary.capture import CaptureError, CaptureFile, Role, collect_capture
from weir.canary.forms import needles
from weir.canary.judge import encode_report, judge_capture, judge_paths, ledger_display
from weir.canary.ledger import LedgerError, parse_ledger, read_ledger
from weir.canary.text import report_lines

__all__ = [
    "EXIT_CODES",
    "LEDGER_SCHEMA",
    "REPORT_SCHEMA",
    "REQUESTS_SCHEMA",
    "Blocked",
    "BlockedKind",
    "CaptureError",
    "CaptureFile",
    "Coverage",
    "Direct",
    "DirectEntry",
    "Exercised",
    "Flow",
    "FlowState",
    "Form",
    "Hit",
    "Incomplete",
    "IncompleteReason",
    "Ledger",
    "LedgerError",
    "LedgerHeader",
    "Network",
    "NetworkState",
    "NotScanned",
    "NotScannedReason",
    "Placement",
    "PlacementState",
    "Report",
    "Request",
    "RequestsHeader",
    "Result",
    "Role",
    "Signal",
    "State",
    "Unexpected",
    "collect_capture",
    "encode_report",
    "judge_capture",
    "judge_paths",
    "ledger_display",
    "ledger_json_schema",
    "needles",
    "parse_ledger",
    "read_ledger",
    "report_json_schema",
    "report_lines",
    "requests_json_schema",
]
