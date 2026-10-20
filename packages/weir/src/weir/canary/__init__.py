"""The canary judge: `weir canary judge` (docs/canary.md).

A canary check plants unique fake credentials, runs a program's flows with
its telemetry captured, and asks whether any planted value reached the
capture. This package is the judge half only: it reads a ledger and capture
files and reports placement ids and locations, never a value. It opens no
socket and starts no process; the runner that plants, mocks and captures is
a separate package that weir never imports.
"""

from weir.canary._types import (
    EXIT_CODES,
    LEDGER_SCHEMA,
    REPORT_SCHEMA,
    Coverage,
    Exercised,
    Flow,
    FlowState,
    Form,
    Hit,
    Incomplete,
    IncompleteReason,
    Ledger,
    LedgerHeader,
    NotScanned,
    NotScannedReason,
    Placement,
    PlacementState,
    Report,
    Result,
    Signal,
    State,
    Unexpected,
    ledger_json_schema,
    report_json_schema,
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
    "CaptureError",
    "CaptureFile",
    "Coverage",
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
    "NotScanned",
    "NotScannedReason",
    "Placement",
    "PlacementState",
    "Report",
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
]
