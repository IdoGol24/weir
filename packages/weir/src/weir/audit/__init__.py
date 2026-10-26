"""The credential audit: `weir audit` (docs/audit.md).

Given the inventory's keyed fingerprints of a person's own credentials, it
reads saved agent session files and exported telemetry and reports which
credentials entered the agent's context and which were sent out in a tool
call, by inventory name, never by value. It reads only the files it is
given: no socket, no process, no clock, no randomness.
"""

from weir.audit._types import (
    AUDIT_SCHEMA,
    EXIT_CODES,
    Coverage,
    CredentialResult,
    FileResult,
    Format,
    Hit,
    Kind,
    Report,
    Result,
    State,
    Unknown,
    UnknownReason,
    report_json_schema,
)
from weir.audit.audit import (
    audit_chunks,
    audit_files,
    audit_naming,
    audit_paths,
    encode_report,
)
from weir.audit.inputs import AuditInputError, Inputs, load_inputs
from weir.audit.text import report_lines

__all__ = [
    "AUDIT_SCHEMA",
    "EXIT_CODES",
    "AuditInputError",
    "Coverage",
    "CredentialResult",
    "FileResult",
    "Format",
    "Inputs",
    "Hit",
    "Kind",
    "Report",
    "Result",
    "State",
    "Unknown",
    "UnknownReason",
    "audit_chunks",
    "audit_files",
    "audit_naming",
    "audit_paths",
    "encode_report",
    "load_inputs",
    "report_json_schema",
    "report_lines",
]
