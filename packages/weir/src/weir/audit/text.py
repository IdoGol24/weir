"""The `weir audit` text report (docs/audit.md, "The text report").

Every string here was already printed under the printing rule when the
report was built, so this module only lays lines out.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from weir._text_safety import plural
from weir.audit._types import CredentialResult, Format, Hit, Report, State

_FORMATS = (
    (Format.CLAUDE_CODE, "claude_code_files"),
    (Format.CLAUDE_CODE_TOOL_RESULTS, "claude_code_tool_results_files"),
    (Format.OTLP, "otlp_files"),
    (Format.UNKNOWN, "unknown_files"),
)


def _quote(name: str) -> str:
    return json.dumps(name, ensure_ascii=False)


def label(credential: CredentialResult) -> str:
    where = credential.display if credential.scope is None else (
        f"{credential.display} {credential.scope}"
    )
    return f"{credential.name} ({where})"


def hit_line(hit: Hit, credential: str) -> str:
    parts = [hit.kind.value.upper(), credential, f"file={hit.file}:{hit.line}"]
    if hit.record is not None:
        parts.append(f"record={hit.record}")
    elif hit.signal is not None:
        parts.append(f"signal={hit.signal.value}")
        if hit.span is not None:
            parts.append(f"span={_quote(hit.span)}")
        if hit.log_record is not None:
            parts.append(f"log={hit.log_record}")
        if hit.metric is not None:
            parts.append(f"metric={_quote(hit.metric)}")
    else:
        parts.append(f"format={hit.format.value}")
    if hit.tool is not None:
        parts.append(f"tool={_quote(hit.tool)}")
    if hit.argument is not None:
        parts.append(f"argument={hit.argument}")
    if hit.location is not None:
        parts.append(f"at={hit.location}")
    parts.append(f"form={hit.form.value}")
    return " ".join(parts)


def _summary(credential: CredentialResult) -> str:
    calls = "tool call" if credential.tool_call == 1 else "tool calls"
    return (
        f"{label(credential)}: {credential.state.value} ({credential.tool_call} {calls},"
        f" {credential.context} context, {credential.stored} stored,"
        f" {credential.unknown} unknown)"
    )


def report_lines(report: Report) -> Iterator[str]:
    labels = {c.id: label(c) for c in report.credentials}
    for hit in report.hits:
        yield hit_line(hit, labels[hit.credential])
    for credential in report.credentials:
        if credential.tool_call or credential.context or credential.stored or credential.unknown:
            yield _summary(credential)
    for credential in report.credentials:
        if credential.state is State.NOT_FOUND:
            yield f"not found: {labels[credential.id]}"
    for credential in report.credentials:
        if credential.state is State.NOT_CHECKABLE:
            yield f"not checkable: {labels[credential.id]} {credential.value_state}"
    for file in report.files:
        if file.not_scanned is not None:
            yield f"not scanned: {file.file} ({file.not_scanned.value})"
    for unknown in report.unknown:
        yield f"unknown: {unknown.reason.value} {unknown.subject}"
    c = report.coverage
    formats = ", ".join(
        f"{getattr(c, field)} {fmt.value}" for fmt, field in _FORMATS if getattr(c, field)
    )
    yield (
        f"coverage: {plural(c.credentials, 'credential')} ({c.checkable} checkable),"
        f" {plural(c.files, 'file')} ({formats}),"
        f" {plural(c.records, 'record')} ({c.unrecognised_records} unrecognised),"
        f" {plural(c.unparsed_lines, 'unparsed line')}, {c.not_scanned} not scanned,"
        f" {plural(c.strings, 'string')}"
    )
    yield f"result: {report.result.value}"
