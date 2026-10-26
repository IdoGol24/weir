"""`weir audit`: which of a person's credentials reached a coding agent
(docs/audit.md).

Reads the inventory's report, store and key, then every file given, and
returns a value-free report. Pure: no socket, no process, no clock, no
randomness, and no environment variable of its own: the command line hands
in `CLAUDE_CONFIG_DIR`. The same inputs, flags and `CLAUDE_CONFIG_DIR` give
the same report.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePath

import msgspec

from weir._text_safety import flatten_untrusted
from weir.audit._types import (
    AUDIT_SCHEMA,
    EXIT_CODES,
    Coverage,
    CredentialResult,
    FileResult,
    Format,
    Hit,
    Kind,
    NotScannedReason,
    Report,
    Result,
    State,
    Unknown,
    UnknownReason,
)
from weir.audit.formats import (
    Line,
    Place,
    Site,
    attachments,
    claude_code_sites,
    is_otlp,
    json_lines,
    note_tools,
    otlp_sites,
    recognise,
    recognised,
    subagent_meta_sites,
    text_sites,
    unparsed_sites,
    whole_json,
    whole_otlp,
)
from weir.audit.inputs import AuditInputError, Credential, Inputs, load_inputs
from weir.audit.matching import Matcher
from weir.canary import CaptureError, Form, collect_capture, needles
from weir.canary.capture import CaptureFile, Role
from weir.canary.text import WITHHELD, Display
from weir.canary.walk import Segment
from weir.inventory.classify import looks_secret_shaped

_FORM_ORDER = {form: index for index, form in enumerate(Form)}
_KIND_ORDER = {kind: index for index, kind in enumerate(Kind)}
_REASON_ORDER = {reason: index for index, reason in enumerate(UnknownReason)}
_UNKNOWN = Place(Kind.UNKNOWN)
_STORED = Place(Kind.STORED)
_CONTEXT = Place(Kind.CONTEXT)


@dataclass(frozen=True)
class _Found:
    """A hit before printing: its strings still as read from the file."""

    credentials: tuple[str, ...]
    file: str
    line: int
    format: Format
    site: Site
    form: Form


@dataclass
class _File:
    path: str
    format: Format | None
    size: int
    records: int = 0
    unrecognised: int = 0
    unparsed: list[int] = field(default_factory=list[int])
    # Lines with a document whose text is in streams no value can be matched in
    encoded: list[int] = field(default_factory=list[int])
    strings: int = 0


class _Auditor:
    def __init__(self, matcher: Matcher, by_fingerprint: dict[bytes, tuple[str, ...]]) -> None:
        self.matcher = matcher
        self.by_fingerprint = by_fingerprint
        self.found: list[_Found] = []

    def search(self, file: _File, line: int, site: Site) -> None:
        file.strings += 1
        for fp, form in self.matcher.find(site.string).items():
            fmt = file.format or Format.UNKNOWN
            self.found.append(_Found(self.by_fingerprint[fp], file.path, line, fmt, site, form))

    def claude_code(self, file: _File, lines: list[Line]) -> None:
        tools: dict[str, str] = {}
        for line in lines:
            if line.parsed is None:
                self._unparsed(file, line)
                continue
            file.records += 1
            if not recognised(line.parsed):
                file.unrecognised += 1
            attached = attachments(line.parsed)
            if attached.encoded:
                file.encoded.append(line.number)
            for site in claude_code_sites(line.parsed, tools, attached):
                self.search(file, line.number, site)
            note_tools(line.parsed, tools)

    def otlp(self, file: _File, data: bytes, lines: list[Line]) -> None:
        whole = whole_otlp(data, lines)
        if whole is not None:
            file.records += 1
            for site in otlp_sites(whole):
                self.search(file, 1, site)
            return
        for line in lines:
            if not is_otlp(line.parsed):
                self._unparsed(file, line)
                continue
            assert line.parsed is not None
            file.records += 1
            for site in otlp_sites(line.parsed):
                self.search(file, line.number, site)

    def _unparsed(self, file: _File, line: Line) -> None:
        file.unparsed.append(line.number)
        for site in unparsed_sites(line, _UNKNOWN):
            self.search(file, line.number, site)

    def text(self, file: _File, data: bytes, place: Place) -> None:
        for number, site in text_sites(data.decode("utf-8", "surrogateescape"), place):
            self.search(file, number, site)

    def subagent_meta(self, file: _File, data: bytes, lines: list[Line]) -> None:
        meta = whole_json(data)
        if meta is None:
            for line in lines:
                self._unparsed(file, line)
            return
        file.records += 1
        for site in subagent_meta_sites(meta):
            self.search(file, 1, site)

    def unknown(self, file: _File, lines: list[Line]) -> None:
        for line in lines:
            for site in unparsed_sites(line, _UNKNOWN):
                self.search(file, line.number, site)


class _Printer:
    """docs/audit.md, "Printing": every input-derived string. A name, a
    location segment or a tool is cut to 200 characters; a file path is
    never cut, since a report must name its file."""

    def __init__(self, found_values: set[str]) -> None:
        self._display = Display(
            [needle for value in found_values for needle, _ in needles(value)], found_values
        )

    def __call__(self, text: str) -> str:
        out = self._display(text)
        if out != WITHHELD and looks_secret_shaped(text):
            return WITHHELD
        return out

    def path(self, text: str) -> str:
        return self._path(text, [text])

    def named(self, text: str) -> str:
        """`path` for a folder or file named beside the report, but a key's
        shape is looked for in each segment: an ordinary folder's segments
        joined can read as a long random run."""
        return self._path(text, re.split(r"[\\/]", text))

    def _path(self, text: str, parts: Sequence[str]) -> str:
        flat = flatten_untrusted(text)
        if self._display.holds_value(text) or self._display.holds_value(flat):
            return WITHHELD
        return WITHHELD if any(looks_secret_shaped(part) for part in parts) else flat


def _location(segments: Sequence[Segment], shown: Callable[[str], str]) -> str:
    out = ""
    for segment in segments:
        if isinstance(segment, int):
            out += f"[{segment}]"
        else:
            out += ("." if out else "") + shown(segment)
    return out


def _hit(found: _Found, credential: str, shown: _Printer) -> Hit:
    site = found.site
    record = site.otlp
    return Hit(
        credential=credential,
        kind=site.place.kind,
        file=shown.path(found.file),
        line=found.line,
        format=found.format,
        record=None if site.record_type is None else shown(site.record_type),
        signal=site.signal,
        span=None if record is None or record.span is None else shown(record.span),
        span_id=None if record is None else record.span_id,
        log_record=None if record is None else record.log_record,
        metric=None if record is None or record.metric is None else shown(record.metric),
        tool=None if site.place.tool is None else shown(site.place.tool),
        argument=None if site.place.argument is None else _location(site.place.argument, shown),
        location=None if site.location is None else _location(site.location, shown),
        form=found.form,
    )


def _hit_order(hit: Hit, labels: dict[str, tuple[str, str, str, str]]) -> tuple[object, ...]:
    return (
        _KIND_ORDER[hit.kind], labels[hit.credential], hit.file, hit.line, hit.location or "",
        _FORM_ORDER[hit.form], hit.tool or "", hit.argument or "",
    )


def _dedupe(hits: list[Hit]) -> list[Hit]:
    """One hit per credential and place: the first form in table order."""
    best: dict[tuple[object, ...], Hit] = {}
    for hit in hits:
        key = msgspec.structs.astuple(msgspec.structs.replace(hit, form=Form.RAW))
        kept = best.get(key)
        if kept is None or _FORM_ORDER[hit.form] < _FORM_ORDER[kept.form]:
            best[key] = hit
    return list(best.values())


def _state(credential: Credential, counts: dict[Kind, int]) -> State:
    if credential.fingerprint is None:
        return State.NOT_CHECKABLE
    for kind, state in (
        (Kind.TOOL_CALL, State.IN_TOOL_CALL),
        (Kind.CONTEXT, State.IN_CONTEXT),
        (Kind.UNKNOWN, State.UNKNOWN),
        (Kind.STORED, State.STORED),
    ):
        if counts.get(kind):
            return state
    return State.NOT_FOUND


def audit_files(
    credentials: Sequence[Credential],
    key: bytes,
    by_fingerprint: dict[bytes, tuple[str, ...]],
    paths: Sequence[str],
    claude_config_dirs: Sequence[str] = (),
) -> Report:
    return audit_naming(credentials, key, by_fingerprint, paths, claude_config_dirs)[0]


def audit_naming(
    credentials: Sequence[Credential],
    key: bytes,
    by_fingerprint: dict[bytes, tuple[str, ...]],
    paths: Sequence[str],
    claude_config_dirs: Sequence[str] = (),
    named: Sequence[str] = (),
) -> tuple[Report, list[str]]:
    """`audit_files`, and each of `named`, paths the caller prints beside
    the report, as the report prints a path but with a key's shape looked
    for in each segment: checked against the store like every path, so a
    value in one is withheld in the report too."""
    # A given path that does not exist was not read: it is not scanned, and
    # never an error, so a missing sessions directory reads as unknown.
    missing = [path for path in paths if not os.path.lexists(path)]
    matcher = Matcher(key, set(by_fingerprint))

    def error_path(path: str) -> str:
        # An error names its path, never a value: a path holding a stored
        # credential is withheld before any file is read.
        return WITHHELD if matcher.path_holds_value(path) else path

    try:
        capture = collect_capture(
            [], [path for path in paths if path not in missing], error_path
        )
    except CaptureError as exc:
        raise AuditInputError(str(exc).replace("capture ", "file ", 1)) from None
    return _report(
        credentials, by_fingerprint, matcher, capture, missing, claude_config_dirs, named=named
    )


def audit_chunks(
    inputs: Inputs, chunks: Sequence[tuple[str, bytes]], claude_config_dirs: Sequence[str] = (),
    as_format: Format | None = None,
) -> Report:
    """Audit bytes already read, each (path, data) as one file, in
    `as_format` when given, else in the format its bytes are recognised as.
    `weir statusline` reads a growing session file in chunks of whole lines,
    which are records each on its own: audited in the format its start was
    recognised as, the chunks give the whole file's hits."""
    capture = [CaptureFile(path, Role.SWEPT, data) for path, data in chunks]
    matcher = Matcher(inputs.key, set(inputs.by_fingerprint))
    return _report(
        inputs.credentials, inputs.by_fingerprint, matcher, capture, [], claude_config_dirs,
        as_format,
    )[0]


def _report(
    credentials: Sequence[Credential],
    by_fingerprint: dict[bytes, tuple[str, ...]],
    matcher: Matcher,
    capture: Sequence[CaptureFile],
    missing: Sequence[str],
    claude_config_dirs: Sequence[str],
    as_format: Format | None = None,
    named: Sequence[str] = (),
) -> tuple[Report, list[str]]:
    projects_dirs = [PurePath(os.path.abspath(d), "projects") for d in claude_config_dirs]
    auditor = _Auditor(matcher, by_fingerprint)
    files: list[_File] = []
    not_scanned: dict[str, NotScannedReason] = {
        path: NotScannedReason.MISSING for path in missing
    }
    files.extend(_File(path, None, 0) for path in missing)
    for item in capture:
        if item.data is None or item.not_scanned is not None:
            files.append(_File(item.path, None, 0))
            reason = item.not_scanned.value if item.not_scanned is not None else "compressed"
            not_scanned[item.path] = NotScannedReason(reason)
            continue
        data = item.data
        lines = json_lines(data)
        fmt = as_format or recognise(item.path, data, lines, projects_dirs)
        file = _File(item.path, fmt, len(data))
        files.append(file)
        if file.format is Format.CLAUDE_CODE:
            auditor.claude_code(file, lines)
        elif file.format is Format.CLAUDE_CODE_TOOL_RESULTS:
            auditor.text(file, data, _STORED)
        elif file.format is Format.CLAUDE_CODE_MEMORY:
            auditor.text(file, data, _CONTEXT)
        elif file.format is Format.CLAUDE_CODE_SUBAGENT_META:
            auditor.subagent_meta(file, data, lines)
        elif file.format is Format.OTLP:
            auditor.otlp(file, data, lines)
        else:
            auditor.unknown(file, lines)

    # Every path the report prints is checked against the store first, so a
    # value that is only in a file name is withheld like a found one.
    for path in [*(file.path for file in files), *named]:
        matcher.path_holds_value(path)
    shown = _Printer(auditor.matcher.found)
    labels = {
        c.id: (shown(c.name), shown(c.display), shown(c.scope) if c.scope else "", c.id)
        for c in credentials
    }
    hits: list[Hit] = []
    for found in auditor.found:
        for cid in found.credentials:
            hits.append(_hit(found, cid, shown))
    hits = sorted(_dedupe(hits), key=lambda h: _hit_order(h, labels))

    counts: dict[str, dict[Kind, int]] = {}
    for hit in hits:
        per = counts.setdefault(hit.credential, {})
        per[hit.kind] = per.get(hit.kind, 0) + 1
    rows: list[CredentialResult] = []
    for c in credentials:
        per = counts.get(c.id, {})
        name, display, scope, _ = labels[c.id]
        rows.append(CredentialResult(
            id=c.id, name=name, source=c.source, display=display, scope=scope or None,
            value_state=c.value_state, state=_state(c, per),
            tool_call=per.get(Kind.TOOL_CALL, 0), context=per.get(Kind.CONTEXT, 0),
            stored=per.get(Kind.STORED, 0), unknown=per.get(Kind.UNKNOWN, 0),
        ))
    rows.sort(key=lambda r: labels[r.id])

    reasons: list[tuple[UnknownReason, str, int]] = []
    if all(file.format is None for file in files):
        reasons.append((UnknownReason.NO_FILES_READ, "", 0))
    for file in files:
        if file.format is Format.UNKNOWN:
            reasons.append((UnknownReason.UNRECOGNISED_FORMAT, shown.path(file.path), 0))
        for number in file.unparsed:
            reasons.append((UnknownReason.UNPARSED_LINE, shown.path(file.path), number))
        for number in file.encoded:
            reasons.append((UnknownReason.NOT_SCANNED, shown.path(file.path), number))
    for path in not_scanned:
        reasons.append((UnknownReason.NOT_SCANNED, shown.path(path), 0))
    for hit in hits:
        if hit.kind is Kind.UNKNOWN:
            reasons.append((UnknownReason.UNKNOWN_KIND, hit.file, hit.line))
    unknown = [
        Unknown(reason=reason, subject=f"{subject}:{line}" if line else subject or None)
        for reason, subject, line in sorted(
            set(reasons), key=lambda r: (_REASON_ORDER[r[0]], r[1], r[2])
        )
    ]

    exposed = any(r.state in (State.IN_TOOL_CALL, State.IN_CONTEXT) for r in rows)
    result = Result.EXPOSED if exposed else Result.UNKNOWN if unknown else Result.CLEAN
    file_rows = sorted(
        (
            FileResult(
                file=shown.path(f.path), format=f.format, records=f.records,
                unrecognised_records=f.unrecognised, unparsed_lines=len(f.unparsed),
                strings=f.strings, bytes=f.size,
                not_scanned=not_scanned.get(f.path),
            )
            for f in files
        ),
        key=lambda f: f.file,
    )
    checkable = sum(c.fingerprint is not None for c in credentials)
    scanned = [f for f in files if f.format is not None]
    coverage = Coverage(
        credentials=len(credentials), checkable=checkable,
        not_checkable=len(credentials) - checkable, files=len(scanned),
        claude_code_files=sum(f.format is Format.CLAUDE_CODE for f in scanned),
        claude_code_tool_results_files=sum(
            f.format is Format.CLAUDE_CODE_TOOL_RESULTS for f in scanned
        ),
        claude_code_memory_files=sum(f.format is Format.CLAUDE_CODE_MEMORY for f in scanned),
        claude_code_subagent_meta_files=sum(
            f.format is Format.CLAUDE_CODE_SUBAGENT_META for f in scanned
        ),
        otlp_files=sum(f.format is Format.OTLP for f in scanned),
        unknown_files=sum(f.format is Format.UNKNOWN for f in scanned),
        not_scanned=len(not_scanned),
        records=sum(f.records for f in files),
        unrecognised_records=sum(f.unrecognised for f in files),
        unparsed_lines=sum(len(f.unparsed) for f in files),
        strings=sum(f.strings for f in files),
        bytes=sum(f.size for f in files),
    )
    return Report(
        schema=AUDIT_SCHEMA, result=result, exit_code=EXIT_CODES[result], credentials=rows,
        hits=hits, files=file_rows, unknown=unknown, coverage=coverage,
    ), [shown.named(path) for path in named]


def audit_paths(
    report_path: Path, store_path: Path, key_path: Path, paths: Sequence[str],
    claude_config_dirs: Sequence[str] = (),
) -> Report:
    """Read the inventory inputs, then every file, and audit. Raises
    `AuditInputError` (exit 2) on unusable input. `claude_config_dirs` (the
    command line passes `CLAUDE_CONFIG_DIR`) are Claude config directories
    whose `projects` directory counts like `.claude/projects`."""
    inputs = load_inputs(report_path, store_path, key_path)
    return audit_files(
        inputs.credentials, inputs.key, inputs.by_fingerprint, paths, claude_config_dirs
    )


def encode_report(report: Report) -> bytes:
    """Deterministic, indented JSON: the `weir audit --json` bytes."""
    return msgspec.json.format(msgspec.json.encode(report), indent=2) + b"\n"
