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
    Form,
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
from weir.audit.matching import Matcher, References
from weir.canary import CaptureError, collect_capture, needles
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
    strings: int = 0


class _Auditor:
    def __init__(
        self, matcher: Matcher, by_fingerprint: dict[bytes, tuple[str, ...]],
        references: References,
    ) -> None:
        self.matcher = matcher
        self.by_fingerprint = by_fingerprint
        self.references = references
        self.found: list[_Found] = []

    def search(self, file: _File, line: int, site: Site) -> None:
        file.strings += 1
        fmt = file.format or Format.UNKNOWN
        for fp, form in self.matcher.find(site.string).items():
            found = _Found(self.by_fingerprint[fp], file.path, line, fmt, site, Form(form.value))
            self.found.append(found)
        if site.place.kind is Kind.TOOL_CALL:
            named = self.references.find(site.string)
            if named:
                self.found.append(
                    _Found(tuple(sorted(named)), file.path, line, fmt, site, Form.NAME)
                )

    def file(self, file: _File, data: bytes, lines: list[Line]) -> None:
        """Search one file's bytes as its format reads them."""
        if file.format is Format.CLAUDE_CODE:
            self.claude_code(file, lines)
        elif file.format is Format.CLAUDE_CODE_TOOL_RESULTS:
            self.text(file, data, _STORED)
        elif file.format is Format.CLAUDE_CODE_MEMORY:
            self.text(file, data, _CONTEXT)
        elif file.format is Format.CLAUDE_CODE_SUBAGENT_META:
            self.subagent_meta(file, data, lines)
        elif file.format is Format.OTLP:
            self.otlp(file, data, lines)
        else:
            self.unknown(file, lines)

    def claude_code(self, file: _File, lines: list[Line]) -> None:
        tools: dict[str, str] = {}
        for line in lines:
            if line.parsed is None:
                self._unparsed(file, line)
                continue
            file.records += 1
            if not recognised(line.parsed):
                file.unrecognised += 1
            for site in claude_code_sites(line.parsed, tools):
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
        flat = flatten_untrusted(text)
        if self._display.holds_value(text) or self._display.holds_value(flat):
            return WITHHELD
        return WITHHELD if looks_secret_shaped(text) else flat


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
    # A credential the store holds no fingerprint of has no hit but one by
    # name: a tool call that names it sent it all the same.
    if credential.fingerprint is None and not counts:
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


def _references(credentials: Sequence[Credential]) -> References:
    """The environment credentials, by variable name (docs/audit.md,
    "References by name"). Several records may share a name."""
    names: dict[str, list[str]] = {}
    for c in credentials:
        if c.source == "environment":
            names.setdefault(c.name, []).append(c.id)
    return References({name: tuple(sorted(ids)) for name, ids in names.items()})


@dataclass(frozen=True)
class Chunk:
    """Bytes to audit as one file: a whole file, or whole lines of one read
    as the format the whole file has (`format`, None to recognise it from
    these bytes). A file's lines are records each on its own, so the lines
    of a file audited in chunks give the hits the whole file gives."""

    path: str
    data: bytes
    format: Format | None = None


def audit_files(
    credentials: Sequence[Credential],
    key: bytes,
    by_fingerprint: dict[bytes, tuple[str, ...]],
    paths: Sequence[str],
    claude_config_dirs: Sequence[str] = (),
) -> Report:
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
    items: list[_Item] = [_Item(path, None, NotScannedReason.MISSING) for path in missing]
    for item in capture:
        if item.data is None or item.not_scanned is not None:
            reason = item.not_scanned.value if item.not_scanned is not None else "compressed"
            items.append(_Item(item.path, None, NotScannedReason(reason)))
        else:
            items.append(_Item(item.path, item.data, None))
    return _audit(credentials, by_fingerprint, matcher, items, claude_config_dirs)


def audit_chunks(
    inputs: Inputs, chunks: Sequence[Chunk], claude_config_dirs: Sequence[str] = ()
) -> Report:
    """Audit bytes already read: each chunk as one file, read as its
    `format` when given. `weir statusline` reads a growing session file in
    chunks of whole lines and keeps what each chunk found."""
    items = [_Item(c.path, c.data, None, c.format) for c in chunks]
    matcher = Matcher(inputs.key, set(inputs.by_fingerprint))
    return _audit(inputs.credentials, inputs.by_fingerprint, matcher, items, claude_config_dirs)


@dataclass(frozen=True)
class _Item:
    path: str
    # None: not scanned, for `not_scanned`
    data: bytes | None
    not_scanned: NotScannedReason | None
    format: Format | None = None


def _audit(
    credentials: Sequence[Credential],
    by_fingerprint: dict[bytes, tuple[str, ...]],
    matcher: Matcher,
    items: Sequence[_Item],
    claude_config_dirs: Sequence[str],
) -> Report:
    projects_dirs = [PurePath(os.path.abspath(d), "projects") for d in claude_config_dirs]
    auditor = _Auditor(matcher, by_fingerprint, _references(credentials))
    files: list[_File] = []
    not_scanned: dict[str, NotScannedReason] = {}
    for item in items:
        if item.data is None:
            files.append(_File(item.path, None, 0))
            not_scanned[item.path] = item.not_scanned or NotScannedReason.MISSING
            continue
        data = item.data
        lines = json_lines(data)
        file = _File(item.path, item.format or recognise(item.path, data, lines, projects_dirs),
                     len(data))
        files.append(file)
        auditor.file(file, data, lines)

    # Every path the report prints is checked against the store first, so a
    # value that is only in a file name is withheld like a found one.
    for file in files:
        matcher.path_holds_value(file.path)
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
    )


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
