"""`weir canary judge`: did any planted value reach the capture?

`judge_capture` is a pure function of the ledger and the capture bytes: no
clock, no randomness, no environment, no socket, no subprocess. It reports
every placement whose value, or an encoded form of it, appears anywhere in
the capture, and names the placement and the location, never a value
(docs/canary.md).

Each telemetry file gets the structured walk (every string of every OTLP
export request, with a precise location) and the raw sweep (the undecoded
bytes); every other capture file gets the raw sweep only. In a telemetry
file a raw hit is reported only where the walk found nothing for the same
placement on the same line.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import msgspec

from weir.canary._types import (
    EXIT_CODES,
    REPORT_SCHEMA,
    Coverage,
    Form,
    Hit,
    Incomplete,
    IncompleteReason,
    Ledger,
    NotScanned,
    Placement,
    PlacementState,
    Report,
    Result,
    Signal,
    State,
)
from weir.canary._types import FlowState as FlowEntry
from weir.canary.capture import CaptureFile, Role, collect_capture
from weir.canary.forms import needles
from weir.canary.ledger import read_ledger
from weir.canary.text import Display
from weir.canary.walk import Segment, Site, walk_request


@dataclass(frozen=True)
class _Needle:
    data: bytes
    placement: Placement
    form: Form


def _all_needles(ledger: Ledger) -> list[_Needle]:
    return [
        _Needle(data, placement, form)
        for placement in ledger.placements
        for data, form in needles(placement.value)
    ]


def ledger_display(ledger: Ledger) -> Display:
    """The printing rule for this ledger's values."""
    return Display((n.data for n in _all_needles(ledger)), (p.value for p in ledger.placements))


def _find(haystack: bytes, needle: bytes, ends: Sequence[int]) -> Iterator[int]:
    """Indexes of the spans (ending at `ends`, exclusive) where `needle`
    starts and fits; each span reported once."""
    pos = haystack.find(needle)
    while pos != -1:
        index = bisect.bisect_right(ends, pos)
        if pos + len(needle) <= ends[index]:
            yield index
            pos = haystack.find(needle, ends[index])
        else:
            pos = haystack.find(needle, pos + 1)


@dataclass(frozen=True)
class _RawHit:
    needle: _Needle
    line: int


def _raw_sweep(data: bytes, table: Sequence[_Needle]) -> list[_RawHit]:
    """Every (needle, line) where a match starts. A match may run past the
    end of its line: a raw needle may itself hold a newline."""
    line_ends = [match.end() for match in re.finditer(b"\n", data)]
    if not line_ends or line_ends[-1] != len(data):
        line_ends.append(len(data))
    hits: list[_RawHit] = []
    for needle in table:
        pos = data.find(needle.data)
        while pos != -1:
            line = bisect.bisect_right(line_ends, pos)
            hits.append(_RawHit(needle, line + 1))
            pos = data.find(needle.data, line_ends[line])
    return hits


@dataclass(frozen=True)
class _SiteHit:
    needle: _Needle
    site: Site
    line: int


@dataclass
class _Telemetry:
    site_hits: list[_SiteHit]
    unparsed_lines: list[int]
    spans: int = 0
    log_records: int = 0
    metric_data_points: int = 0
    strings: int = 0


def _walk_telemetry(data: bytes, table: Sequence[_Needle]) -> _Telemetry:
    lines = data.split(b"\n")
    sites: list[tuple[Site, int]] = []
    telemetry = _Telemetry(site_hits=[], unparsed_lines=[])
    # Nothing after the final newline forms a line: bytes there are a
    # truncated last line, and a file ending in a newline has none.
    complete, truncated = lines[:-1], lines[-1]
    for number, line in enumerate(complete, start=1):
        try:
            walk = walk_request(msgspec.json.decode(line))
        except (msgspec.DecodeError, RecursionError):
            # Nested past the decoder's depth limit: left to the raw sweep
            # and counted as unparsed, like any line the walk cannot read.
            walk = None
        if walk is None:
            telemetry.unparsed_lines.append(number)
            continue
        telemetry.spans += walk.spans
        telemetry.log_records += walk.log_records
        telemetry.metric_data_points += walk.metric_data_points
        sites.extend((site, number) for site in walk.sites)
    if truncated:
        telemetry.unparsed_lines.append(len(lines))
    telemetry.strings = len(sites)

    # One haystack for the whole file, so each needle is one fast search;
    # a match counts only inside one string.
    ends: list[int] = []
    offset = 0
    for site, _ in sites:
        offset += len(site.data)
        ends.append(offset)
    haystack = b"".join(site.data for site, _ in sites)
    for needle in table:
        for index in _find(haystack, needle.data, ends):
            site, number = sites[index]
            telemetry.site_hits.append(_SiteHit(needle, site, number))
    return telemetry


def _location(segments: tuple[Segment, ...], display: Callable[[str], str]) -> str:
    out = ""
    for segment in segments:
        if isinstance(segment, int):
            out += f"[{segment}]"
        else:
            out += ("." if out else "") + display(segment)
    return out


def _shown(display: Callable[[str], str], text: str | None) -> str | None:
    return None if text is None else display(text)


def _hit_sort_key(hit: Hit) -> tuple[object, ...]:
    return (
        hit.placement,
        hit.file,
        hit.line,
        hit.signal.value,
        hit.span or "",
        hit.span_id or "",
        -1 if hit.log_record is None else hit.log_record,
        hit.metric or "",
        hit.location or "",
        hit.form.value,
    )


def judge_capture(ledger: Ledger, files: Sequence[CaptureFile]) -> Report:
    """The report for a validated ledger and a collected capture."""
    table = _all_needles(ledger)
    display = ledger_display(ledger)
    hits: set[Hit] = set()
    unparsed: list[tuple[str, int]] = []
    spans = log_records = data_points = strings = swept = 0

    for capture in files:
        if capture.data is None:
            continue
        path = display(capture.path)
        swept += len(capture.data)
        walked: set[tuple[str, int]] = set()
        if capture.role is Role.TELEMETRY:
            telemetry = _walk_telemetry(capture.data, table)
            spans += telemetry.spans
            log_records += telemetry.log_records
            data_points += telemetry.metric_data_points
            strings += telemetry.strings
            unparsed.extend((path, line) for line in telemetry.unparsed_lines)
            for found in telemetry.site_hits:
                record = found.site.record
                placement = found.needle.placement
                walked.add((placement.id, found.line))
                hits.add(
                    Hit(
                        placement=placement.id,
                        kind=placement.kind,
                        file=path,
                        line=found.line,
                        signal=found.site.signal,
                        span=_shown(display, record and record.span),
                        span_id=record and record.span_id,
                        log_record=record and record.log_record,
                        metric=_shown(display, record and record.metric),
                        location=_location(found.site.location, display),
                        form=found.needle.form,
                    )
                )
        for raw in _raw_sweep(capture.data, table):
            placement = raw.needle.placement
            if (placement.id, raw.line) in walked:
                continue
            hits.add(
                Hit(
                    placement=placement.id,
                    kind=placement.kind,
                    file=path,
                    line=raw.line,
                    signal=Signal.RAW,
                    span=None,
                    span_id=None,
                    log_record=None,
                    metric=None,
                    location=None,
                    form=raw.needle.form,
                )
            )

    ordered_hits = sorted(hits, key=_hit_sort_key)
    hit_counts: dict[str, int] = {}
    for hit in ordered_hits:
        hit_counts[hit.placement] = hit_counts.get(hit.placement, 0) + 1
    evidence: dict[str, set[str]] = {}
    for record in ledger.exercised:
        evidence.setdefault(record.placement, set()).add(record.evidence)

    placements: list[PlacementState] = []
    for placement in sorted(ledger.placements, key=lambda p: p.id):
        seen = evidence.get(placement.id, set())
        if hit_counts.get(placement.id):
            state = State.LEAKED
        elif seen:
            state = State.EXERCISED
        else:
            state = State.NOT_EXERCISED
        placements.append(
            PlacementState(
                id=placement.id,
                kind=placement.kind,
                required=placement.required,
                state=state,
                evidence=sorted(seen),
                hits=hit_counts.get(placement.id, 0),
            )
        )

    not_scanned = sorted(
        (
            NotScanned(file=display(f.path), reason=f.not_scanned)
            for f in files
            if f.not_scanned is not None
        ),
        key=lambda entry: (entry.file, entry.reason.value),
    )
    flows = sorted((FlowEntry(id=f.id, status=f.status) for f in ledger.flows), key=lambda f: f.id)

    reasons: list[tuple[IncompleteReason, str | None, int]] = []
    reasons += [
        (IncompleteReason.REQUIRED_NOT_EXERCISED, p.id, 0)
        for p in placements
        if p.required and p.state is State.NOT_EXERCISED
    ]
    reasons += [
        (IncompleteReason.FLOW_NOT_OK, f"{f.id}={f.status}", 0) for f in flows if f.status != "ok"
    ]
    reasons += [(IncompleteReason.UNEXPECTED_CREDENTIAL, u.id, 0) for u in ledger.unexpected]
    reasons += [(IncompleteReason.NOT_SCANNED, entry.file, 0) for entry in not_scanned]
    reasons += [(IncompleteReason.UNPARSED_RECORD, path, line) for path, line in unparsed]
    if spans + log_records + data_points == 0:
        reasons.append((IncompleteReason.EMPTY_CAPTURE, None, 0))
    reasons.sort(key=lambda r: (r[0].value, r[1] or "", r[2]))
    incomplete = [
        Incomplete(
            reason=reason,
            subject=f"{subject}:{line}" if reason is IncompleteReason.UNPARSED_RECORD else subject,
        )
        for reason, subject, line in reasons
    ]
    # The same file:line can only come from one telemetry file; keep the
    # list free of duplicates should two entries render alike.
    incomplete = list(dict.fromkeys(incomplete))

    if ordered_hits:
        result = Result.LEAK
    elif incomplete:
        result = Result.INCOMPLETE
    else:
        result = Result.CLEAN

    def count(state: State) -> int:
        return sum(p.state is state for p in placements)

    coverage = Coverage(
        placements=len(placements),
        leaked=count(State.LEAKED),
        exercised=count(State.EXERCISED),
        not_exercised=count(State.NOT_EXERCISED),
        required=sum(p.required for p in placements),
        flows=len(flows),
        flows_ok=sum(f.status == "ok" for f in flows),
        files=sum(f.data is not None for f in files),
        files_not_scanned=len(not_scanned),
        spans=spans,
        log_records=log_records,
        metric_data_points=data_points,
        unparsed_records=len(unparsed),
        strings=strings,
        bytes=swept,
    )
    return Report(
        schema=REPORT_SCHEMA,
        result=result,
        exit_code=EXIT_CODES[result],
        hits=ordered_hits,
        placements=placements,
        flows=flows,
        not_scanned=not_scanned,
        incomplete=incomplete,
        coverage=coverage,
    )


def judge_paths(ledger_path: str, otlp: Sequence[str], swept: Sequence[str]) -> Report:
    """Read the ledger, then the capture, and judge. Raises `LedgerError` or
    `CaptureError` (exit 2) on unusable input."""
    ledger = read_ledger(ledger_path)
    return judge_capture(ledger, collect_capture(otlp, swept, ledger_display(ledger)))


def encode_report(report: Report) -> bytes:
    """Deterministic, indented JSON: the `weir canary judge --json` bytes."""
    return msgspec.json.format(msgspec.json.encode(report), indent=2) + b"\n"
