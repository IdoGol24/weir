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

The JSON a text holds is matched as it is and through its decoded view,
the text with its JSON escapes undone (`weir.json_escapes`), by one rule:
the text where it parses as a JSON object, array or string, else each
object or array inside it. The texts are every string the walk reads,
every request part but a credential field's value and a JSON body as a
whole, and every line only the raw sweep reads (a swept file's, a
telemetry line the walk cannot read, a request capture line that is not a
record). A placement the text itself does not hold is found in the
fewest unescapings that hold it, at the same record and location, and its
form is named by the escapings the value took. Text escaped past the
view's bound makes its line unparsed.

Each request capture file is judged record by record under the attribution
rules: a needle in one of the credential fields of a request to the
placement's own provider is evidence that it was exercised, a needle
anywhere else in any request is a hit naming that request's sink. Only a
line that is not a request record gets the raw sweep, since nothing says
where it went.
"""

from __future__ import annotations

import bisect
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field

import msgspec

from weir.canary._types import (
    EXIT_CODES,
    REPORT_SCHEMA,
    Blocked,
    BlockedKind,
    Coverage,
    DirectEntry,
    Form,
    Hit,
    Incomplete,
    IncompleteReason,
    Ledger,
    NetworkState,
    NotScanned,
    Placement,
    PlacementState,
    Report,
    Request,
    Result,
    Signal,
    State,
)
from weir.canary._types import FlowState as FlowEntry
from weir.canary.capture import CaptureFile, Role, collect_capture
from weir.canary.forms import decoded_form, needles
from weir.canary.ledger import read_ledger
from weir.canary.outbound import Part, parse_request, request_parts, shown
from weir.canary.text import Display
from weir.canary.walk import Segment, Site, walk_request
from weir.json_escapes import decoded_view

_JSON_START = re.compile(r"[\[{]")
_DECODER = json.JSONDecoder()


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
    return Display(
        (n.data for n in _all_needles(ledger)),
        (p.value for p in ledger.placements),
        decoded=True,
    )


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
    form: Form


@dataclass
class _Swept:
    hits: list[_RawHit]
    # Lines holding text escaped past the decoded view's bound.
    too_deep: list[int]


@dataclass(frozen=True)
class _Text:
    """One text of a decoded view: where it came from (a site, a line or a
    request part, by index) and how many unescapings gave it."""

    origin: int
    unescapings: int
    data: bytes


def _holds_json(data: bytes) -> bool:
    """Whether `data` holds an escape and parses as a JSON object, array or
    string: text the decoded view reads. JSON nested past the decoder's
    depth limit cannot be told apart, so it is read."""
    if b"\\" not in data:
        return False
    try:
        return isinstance(msgspec.json.decode(data), str | list | dict)
    except msgspec.DecodeError:
        return False
    except RecursionError:
        return True


def _json_spans(line: bytes) -> list[bytes]:
    """The JSON a text holds, where it holds an escape: the text where it
    parses as a JSON object, array or string, else each object or array
    inside it, left to right. The one rule for every text the decoded view
    reads."""
    if b"\\" not in line:
        return []
    if _holds_json(line):
        return [line]
    # A byte that is not UTF-8 stands for itself, so a span encodes back to
    # the very bytes it was read from.
    text = line.decode("utf-8", errors="surrogateescape")
    spans: list[bytes] = []
    at = 0
    while (start := _JSON_START.search(text, at)) is not None:
        try:
            _, end = _DECODER.raw_decode(text, start.start())
        except ValueError:
            at = start.start() + 1
            continue
        except RecursionError:
            return [line]
        spans.append(text[start.start() : end].encode("utf-8", errors="surrogateescape"))
        at = end
    return spans


def _views(origins: Sequence[tuple[int, bytes]]) -> tuple[list[_Text], list[int]]:
    """The decoded view of every (origin, text), and each origin escaped too
    deep, once."""
    texts: list[_Text] = []
    too_deep: dict[int, None] = {}
    for origin, data in origins:
        view = decoded_view(data)
        if not view.complete:
            too_deep[origin] = None
        texts += [_Text(origin, level, text) for level, text in enumerate(view.texts, start=1)]
    return texts, list(too_deep)


def _view_hits(
    texts: Sequence[_Text], table: Sequence[_Needle], found: set[tuple[str, int]]
) -> list[tuple[_Needle, _Text]]:
    """Every needle in a text of the view whose origin does not hold that
    placement itself (`found`: placement id, origin), at the fewest
    unescapings that hold one of the placement's needles."""
    ends: list[int] = []
    offset = 0
    for text in texts:
        offset += len(text.data)
        ends.append(offset)
    haystack = b"".join(text.data for text in texts)
    matches = [
        (needle, texts[index])
        for needle in table
        for index in _find(haystack, needle.data, ends)
        if (needle.placement.id, texts[index].origin) not in found
    ]
    fewest: dict[tuple[str, int], int] = {}
    for needle, text in matches:
        key = (needle.placement.id, text.origin)
        fewest[key] = min(fewest.get(key, text.unescapings), text.unescapings)
    return [
        (needle, text)
        for needle, text in matches
        if fewest[(needle.placement.id, text.origin)] == text.unescapings
    ]


def _every_line(_: int) -> bool:
    return True


def _raw_sweep(data: bytes, table: Sequence[_Needle], viewed: Callable[[int], bool]) -> _Swept:
    """Every (needle, line) where a match starts. A match may run past the
    end of its line: a raw needle may itself hold a newline. The JSON each
    line `viewed` picks (by number) holds is also read through its decoded
    view."""
    line_ends = [match.end() for match in re.finditer(b"\n", data)]
    if not line_ends or line_ends[-1] != len(data):
        line_ends.append(len(data))
    hits: list[_RawHit] = []
    for needle in table:
        pos = data.find(needle.data)
        while pos != -1:
            line = bisect.bisect_right(line_ends, pos)
            hits.append(_RawHit(needle, line + 1, needle.form))
            pos = data.find(needle.data, line_ends[line])
    if b"\\" not in data:
        return _Swept(hits, [])
    starts = [0, *line_ends[:-1]]
    lines = [data[start:end] for start, end in zip(starts, line_ends, strict=True)]
    spans = [
        (origin, span)
        for origin, line in enumerate(lines)
        if viewed(origin + 1)
        for span in _json_spans(line)
    ]
    texts, too_deep = _views(spans)
    # Line numbers are origins counted from 1.
    found = {(hit.needle.placement.id, hit.line - 1) for hit in hits}
    hits += [
        _RawHit(needle, text.origin + 1, decoded_form(needle.form, text.unescapings))
        for needle, text in _view_hits(texts, table, found)
    ]
    return _Swept(hits, [origin + 1 for origin in too_deep])


@dataclass(frozen=True)
class _SiteHit:
    needle: _Needle
    site: Site
    line: int
    form: Form


@dataclass
class _Telemetry:
    site_hits: list[_SiteHit]
    unparsed_lines: list[int]
    # The lines the walk could not read: left to the raw sweep alone.
    unread_lines: list[int] = field(default_factory=lambda: [])
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
    telemetry.unread_lines = list(telemetry.unparsed_lines)
    telemetry.strings = len(sites)

    # One haystack for the whole file, so each needle is one fast search;
    # a match counts only inside one string.
    ends: list[int] = []
    offset = 0
    for site, _ in sites:
        offset += len(site.data)
        ends.append(offset)
    haystack = b"".join(site.data for site, _ in sites)
    found: set[tuple[str, int]] = set()
    for needle in table:
        for index in _find(haystack, needle.data, ends):
            site, number = sites[index]
            telemetry.site_hits.append(_SiteHit(needle, site, number, needle.form))
            found.add((needle.placement.id, index))

    viewed = [
        (index, span) for index, (site, _) in enumerate(sites) for span in _json_spans(site.data)
    ]
    texts, too_deep = _views(viewed)
    for needle, text in _view_hits(texts, table, found):
        site, number = sites[text.origin]
        form = decoded_form(needle.form, text.unescapings)
        telemetry.site_hits.append(_SiteHit(needle, site, number, form))
    telemetry.unparsed_lines += dict.fromkeys(sites[origin][1] for origin in too_deep)
    return telemetry


# docs/canary.md, "Attribution": the sink a request names when it is not
# the placement's own provider.
UNMOCKED = "unmocked"
_BLOCKED_KIND = {"refused": BlockedKind.REQUEST, "connect": BlockedKind.CONNECTION}


@dataclass
class _Requests:
    hits: list[Hit] = field(default_factory=lambda: [])
    evidence: dict[str, set[str]] = field(default_factory=lambda: {})
    blocked: Counter[tuple[BlockedKind, str, int]] = field(default_factory=lambda: Counter())
    unparsed_lines: list[int] = field(default_factory=lambda: [])
    requests: int = 0
    refused: int = 0
    connections: int = 0


def _own_provider(placement: Placement, record: Request) -> bool:
    if record.outcome == "served":
        return record.endpoint is not None and record.endpoint in placement.providers
    host = placement.provider_host
    return host is not None and host.lower() == record.host.lower()


def _host(record: Request, display: Callable[[str], str]) -> str:
    return shown(display, record.host.lower(), record.host)


def _sink(record: Request, display: Callable[[str], str]) -> str:
    if record.outcome == "served":
        return UNMOCKED if record.endpoint is None else display(record.endpoint)
    return f"{_host(record, display)} (blocked)"


def _credential_fields(record: Request) -> set[tuple[str, str]]:
    return {
        (location, name.lower() if location == "header" else name)
        for location, name in record.credential_fields
    }


def _part_needles(
    texts: Sequence[tuple[int, bytes]], present: Sequence[_Needle]
) -> list[tuple[_Needle, Form]]:
    """Every needle in a part's texts (unescapings, text), each placement at
    the fewest unescapings that hold it."""
    out: list[tuple[_Needle, Form]] = []
    seen: set[str] = set()
    for unescapings in sorted({level for level, _ in texts}):
        at = [text for level, text in texts if level == unescapings]
        now = [n for n in present if n.placement.id not in seen and any(n.data in t for t in at)]
        out += [(n, decoded_form(n.form, unescapings)) for n in now]
        seen.update(n.placement.id for n in now)
    return out


def _part_texts(
    part: Part, credentials: set[tuple[str, str]]
) -> tuple[list[tuple[int, bytes]], bool]:
    """The part itself, then the decoded view of the JSON it holds, each
    text with the unescapings that gave it, and whether the view read it in
    full. Not viewed: a JSON body as a whole, whose strings are its parts,
    and a credential field's value, which is matched as the mock matches
    it."""
    texts = [(0, part.data)]
    if part.document or part.field in credentials:
        return texts, True
    complete = True
    for span in _json_spans(part.data):
        view = decoded_view(span)
        complete = complete and view.complete
        texts += enumerate(view.texts, start=1)
    return texts, complete


def _found(
    parts: Sequence[Part], table: Sequence[_Needle], credentials: set[tuple[str, str]]
) -> tuple[set[tuple[str, str, Form, bool]], bool]:
    """(placement id, location, form, in a credential field) for every
    needle in the request; a whole query or body only where no finer part
    of it found the placement. And whether any part is escaped past the
    decoded view's bound."""
    fine: set[tuple[str, str, Form, bool]] = set()
    whole: set[tuple[str, str, Form, str | None]] = set()
    grouped: set[tuple[str, str | None]] = set()
    read = [_part_texts(part, credentials) for part in parts]
    texts = [part_texts for part_texts, _ in read]
    # One search per needle over the whole request first: a needle in no
    # part is in no part's texts, and most needles are in no request.
    joined = b"\0".join(text for part_texts in texts for _, text in part_texts)
    present = [needle for needle in table if needle.data in joined]
    for part, part_texts in zip(parts, texts, strict=True):
        for needle, form in _part_needles(part_texts, present):
            pid = needle.placement.id
            if part.whole:
                whole.add((pid, part.location, form, part.group))
            else:
                fine.add((pid, part.location, form, part.field in credentials))
                grouped.add((pid, part.group))
    for pid, location, form, group in whole:
        if (pid, group) not in grouped:
            fine.add((pid, location, form, False))
    return fine, not all(complete for _, complete in read)


def _judge_requests(
    data: bytes, path: str, ledger: Ledger, table: Sequence[_Needle], display: Callable[[str], str]
) -> _Requests:
    out = _Requests()
    placements = {p.id: p for p in ledger.placements}
    lines = data.split(b"\n")
    complete, truncated = lines[:-1], lines[-1]
    for number, line in enumerate(complete, start=1):
        if number == 1:
            continue  # the header, checked when the file was read
        record = parse_request(line)
        if record is None:
            out.unparsed_lines.append(number)
            out.hits += _raw_hits(line, number, path, table)
            continue
        out.requests += 1
        parts = request_parts(record, display)
        found, too_deep = _found(parts, table, _credential_fields(record))
        if record.unread is not None or too_deep:
            out.unparsed_lines.append(number)
        if record.outcome != "served":
            kind = _BLOCKED_KIND[record.outcome]
            out.blocked[(kind, _host(record, display), record.port)] += 1
            if kind is BlockedKind.REQUEST:
                out.refused += 1
            else:
                out.connections += 1
            for placement in ledger.placements:
                if _own_provider(placement, record):
                    out.evidence.setdefault(placement.id, set()).add("egress")
        sink = _sink(record, display)
        for pid, location, form, credential in found:
            placement = placements[pid]
            if credential and _own_provider(placement, record):
                if record.outcome == "served":
                    out.evidence.setdefault(pid, set()).add("request")
                continue
            out.hits.append(
                Hit(
                    placement=pid,
                    kind=placement.kind,
                    file=path,
                    line=number,
                    signal=Signal.REQUESTS,
                    span=None,
                    span_id=None,
                    log_record=None,
                    metric=None,
                    sink=sink,
                    location=location,
                    form=form,
                )
            )
    if truncated:
        out.unparsed_lines.append(len(lines))
        out.hits += _raw_hits(truncated, len(lines), path, table)
    return out


def _raw_hits(data: bytes, line: int, path: str, table: Sequence[_Needle]) -> list[Hit]:
    return [
        _raw_hit(raw.needle, path, line + raw.line - 1, raw.form)
        for raw in _raw_sweep(data, table, _every_line).hits
    ]


def _raw_hit(needle: _Needle, path: str, line: int, form: Form) -> Hit:
    return Hit(
        placement=needle.placement.id,
        kind=needle.placement.kind,
        file=path,
        line=line,
        signal=Signal.RAW,
        span=None,
        span_id=None,
        log_record=None,
        metric=None,
        sink=None,
        location=None,
        form=form,
    )


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
        hit.sink or "",
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
    derived: dict[str, set[str]] = {}
    blocked: Counter[tuple[BlockedKind, str, int]] = Counter()
    requests = refused = connections = 0

    for capture in files:
        if capture.data is None:
            continue
        path = display(capture.path)
        if capture.role is Role.REQUESTS:
            judged = _judge_requests(capture.data, path, ledger, table, display)
            hits.update(judged.hits)
            unparsed.extend((path, line) for line in judged.unparsed_lines)
            for pid, kinds in judged.evidence.items():
                derived.setdefault(pid, set()).update(kinds)
            blocked.update(judged.blocked)
            requests += judged.requests
            refused += judged.refused
            connections += judged.connections
            continue
        swept += len(capture.data)
        walked: set[tuple[str, int]] = set()
        viewed = _every_line
        if capture.role is Role.TELEMETRY:
            telemetry = _walk_telemetry(capture.data, table)
            spans += telemetry.spans
            log_records += telemetry.log_records
            data_points += telemetry.metric_data_points
            strings += telemetry.strings
            unparsed.extend((path, line) for line in telemetry.unparsed_lines)
            viewed = set(telemetry.unread_lines).__contains__
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
                        sink=None,
                        location=_location(found.site.location, display),
                        form=found.form,
                    )
                )
        swept_file = _raw_sweep(capture.data, table, viewed)
        if capture.role is Role.SWEPT:
            unparsed.extend((path, line) for line in swept_file.too_deep)
        for raw in swept_file.hits:
            placement = raw.needle.placement
            if (placement.id, raw.line) in walked:
                continue
            hits.add(_raw_hit(raw.needle, path, raw.line, raw.form))

    ordered_hits = sorted(hits, key=_hit_sort_key)
    hit_counts: dict[str, int] = {}
    for hit in ordered_hits:
        hit_counts[hit.placement] = hit_counts.get(hit.placement, 0) + 1
    evidence: dict[str, set[str]] = {pid: set(kinds) for pid, kinds in derived.items()}
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
    network = NetworkState(
        isolated=ledger.network is not None and ledger.network.isolated,
        required=ledger.network is not None and ledger.network.required,
        direct=sorted(
            (
                DirectEntry(
                    flow=d.flow, protocol=d.protocol, target=display(d.target), attempts=d.attempts
                )
                for d in ledger.direct
            ),
            key=lambda d: (d.flow, d.protocol, d.target),
        ),
    )
    blocked_list = [
        Blocked(kind=kind, host=host, port=port, count=count)
        for (kind, host, port), count in sorted(
            blocked.items(), key=lambda item: (item[0][0].value, item[0][1], item[0][2])
        )
    ]

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
    if network.required and not network.isolated:
        reasons.append((IncompleteReason.NETWORK_NOT_ISOLATED, None, 0))
    reasons += [
        (IncompleteReason.DIRECT_CONNECTION, f"{d.flow}={d.protocol}:{d.target}", 0)
        for d in network.direct
    ]
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
        request_files=sum(f.role is Role.REQUESTS and f.data is not None for f in files),
        requests=requests,
        requests_refused=refused,
        connections_blocked=connections,
    )
    return Report(
        schema=REPORT_SCHEMA,
        result=result,
        exit_code=EXIT_CODES[result],
        hits=ordered_hits,
        placements=placements,
        flows=flows,
        not_scanned=not_scanned,
        blocked=blocked_list,
        incomplete=incomplete,
        coverage=coverage,
        network=network,
    )


def judge_paths(
    ledger_path: str, otlp: Sequence[str], swept: Sequence[str], requests: Sequence[str] = ()
) -> Report:
    """Read the ledger, then the capture, and judge. Raises `LedgerError` or
    `CaptureError` (exit 2) on unusable input."""
    ledger = read_ledger(ledger_path)
    display = ledger_display(ledger)
    return judge_capture(ledger, collect_capture(otlp, swept, display, requests))


def encode_report(report: Report) -> bytes:
    """Deterministic, indented JSON: the `weir canary judge --json` bytes."""
    return msgspec.json.format(msgspec.json.encode(report), indent=2) + b"\n"
