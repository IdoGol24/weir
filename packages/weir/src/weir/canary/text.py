"""Printing for the canary judge: the capture-text rule and the text report.

A span name, metric name, attribute key, path segment, capture file name or
direct connection target comes from the program under test and may itself
hold a canary. Before any
such string is printed it is flattened to one line, cut to 200 characters,
and replaced entirely by `[withheld]` if it holds any needle or any run of 6
consecutive characters of any ledger value (docs/canary.md, "Printing
capture-derived text").
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from weir.canary._types import RUN, Hit, Report

WITHHELD = "[withheld]"
MAX_CHARS = 200


def _escape(ch: str) -> str:
    code = ord(ch)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


class Display:
    """Renders capture-derived text under the printing rule."""

    def __init__(self, needles: Iterable[bytes], values: Iterable[str]) -> None:
        self._needles = tuple(needles)
        self._runs = frozenset(
            value[i : i + RUN] for value in values for i in range(len(value) - RUN + 1)
        )

    def holds_value(self, text: str) -> bool:
        data = text.encode("utf-8", errors="surrogatepass")
        if any(needle in data for needle in self._needles):
            return True
        return any(text[i : i + RUN] in self._runs for i in range(len(text) - RUN + 1))

    def __call__(self, text: str) -> str:
        if self.holds_value(text):
            return WITHHELD
        flat = "".join(ch if ch.isprintable() else _escape(ch) for ch in text)
        if len(flat) > MAX_CHARS:
            flat = flat[: MAX_CHARS - 3] + "..."
        # Flattening writes new characters; check what is actually printed.
        return WITHHELD if self.holds_value(flat) else flat


def _quote(name: str) -> str:
    return json.dumps(name, ensure_ascii=False)


def hit_line(hit: Hit) -> str:
    parts = [f"LEAK {hit.placement}", f"file={hit.file}:{hit.line}", f"signal={hit.signal}"]
    if hit.span is not None:
        parts.append(f"span={_quote(hit.span)}")
    if hit.log_record is not None:
        parts.append(f"log={hit.log_record}")
    if hit.metric is not None:
        parts.append(f"metric={_quote(hit.metric)}")
    if hit.sink is not None:
        parts.append(f"sink={_quote(hit.sink)}")
    if hit.location is not None:
        parts.append(f"at={hit.location}")
    parts.append(f"form={hit.form}")
    return " ".join(parts)


def report_lines(report: Report) -> Iterator[str]:
    """The text report, one line per item, in the contract's order."""
    for hit in report.hits:
        yield hit_line(hit)
    for placement in report.placements:
        if placement.state == "not_exercised":
            yield f"not exercised: {placement.id}"
    for entry in report.not_scanned:
        yield f"not scanned: {entry.file} ({entry.reason})"
    for blocked in report.blocked:
        yield f"blocked {blocked.kind}: {blocked.host}:{blocked.port} ({blocked.count}x)"
    for entry in report.incomplete:
        subject = "" if entry.subject is None else f" {entry.subject}"
        yield f"incomplete: {entry.reason}{subject}"
    c = report.coverage
    yield (
        f"coverage: {c.placements} placements ({c.leaked} leaked, {c.exercised} exercised,"
        f" {c.not_exercised} not exercised, {c.required} required),"
        f" {c.flows} flows ({c.flows_ok} ok), {c.files} files, {c.spans} spans,"
        f" {c.log_records} log records, {c.metric_data_points} metric data points,"
        f" {c.strings} strings, {c.bytes} bytes swept"
        + (
            f", {c.requests} requests ({c.requests_refused} refused,"
            f" {c.connections_blocked} blocked connections)"
            if c.request_files
            else ""
        )
    )
    if report.network.isolated:
        yield f"network isolated: {len(report.network.direct)} direct connections blocked"
    else:
        yield "network not isolated: direct connections were not observed"
    yield f"result: {report.result}"
