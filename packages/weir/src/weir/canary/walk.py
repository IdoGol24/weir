"""The structured walk of one OTLP/JSON export request (docs/canary.md).

Every string in the request, every `stringValue`, and every `bytesValue`
after base64 decoding, becomes a `Site`: the bytes to match, the record it
belongs to (a span, log record or metric) and a value-free location within
that record. All three signals are read. Strings outside any record
(resource and scope attributes, scope name and version, schema URLs) carry
no record and a location starting `resource.` or `scope.`.

Locations read like weir's exposure scan: a key-value list or an object
member extends the location with `.key`, an array with `[i]`, and the
AnyValue wrappers (`stringValue`, `arrayValue.values` and the like) add
nothing, so a nested value reads `attributes.app.config.headers[0]`.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from weir.canary._types import Signal

Segment = str | int
# A decoded JSON document. Typed so the walk narrows with isinstance alone.
type Json = None | bool | int | float | str | list[Json] | dict[str, Json]

# Repeated KeyValue fields: `.key` descends into one of these.
_KV_LISTS = frozenset({"attributes", "filteredAttributes", "metadata"})
# AnyValue members whose content is the value itself.
_SCALARS = frozenset({"stringValue", "intValue", "doubleValue", "boolValue"})
# A metric's data wrapper adds nothing: `dataPoints[i]` sits under the metric.
_METRIC_DATA = frozenset({"gauge", "sum", "histogram", "exponentialHistogram", "summary"})
_SIGNALS = (
    ("resourceSpans", Signal.TRACES, "scopeSpans", "spans"),
    ("resourceLogs", Signal.LOGS, "scopeLogs", "logRecords"),
    ("resourceMetrics", Signal.METRICS, "scopeMetrics", "metrics"),
)
_SPAN_ID = re.compile(r"[0-9a-fA-F]{16}", re.ASCII)


@dataclass(frozen=True)
class Record:
    """A span (name and id), a log record (index) or a metric (name)."""

    signal: Signal
    span: str | None = None
    span_id: str | None = None
    log_record: int | None = None
    metric: str | None = None


@dataclass(frozen=True)
class Site:
    data: bytes
    signal: Signal
    record: Record | None
    location: tuple[Segment, ...]


@dataclass
class Walk:
    sites: list[Site] = field(default_factory=lambda: [])
    spans: int = 0
    log_records: int = 0
    metric_data_points: int = 0


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogatepass")


def _decode_bytes_value(text: str) -> bytes | None:
    # The protobuf JSON mapping writes bytes as base64, padded or not, in
    # the standard or the URL-safe alphabet.
    altchars = b"-_" if ("-" in text or "_" in text) else None
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None


Emit = Callable[[bytes, tuple[Segment, ...]], None]
# A node still to walk, and its location.
Pending = list[tuple[Json, tuple[Segment, ...]]]


def _walk(node: Json, path: tuple[Segment, ...], emit: Emit) -> None:
    """Walk iteratively: a capture can nest deeper than Python's stack."""
    stack: Pending = [(node, path)]
    while stack:
        node, path = stack.pop()
        if isinstance(node, str):
            emit(_utf8(node), path)
        elif isinstance(node, list):
            stack.extend((item, (*path, index)) for index, item in enumerate(node))
        elif isinstance(node, dict):
            for key, child in node.items():
                stack.extend(_member(key, child, path, emit))


def _member(key: str, child: Json, path: tuple[Segment, ...], emit: Emit) -> Pending:
    """The nodes one object member leaves to walk, with their locations."""
    if key in _KV_LISTS and isinstance(child, list):
        return _kvlist(child, (*path, key), emit)
    if key in _SCALARS:
        return [(child, path)]
    if key == "bytesValue" and isinstance(child, str):
        decoded = _decode_bytes_value(child)
        emit(_utf8(child) if decoded is None else decoded, path)
        return []
    if key == "arrayValue" and isinstance(child, dict):
        return [
            (value, path if inner == "values" and isinstance(value, list) else (*path, inner))
            for inner, value in child.items()
        ]
    if key == "kvlistValue" and isinstance(child, dict):
        pending: Pending = []
        for inner, value in child.items():
            if inner == "values" and isinstance(value, list):
                pending += _kvlist(value, path, emit)
            else:
                pending.append((value, (*path, inner)))
        return pending
    return [(child, (*path, key))]


def _kvlist(items: list[Json], path: tuple[Segment, ...], emit: Emit) -> Pending:
    pending: Pending = []
    for index, item in enumerate(items):
        key = item.get("key") if isinstance(item, dict) else None
        if not isinstance(item, dict) or not isinstance(key, str):
            pending.append((item, (*path, index)))
            continue
        here = (*path, key)
        emit(_utf8(key), here)
        for name, child in item.items():
            if name == "value":
                pending.append((child, here))
            elif name != "key":
                pending.append((child, (*here, name)))
    return pending


def _text(value: Json) -> str:
    return value if isinstance(value, str) else ""


def _span_record(span: dict[str, Json]) -> Record:
    span_id = span.get("spanId")
    valid = isinstance(span_id, str) and _SPAN_ID.fullmatch(span_id)
    return Record(
        Signal.TRACES,
        span=_text(span.get("name")),
        span_id=span_id.lower() if isinstance(span_id, str) and valid else None,
    )


def _count_data_points(metric: dict[str, Json]) -> int:
    count = 0
    for key in _METRIC_DATA:
        data = metric.get(key)
        points = data.get("dataPoints") if isinstance(data, dict) else None
        if isinstance(points, list):
            count += sum(isinstance(p, dict) for p in points)
    return count


class _Walker:
    def __init__(self) -> None:
        self.walk = Walk()
        self._log_index = 0

    def emitter(self, signal: Signal, record: Record | None) -> Emit:
        sites = self.walk.sites

        def emit(data: bytes, location: tuple[Segment, ...]) -> None:
            sites.append(Site(data, signal, record, location))

        return emit

    def signal_list(self, signal: Signal, resources: Json, names: tuple[str, str, str]) -> None:
        outside = self.emitter(signal, None)
        if not isinstance(resources, list):
            _walk(resources, (names[0],), outside)
            return
        for resource in resources:
            if not isinstance(resource, dict):
                _walk(resource, ("resource",), outside)
                continue
            for key, child in resource.items():
                if key == "resource":
                    _walk(child, ("resource",), outside)
                elif key == names[1] and isinstance(child, list):
                    for scoped in child:
                        self.scope(signal, scoped, names[2])
                else:
                    _walk(child, ("resource", key), outside)

    def scope(self, signal: Signal, scoped: Json, record_list: str) -> None:
        outside = self.emitter(signal, None)
        if not isinstance(scoped, dict):
            _walk(scoped, ("scope",), outside)
            return
        for key, child in scoped.items():
            if key == "scope":
                _walk(child, ("scope",), outside)
            elif key == record_list and isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        self.record(signal, item)
                    else:
                        _walk(item, ("scope", record_list), outside)
            else:
                _walk(child, ("scope", key), outside)

    def record(self, signal: Signal, item: dict[str, Json]) -> None:
        if signal is Signal.TRACES:
            self.walk.spans += 1
            _walk(item, (), self.emitter(signal, _span_record(item)))
        elif signal is Signal.LOGS:
            self.walk.log_records += 1
            _walk(item, (), self.emitter(signal, Record(signal, log_record=self._log_index)))
            self._log_index += 1
        else:
            self.walk.metric_data_points += _count_data_points(item)
            emit = self.emitter(signal, Record(signal, metric=_text(item.get("name"))))
            for key, child in item.items():
                if key in _METRIC_DATA and isinstance(child, dict):
                    _walk(child, (), emit)
                else:
                    for node, path in _member(key, child, (), emit):
                        _walk(node, path, emit)


def walk_request(request: Json) -> Walk | None:
    """Walk one export request; None when it is not one.

    An export request is a JSON object holding `resourceSpans`,
    `resourceLogs` or `resourceMetrics`. Its other top-level members are
    left to the raw sweep.
    """
    if not isinstance(request, dict) or not any(name in request for name, *_ in _SIGNALS):
        return None
    walker = _Walker()
    for list_name, signal, scope_list, record_list in _SIGNALS:
        if list_name in request:
            resources = request[list_name]
            walker.signal_list(signal, resources, (list_name, scope_list, record_list))
    return walker.walk
