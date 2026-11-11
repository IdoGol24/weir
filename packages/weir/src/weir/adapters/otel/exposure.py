"""Stage 1b: the raw wire batch -> every string it contains, with a location.
Spans and log records are read the same way, except that a log record is
also read in the shapes listed at `_LOG_WRAPPERS`. Either reports what it
cannot read. Every free-form string field OTLP defines for these signals is
on the surface, each at its own location: names and keys too (a span name, a
span event name, a log record's eventName, a scope's name and version, every
non-empty attribute and kvlist key), a span's or a span link's traceState, a
log record's severityText, each schemaUrl, and the resource's entityRefs.
A field OTLP does not define is not read: when it holds data it is counted
as not scanned, its name and value going nowhere (see `_OTLP_FIELDS`).

Mechanical by design. This module knows nothing about credentials, holds no
regex and never grades anything - that is `weir.exposure`'s job, and the
import-linter contract that separates them is what keeps this honest.

It consumes the batch BEFORE the GenAI span filter in `_map.py`, on purpose:
the leak this was written for lives on `{role}.agent` spans carrying only
vendor attributes, and a walk running after the filter would miss exactly
those spans, silently. Strings come out AS-IS - no JSON parsing, no
unescaping - so a key pasted into the JSON string of `gen_ai.input.messages`
is on the surface like any other.
"""

from __future__ import annotations

from typing import NamedTuple, cast

from weir.adapters.otel._wire import LogRecordInContext, SpanInContext, WireInput
from weir.canary.walk import decode_bytes_value
from weir.schema.exposure import ExposureSurface, ScannedString, Segment

# ponytail: hard depth cap. Real OTLP kvlists are one or two levels deep;
# anything at 64 is malformed or hostile, and crashing the scan is strictly
# worse than not walking it. What lies below the cap is counted as not
# scanned, never passed as clean.
_MAX_DEPTH = 64

# The OpenTelemetry HTTP semantic conventions record request header `<name>`
# as the attribute `http.request.header.<name>`, a string or string array.
# Instrumentation that records the whole header map as ONE kvlist attribute
# (`http.request.headers = {authorization: ...}`) names the header in the
# entry key instead, so inside a kvlist a bare `authorization` key names the
# header too. Some instrumentations write `_` for `-` in a header name
# (`proxy_authorization`), so the two are the same name here. Only the
# credential-carrying authorization headers are named on the surface; every
# other header is a plain string like any other.
_REQUEST_HEADER = "http.request.header."
_AUTHORIZATION_HEADERS = frozenset({"authorization", "proxy-authorization"})

# AnyValue members, in the order they are tried. A span reads the three
# camelCase string carriers only, exactly as it always has, and passes
# camelCase numbers and booleans as holding no string. A log record also
# reads the snake_case spellings protojson writes with proto field names and
# decodes bytes. Any other shape is counted as not scanned.
_SPAN_WRAPPERS = (
    ("stringValue", "string"), ("arrayValue", "array"), ("kvlistValue", "kvlist"),
    ("intValue", "scalar"), ("doubleValue", "scalar"), ("boolValue", "scalar"),
)
_LOG_WRAPPERS = (
    ("stringValue", "string"), ("string_value", "string"),
    ("bytesValue", "bytes"), ("bytes_value", "bytes"),
    ("arrayValue", "array"), ("array_value", "array"),
    ("kvlistValue", "kvlist"), ("kvlist_value", "kvlist"),
    ("intValue", "scalar"), ("int_value", "scalar"),
    ("doubleValue", "scalar"), ("double_value", "scalar"),
    ("boolValue", "scalar"), ("bool_value", "scalar"),
)

# The members OTLP defines at each level, as camelCase OTLP/JSON names
# (`_wire` renames the snake_case structural keys). Any other member holding
# data is counted as not scanned, never read: nothing about it is printed.
# An AnyValue is a oneof, so in a value only the member that was read counts
# as defined.
_OTLP_FIELDS = {
    "resourceSpans": frozenset({"resource", "scopeSpans", "schemaUrl"}),
    "resourceLogs": frozenset({"resource", "scopeLogs", "schemaUrl"}),
    "resource": frozenset({"attributes", "droppedAttributesCount", "entityRefs"}),
    "entityRef": frozenset({"schemaUrl", "type", "idKeys", "descriptionKeys"}),
    "scopeSpans": frozenset({"scope", "spans", "schemaUrl"}),
    "scopeLogs": frozenset({"scope", "logRecords", "schemaUrl"}),
    "scope": frozenset({"name", "version", "attributes", "droppedAttributesCount"}),
    "span": frozenset({
        "traceId", "spanId", "traceState", "parentSpanId", "flags", "name", "kind",
        "startTimeUnixNano", "endTimeUnixNano", "attributes", "droppedAttributesCount",
        "events", "droppedEventsCount", "links", "droppedLinksCount", "status",
    }),
    "event": frozenset({"timeUnixNano", "name", "attributes", "droppedAttributesCount"}),
    "link": frozenset({
        "traceId", "spanId", "traceState", "attributes", "droppedAttributesCount", "flags",
    }),
    "status": frozenset({"message", "code"}),
    "logRecord": frozenset({
        "timeUnixNano", "observedTimeUnixNano", "severityNumber", "severityText", "body",
        "attributes", "droppedAttributesCount", "flags", "traceId", "spanId", "eventName",
    }),
    "keyValue": frozenset({"key", "value"}),
    "values": frozenset({"values"}),
}


class _Found(NamedTuple):
    """A None text marks a value the scan could not read: it is counted as
    not scanned, never treated as clean."""

    path: tuple[Segment, ...]
    text: str | None
    header: str | None = None
    # The text is the attribute or kvlist key at the end of `path`.
    key: bool = False


def _undefined(
    fields: dict[str, object], defined: frozenset[str], path: tuple[Segment, ...],
    out: list[_Found],
) -> None:
    """Each member of `fields` outside `defined` holding data (anything but
    null or an empty string, list or object) is counted as not scanned."""
    out.extend(
        _Found(path, None)
        for name, value in fields.items()
        if name not in defined
        and value is not None
        and not (isinstance(value, str | list | dict) and not value)
    )


def _bytes_text(value: object) -> str | None:
    """A bytesValue is base64 in OTLP/JSON; it is scanned as text when it
    decodes as UTF-8."""
    decoded = decode_bytes_value(value) if isinstance(value, str) else None
    try:
        return None if decoded is None else decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _walk_value(
    value: object,
    path: tuple[Segment, ...],
    out: list[_Found],
    depth: int = 0,
    header: str | None = None,
    *,
    log: bool = False,
) -> None:
    """A string is collected; an array or kvlist recurses with [i] / .key
    appended. In a log record a bytes value is collected too. Any shape
    holding no readable string other than a number or boolean is counted as
    not scanned. An array element keeps the header its attribute names; a
    kvlist entry names its own (see `_header_name`)."""
    if depth > _MAX_DEPTH or not isinstance(value, dict):
        if value is not None:
            out.append(_Found(path, None))
        return
    holder = cast("dict[str, object]", value)
    for wrapper, kind in _LOG_WRAPPERS if log else _SPAN_WRAPPERS:
        inner = holder.get(wrapper)
        if kind == "string" and isinstance(inner, str):
            out.append(_Found(path, inner, header))
        elif kind == "array" and isinstance(inner, dict):
            array = cast("dict[str, object]", inner)
            _undefined(array, _OTLP_FIELDS["values"], path, out)
            items = array.get("values")
            if isinstance(items, list):
                for index, item in enumerate(cast("list[object]", items)):
                    _walk_value(item, (*path, index), out, depth + 1, header, log=log)
            elif items is not None:
                out.append(_Found(path, None))
        elif kind == "kvlist" and isinstance(inner, dict):
            kvlist = cast("dict[str, object]", inner)
            _undefined(kvlist, _OTLP_FIELDS["values"], path, out)
            _walk_attributes(
                kvlist.get("values"),
                path,
                out,
                depth + 1,
                log=log,
                in_kvlist=True,
            )
        elif kind == "bytes" and wrapper in holder:
            out.append(_Found(path, _bytes_text(inner), header))
        elif kind != "scalar" or wrapper not in holder:
            continue
        _undefined(holder, frozenset({wrapper}), path, out)
        return
    if holder:
        out.append(_Found(path, None))


def _header_name(key: str, *, in_kvlist: bool) -> str | None:
    """The authorization header an attribute key names, as written, or None.
    `http.request.header.<name>` names `<name>` anywhere; a bare `<name>`
    names it only as a kvlist entry, where a header map keeps its names."""
    name = key[len(_REQUEST_HEADER):] if key.lower().startswith(_REQUEST_HEADER) else None
    if name is None and in_kvlist:
        name = key
    if name is None or name.lower().replace("_", "-") not in _AUTHORIZATION_HEADERS:
        return None
    return name


def _walk_attributes(
    attributes: object,
    path: tuple[Segment, ...],
    out: list[_Found],
    depth: int = 0,
    *,
    log: bool = False,
    in_kvlist: bool = False,
) -> None:
    if depth > _MAX_DEPTH or not isinstance(attributes, list):
        if attributes is not None:
            out.append(_Found(path, None))
        return
    for raw in cast("list[object]", attributes):
        entry = cast("dict[str, object]", raw) if isinstance(raw, dict) else {}
        key = entry.get("key")
        if not isinstance(key, str):
            out.append(_Found(path, None))
            continue
        _undefined(entry, _OTLP_FIELDS["keyValue"], (*path, key), out)
        if key:
            out.append(_Found((*path, key), key, key=True))
        header = _header_name(key, in_kvlist=in_kvlist)
        _walk_value(entry.get("value"), (*path, key), out, depth, header, log=log)


def _span_surface(ctx: SpanInContext) -> list[_Found]:
    """Every string location of one span, in the spec's declared order."""
    out: list[_Found] = []
    _undefined(ctx.span_entry, _OTLP_FIELDS["span"], (), out)
    if ctx.span.name:
        out.append(_Found(("name",), ctx.span.name))
    _present_text(ctx.span.trace_state, ("traceState",), out)
    _walk_attributes(ctx.span.attributes, ("attributes",), out)
    # `traceState`, `status`, `events` and `links` are raw pass-throughs on
    # the wire struct - typing them would quarantine spans that decode today
    # - so every access here is guarded, exactly as stage 2 guards attribute
    # element access. Read each once into a local before narrowing:
    # re-narrowing a member access (`ctx.span.events` repeated) leaves pyright
    # reporting it partially unknown even inside the isinstance guard, where
    # narrowing a plain local does not.
    events = ctx.span.events
    if isinstance(events, list):
        for index, event in enumerate(cast("list[object]", events)):
            if not isinstance(event, dict):
                out.append(_Found(("events", index), None))
                continue
            fields = cast("dict[str, object]", event)
            _undefined(fields, _OTLP_FIELDS["event"], ("events", index), out)
            _present_text(fields.get("name"), ("events", index, "name"), out)
            _walk_attributes(fields.get("attributes"), ("events", index, "attributes"), out)
    elif events is not None:
        out.append(_Found(("events",), None))
    links = ctx.span.links
    if isinstance(links, list):
        for index, link in enumerate(cast("list[object]", links)):
            if not isinstance(link, dict):
                out.append(_Found(("links", index), None))
                continue
            fields = cast("dict[str, object]", link)
            _undefined(fields, _OTLP_FIELDS["link"], ("links", index), out)
            _present_text(fields.get("traceState"), ("links", index, "traceState"), out)
            _walk_attributes(fields.get("attributes"), ("links", index, "attributes"), out)
    elif links is not None:
        out.append(_Found(("links",), None))
    status = ctx.span.status
    if isinstance(status, dict):
        fields = cast("dict[str, object]", status)
        _undefined(fields, _OTLP_FIELDS["status"], ("status",), out)
        _present_text(fields.get("message"), ("status", "message"), out)
    elif status is not None:
        out.append(_Found(("status",), None))
    return out


def _present_text(value: object, path: tuple[Segment, ...], out: list[_Found]) -> None:
    """A name or message: a non-empty string is collected, an empty one or
    None holds nothing, and anything else is counted as not scanned."""
    if value is not None and value != "":
        out.append(_Found(path, value if isinstance(value, str) else None))


def _log_surface(ctx: LogRecordInContext) -> list[_Found]:
    """A log record's eventName, severityText, attributes, then its body:
    an AnyValue, so a string, array or kvlist body reads `body`, `body[i]`
    or `body.key`. A body written as a bare string is read as that string."""
    out: list[_Found] = []
    _undefined(ctx.record, _OTLP_FIELDS["logRecord"], (), out)
    _present_text(ctx.record.get("eventName"), ("eventName",), out)
    _present_text(ctx.record.get("severityText"), ("severityText",), out)
    _walk_attributes(ctx.record.get("attributes"), ("attributes",), out, log=True)
    body = ctx.record.get("body")
    if isinstance(body, str):
        out.append(_Found(("body",), body))
    else:
        _walk_value(body, ("body",), out, log=True)
    return out


def _entity_refs(refs: object, out: list[_Found]) -> None:
    """A resource's entityRefs: each one's schemaUrl, type, and the
    attribute keys it lists."""
    if not isinstance(refs, list):
        if refs is not None:
            out.append(_Found(("resource", "entityRefs"), None))
        return
    for index, ref in enumerate(cast("list[object]", refs)):
        path: tuple[Segment, ...] = ("resource", "entityRefs", index)
        if not isinstance(ref, dict):
            out.append(_Found(path, None))
            continue
        fields = cast("dict[str, object]", ref)
        _undefined(fields, _OTLP_FIELDS["entityRef"], path, out)
        _present_text(fields.get("schemaUrl"), (*path, "schemaUrl"), out)
        _present_text(fields.get("type"), (*path, "type"), out)
        for name in ("idKeys", "descriptionKeys"):
            keys = fields.get(name)
            if isinstance(keys, list):
                for key_index, key in enumerate(cast("list[object]", keys)):
                    _present_text(key, (*path, name, key_index), out)
            elif keys is not None:
                out.append(_Found((*path, name), None))


def _context_surface(
    ctx: SpanInContext | LogRecordInContext, seen: set[int], *, log: bool = False
) -> list[_Found]:
    """The resource (its schemaUrl, attributes and entityRefs) and the scope
    (its schemaUrl, name, version and attributes) are each visited ONCE,
    attributed to the first span or log record that arrived under them.

    id()-keyed dedupe is only correct because the wire contexts store plain
    field references that stay alive for the life of the `WireInput` - a
    future computed property here would return a fresh object each access
    and silently defeat this."""
    out: list[_Found] = []
    if id(ctx.resource_attributes) not in seen:
        seen.add(id(ctx.resource_attributes))
        entry = "resourceLogs" if log else "resourceSpans"
        _undefined(ctx.resource_entry, _OTLP_FIELDS[entry], (), out)
        _present_text(ctx.resource_entry.get("schemaUrl"), ("resource", "schemaUrl"), out)
        _walk_attributes(ctx.resource_attributes, ("resource", "attributes"), out, log=log)
        resource = ctx.resource_entry.get("resource")
        if isinstance(resource, dict):
            fields = cast("dict[str, object]", resource)
            _undefined(fields, _OTLP_FIELDS["resource"], ("resource",), out)
            _entity_refs(fields.get("entityRefs"), out)
    scope = ctx.scope
    if id(scope) not in seen:
        seen.add(id(scope))
        _undefined(ctx.scope_entry, _OTLP_FIELDS["scopeLogs" if log else "scopeSpans"], (), out)
        raw_scope = ctx.scope_entry.get("scope")
        if isinstance(raw_scope, dict):
            fields = cast("dict[str, object]", raw_scope)
            _undefined(fields, _OTLP_FIELDS["scope"], ("scope",), out)
        _present_text(ctx.scope_entry.get("schemaUrl"), ("scope", "schemaUrl"), out)
        _present_text(scope.name, ("scope", "name"), out)
        _present_text(scope.version, ("scope", "version"), out)
        _walk_attributes(scope.attributes, ("scope", "attributes"), out, log=log)
    return out


def scan_surface(wire: WireInput) -> ExposureSurface:
    seen: set[int] = set()
    strings: list[ScannedString] = []
    unread = wire.values_not_scanned

    def readable(found: list[_Found]) -> list[tuple[_Found, str]]:
        nonlocal unread
        unread += sum(f.text is None for f in found)
        return [(f, f.text) for f in found if f.text is not None]

    for span_index, ctx in enumerate(wire.spans):
        found = readable(
            _span_surface(ctx) + _context_surface(ctx, seen)
        )
        span_ref = ctx.span.span_id.strip().lower()
        strings.extend(
            ScannedString(
                record_index=span_index,
                span_ref=span_ref,
                span_name=ctx.span.name,
                path=f.path,
                text=text,
                header=f.header,
                key=f.key,
            )
            for f, text in found
        )
    for log_index, ctx in enumerate(wire.log_records):
        found = readable(
            _log_surface(ctx) + _context_surface(ctx, seen, log=True)
        )
        strings.extend(
            ScannedString(
                record_index=len(wire.spans) + log_index,
                span_ref="",
                span_name="",
                path=f.path,
                text=text,
                header=f.header,
                log_record=ctx.position,
                key=f.key,
            )
            for f, text in found
        )

    return ExposureSurface(
        applicable=True,
        spans_scanned=len(wire.spans),
        strings=strings,
        log_records_scanned=len(wire.log_records),
        batches_not_scanned=wire.batches_not_scanned,
        values_not_scanned=unread,
    )
