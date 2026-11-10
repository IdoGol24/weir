"""Stage 1b: the raw wire batch -> every string it contains, with a location.
Spans and log records are read the same way, except that a log record is
also read in the shapes listed at `_LOG_WRAPPERS` and reports what it cannot
read.

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

from typing import cast

from weir.adapters.otel._wire import LogRecordInContext, SpanInContext, WireInput, WireScope
from weir.canary.walk import decode_bytes_value
from weir.schema.exposure import ExposureSurface, ScannedString

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
# camelCase string carriers only, exactly as it always has. A log record
# also reads the snake_case spellings protojson writes with proto field
# names, decodes bytes, and passes numbers and booleans as holding no string.
_SPAN_WRAPPERS = (("stringValue", "string"), ("arrayValue", "array"), ("kvlistValue", "kvlist"))
_LOG_WRAPPERS = (
    ("stringValue", "string"), ("string_value", "string"),
    ("bytesValue", "bytes"), ("bytes_value", "bytes"),
    ("arrayValue", "array"), ("array_value", "array"),
    ("kvlistValue", "kvlist"), ("kvlist_value", "kvlist"),
    ("intValue", "scalar"), ("int_value", "scalar"),
    ("doubleValue", "scalar"), ("double_value", "scalar"),
    ("boolValue", "scalar"), ("bool_value", "scalar"),
)

# (location, text, header). A None text marks a log-record value the scan
# could not read: it is counted as not scanned, never treated as clean.
# Span values in a shape the scan does not read are passed over, as before.
_Found = tuple[str, str | None, str | None]


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
    location: str,
    out: list[_Found],
    depth: int = 0,
    header: str | None = None,
    *,
    log: bool = False,
) -> None:
    """A string is collected; an array or kvlist recurses with [i] / .key
    appended. In a log record a bytes value is collected too, and any shape
    holding no readable string other than a number or boolean is counted as
    not scanned. An array element keeps the header its attribute names; a
    kvlist entry names its own (see `_header_name`)."""
    if depth > _MAX_DEPTH or not isinstance(value, dict):
        if log and value is not None:
            out.append((location, None, None))
        return
    holder = cast("dict[str, object]", value)
    for wrapper, kind in _LOG_WRAPPERS if log else _SPAN_WRAPPERS:
        inner = holder.get(wrapper)
        if kind == "string" and isinstance(inner, str):
            out.append((location, inner, header))
        elif kind == "array" and isinstance(inner, dict):
            items = cast("dict[str, object]", inner).get("values")
            if isinstance(items, list):
                for index, item in enumerate(cast("list[object]", items)):
                    _walk_value(item, f"{location}[{index}]", out, depth + 1, header, log=log)
            elif log and items is not None:
                out.append((location, None, None))
        elif kind == "kvlist" and isinstance(inner, dict):
            _walk_attributes(
                cast("dict[str, object]", inner).get("values"),
                location,
                out,
                depth + 1,
                log=log,
                in_kvlist=True,
            )
        elif kind == "bytes" and wrapper in holder:
            out.append((location, _bytes_text(inner), header))
        elif kind != "scalar" or wrapper not in holder:
            continue
        return
    if log and holder:
        out.append((location, None, None))


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
    location: str,
    out: list[_Found],
    depth: int = 0,
    *,
    log: bool = False,
    in_kvlist: bool = False,
) -> None:
    if depth > _MAX_DEPTH or not isinstance(attributes, list):
        if log and attributes is not None:
            out.append((location, None, None))
        return
    for raw in cast("list[object]", attributes):
        entry = cast("dict[str, object]", raw) if isinstance(raw, dict) else {}
        key = entry.get("key")
        if not isinstance(key, str):
            if log:
                out.append((location, None, None))
            continue
        header = _header_name(key, in_kvlist=in_kvlist)
        _walk_value(entry.get("value"), f"{location}.{key}", out, depth, header, log=log)


def _span_surface(ctx: SpanInContext) -> list[_Found]:
    """Every string location of one span, in the spec's declared order."""
    out: list[_Found] = []
    _walk_attributes(ctx.span.attributes, "attributes", out)
    # `status` and `events` are raw pass-throughs on the wire struct - typing
    # them would quarantine spans that decode today - so every access here is
    # guarded, exactly as stage 2 guards attribute element access. Read each
    # once into a local before narrowing: re-narrowing a member access
    # (`ctx.span.events` repeated) leaves pyright reporting it partially
    # unknown even inside the isinstance guard, where narrowing a plain local
    # does not.
    events = ctx.span.events
    if isinstance(events, list):
        for index, event in enumerate(cast("list[object]", events)):
            if isinstance(event, dict):
                _walk_attributes(
                    cast("dict[str, object]", event).get("attributes"),
                    f"events[{index}].attributes",
                    out,
                )
    status = ctx.span.status
    if isinstance(status, dict):
        message = cast("dict[str, object]", status).get("message")
        if isinstance(message, str) and message:
            out.append(("status.message", message, None))
    return out


def _log_surface(ctx: LogRecordInContext) -> list[_Found]:
    """A log record's attributes, then its body: an AnyValue, so a string,
    array or kvlist body reads `body`, `body[i]` or `body.key`. A body
    written as a bare string is read as that string."""
    out: list[_Found] = []
    _walk_attributes(ctx.record.get("attributes"), "attributes", out, log=True)
    body = ctx.record.get("body")
    if isinstance(body, str):
        out.append(("body", body, None))
    else:
        _walk_value(body, "body", out, log=True)
    return out


def _context_surface(
    resource_attributes: list[dict[str, object]],
    scope: WireScope,
    seen: set[int],
    *,
    log: bool = False,
) -> list[_Found]:
    """Resource and scope attributes are visited ONCE, attributed to the
    first span or log record that arrived under them.

    id()-keyed dedupe is only correct because the wire contexts store plain
    field references that stay alive for the life of the `WireInput` - a
    future computed property here would return a fresh object each access
    and silently defeat this."""
    out: list[_Found] = []
    if id(resource_attributes) not in seen:
        seen.add(id(resource_attributes))
        _walk_attributes(resource_attributes, "resource.attributes", out, log=log)
    if id(scope) not in seen:
        seen.add(id(scope))
        _walk_attributes(scope.attributes, "scope.attributes", out, log=log)
    return out


def scan_surface(wire: WireInput) -> ExposureSurface:
    seen: set[int] = set()
    strings: list[ScannedString] = []
    unread = wire.values_not_scanned

    def readable(found: list[_Found]) -> list[tuple[str, str, str | None]]:
        nonlocal unread
        unread += sum(text is None for _, text, _ in found)
        return [(location, text, header) for location, text, header in found if text is not None]

    for span_index, ctx in enumerate(wire.spans):
        found = readable(
            _span_surface(ctx) + _context_surface(ctx.resource_attributes, ctx.scope, seen)
        )
        span_ref = ctx.span.span_id.strip().lower()
        strings.extend(
            ScannedString(
                record_index=span_index,
                span_ref=span_ref,
                span_name=ctx.span.name,
                location=location,
                text=text,
                header=header,
            )
            for location, text, header in found
        )
    for log_index, ctx in enumerate(wire.log_records):
        found = readable(
            _log_surface(ctx) + _context_surface(ctx.resource_attributes, ctx.scope, seen, log=True)
        )
        strings.extend(
            ScannedString(
                record_index=len(wire.spans) + log_index,
                span_ref="",
                span_name="",
                location=location,
                text=text,
                header=header,
                log_record=ctx.position,
            )
            for location, text, header in found
        )

    return ExposureSurface(
        applicable=True,
        spans_scanned=len(wire.spans),
        strings=strings,
        log_records_scanned=len(wire.log_records),
        batches_not_scanned=wire.batches_not_scanned,
        values_not_scanned=unread,
    )
