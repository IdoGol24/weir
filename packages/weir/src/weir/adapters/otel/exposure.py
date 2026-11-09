"""Stage 1b: the raw wire batch -> every string it contains, with a location.

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

from weir.adapters.otel._wire import SpanInContext, WireInput
from weir.schema.exposure import ExposureSurface, ScannedString

# ponytail: hard depth cap, no ledger entry. Real OTLP kvlists are one or two
# levels deep; anything at 64 is malformed or hostile, and crashing the scan
# is strictly worse than not walking it. Upgrade path: if a real payload ever
# trips this, record a degradation rather than raising the cap.
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

_Found = tuple[str, str, str | None]


def _walk_value(
    value: object,
    location: str,
    out: list[_Found],
    depth: int = 0,
    header: str | None = None,
) -> None:
    """stringValue is collected; arrayValue and kvlistValue recurse with [i] /
    .key appended; every other value type is skipped, never coerced. An
    array element keeps the header its attribute names; a kvlist entry names
    its own (see `_header_name`)."""
    if depth > _MAX_DEPTH:
        return
    if not isinstance(value, dict):
        return
    holder = cast("dict[str, object]", value)
    text = holder.get("stringValue")
    if isinstance(text, str):
        out.append((location, text, header))
        return
    array = holder.get("arrayValue")
    if isinstance(array, dict):
        items = cast("dict[str, object]", array).get("values")
        if isinstance(items, list):
            for index, item in enumerate(cast("list[object]", items)):
                _walk_value(item, f"{location}[{index}]", out, depth + 1, header)
        return
    kvlist = holder.get("kvlistValue")
    if isinstance(kvlist, dict):
        _walk_attributes(
            cast("dict[str, object]", kvlist).get("values"),
            location,
            out,
            depth + 1,
            in_kvlist=True,
        )


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
    in_kvlist: bool = False,
) -> None:
    if depth > _MAX_DEPTH:
        return
    if not isinstance(attributes, list):
        return
    for raw in cast("list[object]", attributes):
        if not isinstance(raw, dict):
            continue
        entry = cast("dict[str, object]", raw)
        key = entry.get("key")
        if isinstance(key, str):
            header = _header_name(key, in_kvlist=in_kvlist)
            _walk_value(entry.get("value"), f"{location}.{key}", out, depth, header)


def _span_surface(
    ctx: SpanInContext, *, first_of_resource: bool, first_of_scope: bool
) -> list[_Found]:
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
    # Resource and scope attributes are visited ONCE, attributed to the first
    # span that arrived under them.
    if first_of_resource:
        _walk_attributes(ctx.resource_attributes, "resource.attributes", out)
    if first_of_scope:
        _walk_attributes(ctx.scope.attributes, "scope.attributes", out)
    return out


def scan_surface(wire: WireInput) -> ExposureSurface:
    seen_resources: set[int] = set()
    seen_scopes: set[int] = set()
    strings: list[ScannedString] = []

    for span_index, ctx in enumerate(wire.spans):
        # id()-keyed dedupe is only correct because SpanInContext stores plain
        # field references that stay alive for the life of `wire.spans` - a
        # future computed property here would return a fresh object each
        # access and silently defeat this.
        resource_key, scope_key = id(ctx.resource_attributes), id(ctx.scope)
        found = _span_surface(
            ctx,
            first_of_resource=resource_key not in seen_resources,
            first_of_scope=scope_key not in seen_scopes,
        )
        seen_resources.add(resource_key)
        seen_scopes.add(scope_key)
        span_ref = ctx.span.span_id.strip().lower()
        strings.extend(
            ScannedString(
                span_index=span_index,
                span_ref=span_ref,
                span_name=ctx.span.name,
                location=location,
                text=text,
                header=header,
            )
            for location, text, header in found
        )

    return ExposureSurface(
        applicable=True, spans_scanned=len(wire.spans), strings=strings
    )
