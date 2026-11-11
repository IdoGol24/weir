"""The seam between the adapter's string walk and the pure exposure
classifier (spec 2026-09-06 section 2).

It lives in `weir.schema` because that is the one package both sides are
allowed to reach: `weir.adapters` may not import the catalog, and the pure
layer may not import `weir.adapters`, so the type they agree on can live in
neither. Enumeration on one side, judgement on the other, this in between.

`ScannedString.text` is raw exported content and is the only value-carrying
struct in this package. It is an IN-MEMORY transport: it is never encoded,
never reaches `CanonicalTrace`, and never survives past
`classify_exposure`, which converts it into value-free hits. Do not
serialize it, and do not put it on a report type.
"""

from __future__ import annotations

from collections.abc import Callable

import msgspec

# One step of a location: a field or attribute key, or an array index.
type Segment = str | int


# Marks a location whose string is the attribute or kvlist key at the end
# of its path, not that key's value: `attributes.app.cred (key)`.
KEY_MARK = " (key)"


def format_location(
    path: tuple[Segment, ...], show: Callable[[str], str] = str, *, key: bool = False
) -> str:
    """`attributes.app.config`, `events[0].attributes.k`: a key is joined
    with `.`, an index is written `[i]`. `show` renders each key, so a key
    that holds a matched value can be printed as `[withheld]` on its own
    (docs/scan.md, "Why you can trust it"). `key` marks the location of the
    last key itself, not of its value."""
    out = ""
    for segment in path:
        if isinstance(segment, int):
            out += f"[{segment}]"
        else:
            out += ("." if out else "") + show(segment)
    return out + KEY_MARK if key else out


class ScannedString(msgspec.Struct, frozen=True):
    # Position of its span or log record in the input, spans first; the hit
    # ordering key.
    record_index: int
    span_ref: str
    span_name: str
    # Kept as segments, not a joined string: an attribute key may hold dots,
    # so a joined location cannot be split back into the keys it was made of.
    path: tuple[Segment, ...]
    text: str
    # The authorization request header `text` is the value of, when the
    # attribute key names one: `http.request.header.authorization` or
    # `http.request.header.proxy-authorization` anywhere, or a bare
    # `authorization` or `proxy-authorization` as a kvlist entry at any depth
    # (a header map recorded as one attribute), any case and with `_` for `-`
    # (`proxy_authorization`). The name is kept as written, and the
    # classifier then reads the string as the header line `<name>: <text>`.
    header: str | None = None
    # The log record's 0-based index in the input when the string is in a log
    # record; `span_ref` and `span_name` are then empty.
    log_record: int | None = None
    # True when `text` is the attribute or kvlist key at the end of `path`,
    # not its value: the location is then marked (`KEY_MARK`).
    key: bool = False

    @property
    def location(self) -> str:
        return format_location(self.path, key=self.key)


class ExposureSurface(msgspec.Struct, frozen=True):
    # False for native input, which carries no attributes at all. Reported as
    # "not applicable", never as zero (constitution #5).
    applicable: bool
    spans_scanned: int
    strings: list[ScannedString]
    log_records_scanned: int = 0
    # Batches holding data the scan cannot read (metrics, another signal, or
    # nothing OTLP-shaped): reported as not scanned, never as clean.
    batches_not_scanned: int = 0
    # Values inside the read data whose shape the scan could not read
    # (an undecodable bytesValue, a list given as an object, a depth past
    # the cap): reported as not scanned, never as clean.
    values_not_scanned: int = 0
