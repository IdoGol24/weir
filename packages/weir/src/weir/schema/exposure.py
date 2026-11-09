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

import msgspec


class ScannedString(msgspec.Struct, frozen=True):
    # Position of its span or log record in the input, spans first; the hit
    # ordering key.
    record_index: int
    span_ref: str
    span_name: str
    location: str
    text: str
    # The authorization request header `text` is the value of, when the
    # attribute key names one (`http.request.header.authorization` or
    # `http.request.header.proxy-authorization`, any case); the classifier
    # then reads the string as the header line `<name>: <text>`.
    header: str | None = None
    # The log record's 0-based index in the input when the string is in a log
    # record; `span_ref` and `span_name` are then empty.
    log_record: int | None = None


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
