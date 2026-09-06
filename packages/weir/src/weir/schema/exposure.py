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
    span_index: int  # position in the wire batch; the hit ordering key
    span_ref: str
    span_name: str
    location: str
    text: str


class ExposureSurface(msgspec.Struct, frozen=True):
    # False for native input, which carries no attributes at all. Reported as
    # "not applicable", never as zero (constitution #5).
    applicable: bool
    spans_scanned: int
    strings: list[ScannedString]
