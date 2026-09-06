"""Exposure records: a PRESENCE fact about one location, not a flow.

No source node, no sink node, no join, no taint - so no witness path and no
degraded-node clause. The record never carries the value (G4). `last4` and
`fingerprint` are recorded only for ELIGIBLE hits: a triage hit may be a weak
password, and an unsalted hash (or a suffix of one) is a dictionary target.

The fingerprint is deliberately unsalted. Its whole job is to say "same key"
across spans, captures and CI runs, which a per-run salt would defeat; that is
safe for the classes that carry it because eligibility makes them
high-entropy. Algorithm version 1 is sha256(value.encode("utf-8")) as hex,
first 12 characters; `fingerprint_v` rides on every hit so a hash-input change
is a version bump, never a silent migration.
"""

from __future__ import annotations

import msgspec


class ExposureHit(msgspec.Struct, frozen=True):
    span_ref: str
    span_name: str
    location: str
    source_class: str
    eligible: bool
    value_len: int
    prefix: str
    last4: str | None = None
    fingerprint: str | None = None
    fingerprint_v: int = 1


class ExposureScan(msgspec.Struct, frozen=True):
    applicable: bool
    spans_scanned: int
    strings_scanned: int
    hits: list[ExposureHit]
