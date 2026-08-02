"""Catalog data model (C1) — minimal, inline for this demo slice per the
demo-slice doc's L3 notes; the full rule/catalog/report/gauge schema layer
(execution-plan L4/L5) is deferred. Guards, canon v2 normalizer definitions,
and the event-source registry are out of scope here (no guard-bearing
scenario in this slice; canon v2 and events are deferred to M2/NEW-ATR)."""

from __future__ import annotations

import msgspec


class VerbatimEligibility(msgspec.Struct, frozen=True):
    """R5.9: exactly one of these determines whether a value clears the
    floor for the source class it's attached to — a value long enough for
    some *other* class is not automatically eligible for this one."""

    structure_class: str | None = None
    min_length: int | None = None


class SourceSpec(msgspec.Struct, frozen=True):
    """A content-pattern source class (R4.1-4.5): `content_pattern` is a
    deliberately loose regex — it is allowed to over-match (e.g. a bare
    numeral alongside a real IBAN) because `eligibility` (R5.9), not the
    label pattern, is what must discriminate a genuine secret from an
    incidental digit string."""

    name: str
    content_pattern: str
    eligibility: VerbatimEligibility


class SinkSpec(msgspec.Struct, frozen=True):
    """A tool-pattern sink (R4.1-4.5): `destination_arg_keys` names the args
    the labeler recursively descends into to find the true destination."""

    tool_name: str
    destination_arg_keys: list[str]


class Catalog(msgspec.Struct, frozen=True):
    sources: list[SourceSpec]
    sinks: list[SinkSpec]
    remediations: dict[str, str]
