"""Exposure classification (spec 2026-09-06 section 2): a scanned surface plus
the catalog -> value-free hits. Pure, and a sidecar beside the flow engine
rather than a stage of it.

The strings arrive already enumerated by `weir.adapters.otel.exposure`, which
is why this module needs no wire model and never imports `weir.adapters` - the
"Analysis-path purity" contract holds it to that.
"""

from __future__ import annotations

import hashlib
import re

import msgspec

from weir.catalog import Catalog, SourceSpec, class_prefix, is_verbatim_eligible
from weir.exposure._types import ExposureHit, ExposureScan
from weir.schema.exposure import ExposureSurface, ScannedString

FINGERPRINT_VERSION = 1

_REGEX_META = frozenset(".^$*+?{}[]\\|()")


class _RawHit(msgspec.Struct, frozen=True):
    """One match before subsumption and triage dedupe. Carries the value and
    its offsets, which the public ExposureHit deliberately does not."""

    span_index: int
    span_ref: str
    span_name: str
    location: str
    start: int
    spec: SourceSpec
    value: str
    prefix: str
    eligible: bool
    value_start: int
    value_end: int
    has_group: bool


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _literal_prefix(pattern: str) -> str:
    """The leading LITERAL run of a content_pattern. Two classes can match at
    one offset (`sk-` and `sk-ant-`); the longer literal prefix is the more
    specific class and wins. A leading \\b is skipped and scanning stops at the
    first metacharacter, so `(?:AKIA|ASIA)...` and the `(?i)`-prefixed
    credential_field pattern both yield "" and lose every tie - correct, since
    neither is a prefix refinement of anything."""
    out: list[str] = []
    for ch in pattern.removeprefix("\\b"):
        if ch in _REGEX_META:
            break
        out.append(ch)
    return "".join(out)


def _has_floor(spec: SourceSpec) -> bool:
    e = spec.eligibility
    return e.structure_class is not None or e.pattern is not None or e.min_length is not None


def _raw_hits_for(
    scanned: ScannedString, classes: list[tuple[SourceSpec, re.Pattern[str], int]]
) -> list[_RawHit]:
    # Class assignment happens BEFORE eligibility and is final: at one offset
    # the longest literal prefix wins, so one value yields one hit per
    # location, never two. An sk-ant- value that fails the strict Anthropic
    # pattern stays an anthropic_api_key MISS; it is never re-graded under
    # openai_api_key. A miss must stay visible as a miss. Do not "fix" this.
    best: dict[int, tuple[int, SourceSpec, re.Match[str]]] = {}
    for spec, pattern, prefix_len in classes:
        for match in pattern.finditer(scanned.text):
            incumbent = best.get(match.start())
            if incumbent is None or prefix_len > incumbent[0]:
                best[match.start()] = (prefix_len, spec, match)

    hits: list[_RawHit] = []
    for start in sorted(best):
        _, spec, match = best[start]
        has_group = match.re.groups > 0
        if has_group:
            # An assignment-shaped class captures the SECRET in group 1; the
            # text before it is the key name, which is the display prefix.
            value = match.group(1) or ""
            prefix = match.group(0)[: match.start(1) - match.start(0)].rstrip("'\" =:")
            value_start, value_end = match.span(1)
        else:
            value = match.group(0)
            prefix = class_prefix(value)
            value_start, value_end = match.span(0)
        eligible = is_verbatim_eligible(value, spec)
        if (
            not eligible
            and not _has_floor(spec)
            and any(re.fullmatch(p, value) is not None for p in spec.eligibility.reject_patterns)
        ):
            # A triage-only class declares no floor, so there is no weaker
            # state to demote a rejected value to: a masked `api_key='***'` is
            # excluded outright rather than parked in the review queue forever.
            continue
        hits.append(_RawHit(
            span_index=scanned.span_index, span_ref=scanned.span_ref,
            span_name=scanned.span_name, location=scanned.location, start=start,
            spec=spec, value=value, prefix=prefix, eligible=eligible,
            value_start=value_start, value_end=value_end, has_group=has_group,
        ))
    return hits


def _subsumed(hit: _RawHit, raw: list[_RawHit]) -> bool:
    """`api_key='sk-proj-...'` matches credential_field at the key name and
    openai_api_key at the value, so the offset rule does not dedupe them. Drop
    the assignment-shaped hit when an eligible hit of another class lies inside
    its value group: the verdict-grade hit is the stronger claim about the same
    bytes, and keeping both would double every location in the report and the
    gauge."""
    if not hit.has_group:
        return False
    return any(
        other.eligible
        and other.span_index == hit.span_index
        and other.location == hit.location
        and hit.value_start <= other.start < hit.value_end
        for other in raw
    )


def classify_exposure(surface: ExposureSurface, catalog: Catalog) -> ExposureScan:
    classes = [
        (spec, re.compile(spec.content_pattern), len(_literal_prefix(spec.content_pattern)))
        for spec in catalog.sources
        if spec.exposure
    ]

    raw: list[_RawHit] = []
    for scanned in surface.strings:
        raw.extend(_raw_hits_for(scanned, classes))

    hits: list[ExposureHit] = []
    triage_seen: set[tuple[str, str, str]] = set()
    for hit in sorted(raw, key=lambda h: (h.span_index, h.location, h.start)):
        if _subsumed(hit, raw):
            continue
        if not hit.eligible:
            key = (hit.span_ref, hit.location, hit.spec.name)
            if key in triage_seen:
                continue
            triage_seen.add(key)
        hits.append(ExposureHit(
            span_ref=hit.span_ref,
            span_name=hit.span_name,
            location=hit.location,
            source_class=hit.spec.name,
            eligible=hit.eligible,
            value_len=len(hit.value),
            prefix=hit.prefix,
            last4=hit.value[-4:] if hit.eligible else None,
            fingerprint=_fingerprint(hit.value) if hit.eligible else None,
            fingerprint_v=FINGERPRINT_VERSION,
        ))

    return ExposureScan(
        applicable=surface.applicable,
        spans_scanned=surface.spans_scanned,
        strings_scanned=len(surface.strings),
        hits=hits,
    )
