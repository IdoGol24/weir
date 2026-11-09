"""Exposure classification (spec 2026-09-06 section 2): a scanned surface plus
the catalog -> value-free hits. Pure, and a sidecar beside the flow engine
rather than a stage of it.

The strings arrive already enumerated by `weir.adapters.otel.exposure`, which
is why this module needs no wire model and never imports `weir.adapters` - the
"Analysis-path purity" contract holds it to that.

This is also the one place the matched values and the names they sit under
are both in hand, so it is where a span id, span name or location key that
holds a matched value becomes `[withheld]` (docs/scan.md, "Why you can trust it").
Every renderer downstream prints hits as they are and cannot get a name back.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from typing import NamedTuple

import msgspec

from weir._text_safety import flatten_untrusted
from weir.canary import needles
from weir.canary._types import RUN
from weir.canary.text import WITHHELD
from weir.catalog import (
    Catalog,
    SourceSpec,
    assignment_prefix,
    class_prefix,
    is_verbatim_eligible,
    matched_value,
)
from weir.exposure._types import ExposureHit, ExposureScan
from weir.schema.exposure import ExposureSurface, ScannedString, Segment, format_location

FINGERPRINT_VERSION = 1

# A value this short, plus its own last4, could be reconstructed from the
# hit alone - see the last4= line in classify_exposure below.
_MIN_LAST4_VALUE_LEN = 12

# A needle at least this long is looked up by its last this-many bytes.
_TAIL = 8

_REGEX_META = frozenset(".^$*+?{}[]\\|()")

# The leading boundaries a key-shaped content_pattern may open with: the
# escape-aware one (a word boundary, or right after a JSON \n, \t or \r
# escape) and the plain word boundary. Longest first.
_LEADING_BOUNDARIES = ("(?:\\b|(?<=\\\\[ntr]))", "\\b")


class _RawHit(msgspec.Struct, frozen=True):
    """One match after subsumption, before triage/eligible dedupe. Carries
    the value, which the public ExposureHit deliberately does not."""

    span_index: int
    span_ref: str
    span_name: str
    path: tuple[Segment, ...]
    location: str
    start: int
    spec: SourceSpec
    value: str
    prefix: str
    eligible: bool


class _Candidate(NamedTuple):
    """One match at one (span, location), before subsumption. `value_start`,
    `value_end` and `has_group` exist only to decide subsumption at THIS
    location, so they never make it into `_RawHit`."""

    spec: SourceSpec
    start: int
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
    specific class and wins. A leading boundary (`_LEADING_BOUNDARIES`) is
    skipped and scanning stops at the first metacharacter, so `(?:AKIA|ASIA)...`
    and the `(?i)`-prefixed credential_field pattern both yield "" and lose
    every tie - correct, since neither is a prefix refinement of anything."""
    for boundary in _LEADING_BOUNDARIES:
        if pattern.startswith(boundary):
            pattern = pattern[len(boundary):]
            break
    out: list[str] = []
    for ch in pattern:
        if ch in _REGEX_META:
            break
        out.append(ch)
    return "".join(out)


def _has_floor(spec: SourceSpec) -> bool:
    e = spec.eligibility
    return e.structure_class is not None or e.pattern is not None or e.min_length is not None


def _subsumed(cand: _Candidate, candidates: list[_Candidate]) -> bool:
    """`api_key='sk-proj-...'` matches credential_field at the key name and
    openai_api_key at the value, so the offset rule does not dedupe them. Drop
    the assignment-shaped hit when an eligible hit of ANOTHER class lies
    inside its value group: the verdict-grade hit is the stronger claim about
    the same bytes, and keeping both would double every location in the
    report and the gauge.

    `candidates` is always the list for one (span, location) - one
    `_raw_hits_for` call, one `ScannedString` - so unlike the batch-wide scan
    this used to run against, span/location never need comparing here."""
    if not cand.has_group:
        return False
    return any(
        other.eligible
        and other.spec is not cand.spec
        and cand.value_start <= other.start < cand.value_end
        for other in candidates
    )


def _raw_hits_for(
    scanned: ScannedString, classes: list[tuple[SourceSpec, re.Pattern[str], int]]
) -> list[_RawHit]:
    # Class assignment happens BEFORE eligibility and is final: at one offset
    # the longest literal prefix wins, so one value yields one hit per
    # location, never two. An sk-ant- value that fails the strict Anthropic
    # pattern stays an anthropic_api_key MISS; it is never re-graded under
    # openai_api_key. A miss must stay visible as a miss. Do not "fix" this.
    # A tie between two classes that BOTH have a zero-length literal prefix
    # (e.g. `aws_access_key_id`'s `(?:AKIA|ASIA)...` against the
    # `(?i)`-prefixed `credential_field`) falls back to catalog list order -
    # no bundled pair collides at one offset, so this is untested by design,
    # not unhandled.
    text = scanned.text if scanned.header is None else f"{scanned.header}: {scanned.text}"
    best: dict[int, tuple[int, SourceSpec, re.Match[str]]] = {}
    for spec, pattern, prefix_len in classes:
        for match in pattern.finditer(text):
            incumbent = best.get(match.start())
            if incumbent is None or prefix_len > incumbent[0]:
                best[match.start()] = (prefix_len, spec, match)

    candidates: list[_Candidate] = []
    for start in sorted(best):
        _, spec, match = best[start]
        has_group = match.re.groups > 0
        if has_group:
            # An assignment-shaped class captures the SECRET in group 1; the
            # text before it is the key name, which is the display prefix.
            value = matched_value(match.group(1) or "", spec)
            prefix = assignment_prefix(match.group(0)[: match.start(1) - match.start(0)])
            value_start, value_end = match.span(1)
        else:
            value = matched_value(match.group(0), spec)
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
        candidates.append(
            _Candidate(spec, start, value, prefix, eligible, value_start, value_end, has_group)
        )

    return [
        _RawHit(
            span_index=scanned.span_index, span_ref=scanned.span_ref,
            span_name=scanned.span_name, path=scanned.path, location=scanned.location,
            start=cand.start,
            spec=cand.spec, value=cand.value, prefix=cand.prefix, eligible=cand.eligible,
        )
        for cand in candidates
        if not _subsumed(cand, candidates)
    ]


def _withholding(values: set[str]) -> Callable[[str], str]:
    """The canary judge's printing rule, with `values` in the ledger's place:
    text that holds one, or any run of 6 consecutive characters of one,
    prints as `[withheld]`. The flattened form is checked as well, since
    that is what is printed.

    A scan can match a value per span, so each needle is looked up by its
    last `_TAIL` bytes, or a shorter one by its length, and each distinct
    string is checked once: the cost is the length of the strings checked,
    not that times every needle of the scan."""
    runs = frozenset(value[i : i + RUN] for value in values for i in range(len(value) - RUN + 1))
    short: dict[int, set[bytes]] = {}
    by_tail: dict[bytes, set[bytes]] = {}
    for value in values:
        for needle, _ in needles(value):
            if len(needle) < _TAIL:
                short.setdefault(len(needle), set()).add(needle)
            else:
                by_tail.setdefault(needle[-_TAIL:], set()).add(needle)

    def holds_value(text: str) -> bool:
        if any(text[i : i + RUN] in runs for i in range(len(text) - RUN + 1)):
            return True
        data = text.encode("utf-8", errors="surrogatepass")
        if any(
            data[i : i + size] in found
            for size, found in short.items()
            for i in range(len(data) - size + 1)
        ):
            return True
        return any(
            data.endswith(needle, 0, end)
            for end in range(_TAIL, len(data) + 1)
            for needle in by_tail.get(data[end - _TAIL : end], ())
        )

    printed: dict[str, str] = {}

    def withhold(text: str) -> str:
        if text not in printed:
            held = holds_value(text) or holds_value(flatten_untrusted(text))
            printed[text] = WITHHELD if held else text
        return printed[text]

    return withhold


def classify_exposure(surface: ExposureSurface, catalog: Catalog) -> ExposureScan:
    classes = [
        (spec, re.compile(spec.content_pattern), len(_literal_prefix(spec.content_pattern)))
        for spec in catalog.sources
        if spec.exposure
    ]

    raw: list[_RawHit] = []
    for scanned in surface.strings:
        raw.extend(_raw_hits_for(scanned, classes))

    # Every value this scan matched, eligible or triage. A span id is
    # lowercased off the wire, so for it each value counts in lower case too.
    values = {hit.value for hit in raw}
    withhold = _withholding(values)
    withhold_id = _withholding(values | {value.lower() for value in values})
    # Counts key on these ordinals, in hit order, never on the printed text:
    # two locations can both print as `attributes.[withheld]`.
    span_keys: dict[str, int] = {}
    site_keys: dict[tuple[str, str], int] = {}
    hits: list[ExposureHit] = []
    # Dedupe key, both grades: one claim per (span, location, class, value).
    # span_index not span_ref - two spans may legally share a spanId (retries,
    # broken instrumentation, or an attacker-set id), and a security finding
    # must not vanish into a duplicate. The fingerprint distinguishes two
    # different secrets at one location, and is None for triage hits, which
    # collapses this to the (span, location, class) rule triage needs.
    seen: set[tuple[int, str, str, str | None]] = set()
    for hit in sorted(raw, key=lambda h: (h.span_index, h.location, h.start)):
        fingerprint = _fingerprint(hit.value) if hit.eligible else None
        key = (hit.span_index, hit.location, hit.spec.name, fingerprint)
        if key in seen:
            continue
        seen.add(key)
        hits.append(ExposureHit(
            span_ref=withhold_id(hit.span_ref),
            span_name=withhold(hit.span_name),
            location=format_location(hit.path, withhold),
            span_key=span_keys.setdefault(hit.span_ref, len(span_keys)),
            site_key=site_keys.setdefault((hit.span_ref, hit.location), len(site_keys)),
            source_class=hit.spec.name,
            eligible=hit.eligible,
            value_len=len(hit.value),
            prefix=hit.prefix,
            # Never emit a suffix that could reconstruct a short value: the
            # bundled classes are all >= 20 chars, but a contributed catalog
            # sets its own floor and G4 must not depend on it.
            last4=(
                hit.value[-4:]
                if hit.eligible and len(hit.value) >= _MIN_LAST4_VALUE_LEN
                else None
            ),
            fingerprint=fingerprint,
            fingerprint_v=FINGERPRINT_VERSION,
        ))

    return ExposureScan(
        applicable=surface.applicable,
        spans_scanned=surface.spans_scanned,
        strings_scanned=len(surface.strings),
        hits=hits,
    )
