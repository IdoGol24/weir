"""Exposure lines for `weir gauge` (spec section 4). Computed from the scan
alone - no rule is loaded, because the gauge's job is to say what is in the
telemetry, not to judge it.

Constitution #5 both ways: a clean export still prints what was scanned, and
native input says "not applicable" rather than a zero it did not earn.
"""

from __future__ import annotations

from weir._text_safety import flatten_untrusted, plural
from weir.exposure import ExposureScan


def exposure_gauge_lines(scan: ExposureScan) -> list[str]:
    if not scan.applicable:
        return ["exposure scan: not applicable - native input carries no attributes"]
    header = f"exposure scan: {scan.spans_scanned} spans, {scan.strings_scanned} strings"
    if not scan.hits:
        return [f"{header} - no credential-shaped values"]

    lines = [header]
    eligible = [h for h in scan.hits if h.eligible]
    triage = [h for h in scan.hits if not h.eligible]
    if eligible:
        classes = ", ".join(sorted({flatten_untrusted(h.source_class) for h in eligible}))
        locations = len({(h.span_ref, h.location) for h in eligible})
        spans = len({h.span_ref for h in eligible})
        lines.append(
            f"  credentials: {len({h.fingerprint for h in eligible})} distinct "
            f"({classes}) in {plural(locations, 'location')} across "
            f"{plural(spans, 'span')}"
        )
    if triage:
        classes = ", ".join(sorted({flatten_untrusted(h.source_class) for h in triage}))
        locations = len({(h.span_ref, h.location) for h in triage})
        # "match" pluralises irregularly (matches, not matchs) - plural() only
        # handles the regular +s case, so this one stays a manual ternary.
        match_word = "match" if len(triage) == 1 else "matches"
        lines.append(
            f"  triage: {len(triage)} credential-shaped {match_word} "
            f"({classes}) in {plural(locations, 'location')}"
        )
    return lines
