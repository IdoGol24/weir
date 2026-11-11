"""Exposure lines for `weir gauge` (spec section 4). Computed from the scan
alone - no rule is loaded, because the gauge's job is to say what is in the
telemetry, not to judge it.

Constitution #5 both ways: a clean export still prints what was scanned, and
native input says "not applicable" rather than a zero it did not earn.
"""

from __future__ import annotations

from weir._text_safety import flatten_untrusted, plural, records_phrase
from weir.exposure import ExposureScan


def not_scanned_lines(scan: ExposureScan) -> list[str]:
    """Data the scan could not read is said, never folded into a clean
    result. `weir scan` prints the same line."""
    lines: list[str] = []
    count = scan.batches_not_scanned
    if count:
        batches = "1 batch" if count == 1 else f"{count} batches"
        lines.append(
            f"exposure scan: data in {batches} not scanned - only spans and log records "
            "are read, not metrics or other data"
        )
    if scan.values_not_scanned:
        lines.append(
            f"exposure scan: {plural(scan.values_not_scanned, 'value')} not scanned - "
            "not in a shape the scan reads"
        )
    return lines


def exposure_gauge_lines(scan: ExposureScan) -> list[str]:
    if not scan.applicable:
        return ["exposure scan: not applicable - native input carries no attributes"]
    logs = scan.log_records_scanned
    header = (
        f"exposure scan: {scan.spans_scanned} spans, "
        + (f"{plural(logs, 'log record')}, " if logs else "")
        + f"{scan.strings_scanned} strings"
    )
    if not scan.hits:
        return [f"{header} - no credential-shaped values", *not_scanned_lines(scan)]

    lines = [header]
    eligible = [h for h in scan.hits if h.eligible]
    triage = [h for h in scan.hits if not h.eligible]
    if eligible:
        classes = ", ".join(sorted({flatten_untrusted(h.source_class) for h in eligible}))
        # The ordinals, not the strings: two locations can both be withheld.
        locations = len({h.site_key for h in eligible})
        spans = len({h.span_key for h in eligible if h.log_record is None})
        records = len({h.log_record for h in eligible if h.log_record is not None})
        lines.append(
            f"  credentials: {len({h.fingerprint for h in eligible})} distinct "
            f"({classes}) in {plural(locations, 'location')} across "
            f"{records_phrase(spans, records)}"
        )
    if triage:
        classes = ", ".join(sorted({flatten_untrusted(h.source_class) for h in triage}))
        locations = len({h.site_key for h in triage})
        # "match" pluralizes irregularly (matches, not matchs) - plural() only
        # handles the regular +s case, so this one stays a manual ternary.
        match_word = "match" if len(triage) == 1 else "matches"
        lines.append(
            f"  triage: {len(triage)} credential-shaped {match_word} "
            f"({classes}) in {plural(locations, 'location')}"
        )
    return [*lines, *not_scanned_lines(scan)]
