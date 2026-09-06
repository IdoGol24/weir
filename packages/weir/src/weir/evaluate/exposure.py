"""Exposure grading (spec 2026-09-06 section 3). Pure over the value-free hit
record plus the rules.

`is_verdict_grade = hit.eligible and rule.stage == "active"`. There are exactly
two demotion reasons, and neither the join clause nor the degraded-node clause
applies: presence does not depend on how well the span mapped. Eligibility - a
strict pattern, a length range, a charset, a distinct-character floor, a reject
list - is what earns the grade, and a key-name match never does, because its
class declares no floor at all.

`evaluate_exposure` reads only `scan.hits`, not `scan.applicable`; a caller
that must report "exposure scan: not applicable" on native input (constitution
#5) has to keep the `ExposureScan` around alongside the returned findings for
that flag, rather than expecting this function to surface it.
"""

from __future__ import annotations

from weir.evaluate._types import ExposureFinding
from weir.exposure import ExposureScan
from weir.rules_commons import RuleSpec


def evaluate_exposure(scan: ExposureScan, rules: list[RuleSpec]) -> list[ExposureFinding]:
    by_class: dict[str, list[RuleSpec]] = {}
    for rule in rules:
        if rule.mode == "exposure":
            by_class.setdefault(rule.source_class, []).append(rule)

    findings: list[ExposureFinding] = []
    # Hit order is already deterministic (span order, then location) and
    # load_rules returns a stable global id order, so the product needs no
    # re-sort - sorting here would discard wire order for no gain.
    for hit in scan.hits:
        for rule in by_class.get(hit.source_class, []):
            reasons: list[str] = []
            if not hit.eligible:
                reasons.append(f"value shape not eligible for {hit.source_class}")
            if rule.stage != "active":
                reasons.append(f"rule {rule.id} is in stage {rule.stage!r}, not active")
            findings.append(ExposureFinding(
                rule_id=rule.id,
                rule_version=rule.version,
                severity=rule.severity,
                source_class=hit.source_class,
                span_ref=hit.span_ref,
                span_name=hit.span_name,
                location=hit.location,
                value_len=hit.value_len,
                prefix=hit.prefix,
                last4=hit.last4,
                fingerprint=hit.fingerprint,
                fingerprint_v=hit.fingerprint_v,
                is_verdict_grade=not reasons,
                demotion_reasons=reasons,
            ))
    return findings
