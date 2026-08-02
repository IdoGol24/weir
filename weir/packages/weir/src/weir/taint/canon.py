"""Base canon (R5.3): uppercase, strip whitespace and hyphens. canon v2's
closed normalizer set (N1-N3) is deferred to M2 — base canon only here, per
the demo-slice doc's L15 notes."""

from __future__ import annotations


def canon(value: str) -> str:
    return value.upper().replace(" ", "").replace("-", "")
