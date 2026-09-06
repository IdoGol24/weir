"""Rule data model - minimal, inline for this demo slice (one rule, no
provenance block, no fixtures[] references) rather than the full L4 rule
schema. Rules are data, never code (constitution #4)."""

from __future__ import annotations

import msgspec


class RuleSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: str
    version: str
    stage: str  # "active" | "shadow" (R6.8)
    description: str
    source_class: str
    # None for `exposure`, required for `verbatim`/`provenance`. The loader
    # validates both directions; the type alone cannot.
    sink_tool_name: str | None
    mode: str  # "verbatim" | "provenance" | "exposure"
    # high | medium | low. Drives `--fail-on` for EVERY finding family, so the
    # default preserves today's behavior: every bundled rule fails CI at the
    # default threshold.
    severity: str = "high"
