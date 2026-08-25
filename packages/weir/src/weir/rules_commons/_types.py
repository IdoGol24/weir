"""Rule data model - minimal, inline for this demo slice (one rule, no
provenance block, no fixtures[] references) rather than the full L4 rule
schema. Rules are data, never code (constitution #4)."""

from __future__ import annotations

import msgspec


class RuleSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: str
    version: str
    stage: str  # "active" | "shadow" (R6.8) - only "active" is exercised here
    description: str
    source_class: str
    sink_tool_name: str
    mode: str  # "verbatim" | "context" (R5.1/R5.2) - only "verbatim" is exercised here
