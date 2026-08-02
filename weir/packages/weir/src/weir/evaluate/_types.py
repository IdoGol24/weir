"""Finding data model — an internal pipeline artifact (§3.3), minimal and
inline for this demo slice. The full R7.4 evidence JSON (witnesses,
commitments, join provenance, versions) is an M2 deliverable (L22); this is
just enough for L17's reporter."""

from __future__ import annotations

import msgspec


class Finding(msgspec.Struct, frozen=True):
    rule_id: str
    rule_version: str
    source_node_index: int
    sink_node_index: int
    matched_value: str
    witness_path: list[int]
    is_verdict_grade: bool


class EvaluationResult(msgspec.Struct, frozen=True):
    findings: list[Finding]
