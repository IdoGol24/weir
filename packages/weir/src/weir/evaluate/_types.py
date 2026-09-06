"""Finding data model - an internal pipeline artifact (§3.3), minimal and
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
    # Why a finding is NOT verdict-grade, stated on the finding itself (M4
    # design section 3 rule 2). Empty for verdict-grade findings.
    demotion_reasons: list[str] = []
    # "structural" (verbatim value-match) or "provenance" (untrusted-origin flow).
    kind: str = "structural"


class EvaluationResult(msgspec.Struct, frozen=True):
    findings: list[Finding]


class ExposureFinding(msgspec.Struct, frozen=True):
    """A presence fact, not a flow (spec 2026-09-06). It has its own struct
    because its truth conditions are simpler: one location, no witness path, no
    join tier, and a grade that does not depend on graph quality. Forcing it
    through `Finding` would either lie about what was proven or demote a fact
    under the degraded-node clause."""

    rule_id: str
    rule_version: str
    severity: str
    source_class: str
    span_ref: str
    span_name: str
    location: str
    value_len: int
    prefix: str
    is_verdict_grade: bool
    last4: str | None = None
    fingerprint: str | None = None
    fingerprint_v: int = 1
    demotion_reasons: list[str] = []
