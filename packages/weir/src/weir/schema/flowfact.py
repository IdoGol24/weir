"""Flow-fact schema for the version-diff baseline gate (spec sections 2.1-2.3).

Schema and pure helpers only - fact DERIVATION from a TaintedGraph is engine
work, deliberately sequenced after M3/M4 (spec section 7). Identity is stable
keys only; step indices, timestamps, wording, token counts, matched values,
and witness paths are excluded from identity by construction.
"""

from __future__ import annotations

import enum
import hashlib
import json

import msgspec

FACT_SCHEMA_VERSION = "1.0.0"

# destination_class sentinels (spec 2.1): the two nothings differ. `none` is
# structural (a sink with no destination concept, declared in the catalog);
# `unextracted` is an extraction failure, and any transition to/from it is an
# evidentiary delta, never a behavioral one.
DESTINATION_NONE = "none"
DESTINATION_UNEXTRACTED = "unextracted"


class TaintMode(enum.StrEnum):
    CONTEXT = "context"
    VERBATIM = "verbatim"


_MODE_RANK: dict[TaintMode, int] = {TaintMode.CONTEXT: 0, TaintMode.VERBATIM: 1}


class EvidenceConfidence(enum.StrEnum):
    """Ordered evidence tiers (derivation is post-M4 engine work; documented
    mapping: FULL = explicit joins only, no degraded node, args inspectable
    along the witness; PARTIAL = a nested join on the path; DEGRADED = a
    heuristic or content_mined join, a degraded node, or missing args on the
    path)."""

    FULL = "full"
    PARTIAL = "partial"
    DEGRADED = "degraded"


_CONFIDENCE_RANK: dict[EvidenceConfidence, int] = {
    EvidenceConfidence.DEGRADED: 0,
    EvidenceConfidence.PARTIAL: 1,
    EvidenceConfidence.FULL: 2,
}

if set(_MODE_RANK) != set(TaintMode) or set(_CONFIDENCE_RANK) != set(EvidenceConfidence):
    raise RuntimeError("rank tables must cover every enum member")


class FlowFact(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """One canonical flow fact. Identity fields first, then attributes.

    `guards_on_path` and `sink_arg_roles` carry set semantics as sorted,
    duplicate-free lists so canonical serialization stays byte-stable.
    `witness` is evidence, never identity: node source_refs in path order.
    """

    # identity (spec 2.1)
    source_class: str
    sink_tool_name: str
    destination_class: str
    guards_on_path: list[str]
    # attributes (spec 2.2)
    mode: TaintMode
    evidence_confidence: EvidenceConfidence
    sink_arg_roles: list[str]
    witness: list[str]

    def __post_init__(self) -> None:
        if self.mode not in _MODE_RANK:
            raise ValueError("mode must be a TaintMode member")
        if self.evidence_confidence not in _CONFIDENCE_RANK:
            raise ValueError("evidence_confidence must be an EvidenceConfidence member")
        if self.guards_on_path != sorted(set(self.guards_on_path)):
            raise ValueError("guards_on_path must be sorted and duplicate-free")
        if self.sink_arg_roles != sorted(set(self.sink_arg_roles)):
            raise ValueError("sink_arg_roles must be sorted and duplicate-free")
        if not self.witness:
            raise ValueError("witness must be a non-empty path")


def identity_key(fact: FlowFact) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        fact.source_class,
        fact.sink_tool_name,
        fact.destination_class,
        tuple(fact.guards_on_path),
    )


def guard_free_projection(fact: FlowFact) -> tuple[str, str, str]:
    """The pairing-pass projection (spec section 4): identity minus guards."""
    return (fact.source_class, fact.sink_tool_name, fact.destination_class)


def canonical_fact_bytes(fact: FlowFact) -> bytes:
    """Canonical JSON: sorted keys, no whitespace. The digest input."""
    data = msgspec.to_builtins(fact, str_keys=True)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fact_digest(fact: FlowFact) -> str:
    """The fact's stable id (spec section 5: --accept/--require address facts
    by this digest)."""
    return hashlib.sha256(canonical_fact_bytes(fact)).hexdigest()


def canonical_identity_bytes(fact: FlowFact) -> bytes:
    """Canonical JSON over the identity fields only (spec 2.1)."""
    data = {
        "source_class": fact.source_class,
        "sink_tool_name": fact.sink_tool_name,
        "destination_class": fact.destination_class,
        "guards_on_path": list(fact.guards_on_path),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def identity_digest(fact: FlowFact) -> str:
    """Stable id for the fact's IDENTITY, independent of attributes.

    The handle that survives re-capture: a run that improves a witness or
    escalates a mode changes fact_digest but never identity_digest. Baseline
    observation counts and `--require` address facts by THIS digest;
    fact_digest addresses one exact observed fact (content addressing for the
    accept chain)."""
    return hashlib.sha256(canonical_identity_bytes(fact)).hexdigest()


def decode_flow_fact(data: bytes | str) -> FlowFact:
    """Decode + validate, G9-style precise errors on rejection."""
    return msgspec.json.decode(data, type=FlowFact, strict=True)


def witness_order_key(
    confidence: EvidenceConfidence, witness: list[str]
) -> tuple[int, int, tuple[str, ...]]:
    """Total order for witness selection (spec 2.2): highest confidence first,
    then shortest path, then lexicographic on the source_ref sequence in PATH
    ORDER. Confidence ranks first because evidence_confidence derives from the
    STORED witness - a short degraded path must never shadow a longer clean
    one. Path order, not sorted order, is what makes this injective: two
    distinct witnesses that are permutations of each other must not tie, or
    merge_facts becomes order-dependent and byte-identity breaks."""
    return (-_CONFIDENCE_RANK[confidence], len(witness), tuple(witness))


def merge_facts(a: FlowFact, b: FlowFact) -> FlowFact:
    """Attribute-merge rules (spec 2.3): max mode, max confidence, union of
    roles, best witness under the total order. Used identically for within-run
    and cross-run merging.

    Note: max mode and best witness are independent rules, so a merged fact
    can report `verbatim` while storing a witness from a `context` run. That
    is spec 2.3's prescribed behavior, not an oversight - the delta report
    must not assume the stored witness demonstrates the reported mode."""
    if identity_key(a) != identity_key(b):
        raise ValueError("cannot merge facts with different identities")
    best = min(
        (a, b), key=lambda f: witness_order_key(f.evidence_confidence, f.witness)
    )
    mode = a.mode if _MODE_RANK[a.mode] >= _MODE_RANK[b.mode] else b.mode
    return FlowFact(
        source_class=a.source_class,
        sink_tool_name=a.sink_tool_name,
        destination_class=a.destination_class,
        guards_on_path=list(a.guards_on_path),
        mode=mode,
        evidence_confidence=best.evidence_confidence,
        sink_arg_roles=sorted({*a.sink_arg_roles, *b.sink_arg_roles}),
        witness=list(best.witness),
    )
