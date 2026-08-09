"""Tests for the FlowFact schema (spec sections 2.1-2.3)."""

import msgspec
import pytest

from weir.schema.flowfact import (
    DESTINATION_NONE,
    DESTINATION_UNEXTRACTED,
    FACT_SCHEMA_VERSION,
    EvidenceConfidence,
    FlowFact,
    TaintMode,
    canonical_fact_bytes,
    decode_flow_fact,
    fact_digest,
    guard_free_projection,
    identity_key,
    merge_facts,
    witness_order_key,
)


def _fact(**overrides: object) -> FlowFact:
    base: dict[str, object] = {
        "source_class": "financial_account_identifier",
        "sink_tool_name": "send_email",
        "destination_class": "known-contact",
        "guards_on_path": [],
        "mode": TaintMode.VERBATIM,
        "evidence_confidence": EvidenceConfidence.FULL,
        "sink_arg_roles": ["body"],
        "witness": ["native-injection-exfil-2", "native-injection-exfil-6"],
    }
    base.update(overrides)
    return FlowFact(**base)  # type: ignore[arg-type]


def test_schema_version_is_semver() -> None:
    assert FACT_SCHEMA_VERSION == "1.0.0"


def test_sentinels() -> None:
    assert DESTINATION_NONE == "none"
    assert DESTINATION_UNEXTRACTED == "unextracted"


def test_identity_key_excludes_attributes() -> None:
    a = _fact()
    b = _fact(
        mode=TaintMode.CONTEXT,
        evidence_confidence=EvidenceConfidence.DEGRADED,
        sink_arg_roles=["recipient"],
        witness=["native-x-0"],
    )
    assert identity_key(a) == identity_key(b)


def test_guard_free_projection_drops_guards() -> None:
    a = _fact(guards_on_path=["mandate_present"])
    b = _fact()
    assert guard_free_projection(a) == guard_free_projection(b)
    assert identity_key(a) != identity_key(b)


def test_canonical_bytes_deterministic_and_digest_stable() -> None:
    a = _fact()
    b = _fact()
    assert canonical_fact_bytes(a) == canonical_fact_bytes(b)
    assert fact_digest(a) == fact_digest(b)
    assert len(fact_digest(a)) == 64  # sha256 hex


def test_digest_changes_with_identity() -> None:
    assert fact_digest(_fact()) != fact_digest(_fact(destination_class="external-novel"))


def test_unsorted_guards_rejected() -> None:
    with pytest.raises(ValueError, match="guards_on_path"):
        _fact(guards_on_path=["b_guard", "a_guard"])


def test_duplicate_roles_rejected() -> None:
    with pytest.raises(ValueError, match="sink_arg_roles"):
        _fact(sink_arg_roles=["body", "body"])


def test_empty_witness_rejected() -> None:
    with pytest.raises(ValueError, match="witness"):
        _fact(witness=[])


def test_decode_rejects_unknown_fields() -> None:
    raw = msgspec.json.encode(msgspec.to_builtins(_fact(), str_keys=True))
    ok = decode_flow_fact(raw)
    assert ok == _fact()
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        decode_flow_fact(b'{"bogus": 1}')


def test_witness_order_confidence_ranks_before_length() -> None:
    # Spec 2.2: a short degraded path must NOT beat a longer clean path.
    short_degraded = witness_order_key(EvidenceConfidence.DEGRADED, ["n-2", "n-3"])
    long_full = witness_order_key(EvidenceConfidence.FULL, ["n-2", "n-3", "n-4", "n-5"])
    assert long_full < short_degraded


def test_witness_order_length_then_lexicographic() -> None:
    k_short = witness_order_key(EvidenceConfidence.FULL, ["n-2", "n-3"])
    k_long = witness_order_key(EvidenceConfidence.FULL, ["n-2", "n-3", "n-4"])
    assert k_short < k_long
    k_a = witness_order_key(EvidenceConfidence.FULL, ["n-1", "n-2"])
    k_b = witness_order_key(EvidenceConfidence.FULL, ["n-1", "n-3"])
    assert k_a < k_b


def test_merge_facts_attribute_rules() -> None:
    # Spec 2.3: max mode, max confidence, union of roles, best witness.
    a = _fact(
        mode=TaintMode.CONTEXT,
        evidence_confidence=EvidenceConfidence.FULL,
        sink_arg_roles=["body"],
        witness=["n-2", "n-3", "n-4"],
    )
    b = _fact(
        mode=TaintMode.VERBATIM,
        evidence_confidence=EvidenceConfidence.DEGRADED,
        sink_arg_roles=["recipient"],
        witness=["n-2", "n-3"],
    )
    merged = merge_facts(a, b)
    assert merged.mode == TaintMode.VERBATIM
    assert merged.evidence_confidence == EvidenceConfidence.FULL
    assert merged.sink_arg_roles == ["body", "recipient"]
    assert merged.witness == ["n-2", "n-3", "n-4"]  # clean beats short-degraded


def test_merge_facts_rejects_different_identities() -> None:
    with pytest.raises(ValueError, match="identities"):
        merge_facts(_fact(), _fact(destination_class="external-novel"))


def test_merge_is_commutative_and_byte_identical() -> None:
    a = _fact(mode=TaintMode.CONTEXT, sink_arg_roles=["recipient"])
    b = _fact(sink_arg_roles=["body"])
    assert canonical_fact_bytes(merge_facts(a, b)) == canonical_fact_bytes(merge_facts(b, a))
