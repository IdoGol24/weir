"""Tests for the FlowBaseline schema (spec section 3)."""

import msgspec
import pytest

from weir.schema.baseline import (
    BaselineMetadata,
    BaselineObservations,
    FlowBaseline,
    ScenarioBaseline,
    baseline_digest,
    canonical_baseline_bytes,
    decode_flow_baseline,
    validate_flow_baseline,
)
from weir.schema.dialect import NATIVE_SEAM1, profile_digest
from weir.schema.flowfact import (
    FACT_SCHEMA_VERSION,
    EvidenceConfidence,
    FlowFact,
    TaintMode,
    canonical_fact_bytes,
    identity_digest,
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


def _baseline(
    *,
    required: list[FlowFact] | None = None,
    allowed: list[FlowFact] | None = None,
    counts: dict[str, int] | None = None,
    n_runs: int = 5,
    accepted: list[str] | None = None,
) -> FlowBaseline:
    fact = _fact()
    required = [fact] if required is None else required
    allowed = [fact] if allowed is None else allowed
    accepted = [] if accepted is None else accepted
    if counts is None:
        counts = {
            identity_digest(f): n_runs
            for f in allowed
            if identity_digest(f) not in set(accepted)
        }
    return FlowBaseline(
        fact_schema_version=FACT_SCHEMA_VERSION,
        scenarios=[
            ScenarioBaseline(
                scenario_id="injection-exfil",
                n_runs=n_runs,
                required=required,
                allowed=allowed,
                observations=BaselineObservations(uncataloged_tools_on_tainted_paths=[]),
                observation_counts=counts,
                source_trace_digests=[f"{i:064x}" for i in range(n_runs)],
                accepted=sorted(accepted),
            )
        ],
        metadata=BaselineMetadata(
            weir_version="0.1.0",
            catalog_digest="a" * 64,
            dialect_profile_id=NATIVE_SEAM1.profile_id,
            dialect_profile_digest=profile_digest(NATIVE_SEAM1),
        ),
    )


def test_roundtrip_and_digest_stable() -> None:
    b = _baseline()
    raw = canonical_baseline_bytes(b)
    assert decode_flow_baseline(raw) == b
    assert baseline_digest(b) == baseline_digest(_baseline())
    assert len(baseline_digest(b)) == 64


def test_parent_digest_defaults_to_none() -> None:
    assert _baseline().metadata.parent_digest is None


def test_required_must_be_subset_of_allowed() -> None:
    stray = _fact(destination_class="external-novel")
    bad = _baseline(required=[stray], allowed=[_fact()])
    with pytest.raises(ValueError, match="required"):
        validate_flow_baseline(bad)


def test_required_fact_must_be_observed_in_all_runs() -> None:
    fact = _fact()
    bad = _baseline(counts={identity_digest(fact): 3}, n_runs=5)
    with pytest.raises(ValueError, match="all runs"):
        validate_flow_baseline(bad)


def test_observation_count_bounds() -> None:
    fact = _fact()
    bad = _baseline(counts={identity_digest(fact): 6}, n_runs=5)
    with pytest.raises(ValueError, match="observation count"):
        validate_flow_baseline(bad)


def test_valid_baseline_passes() -> None:
    validate_flow_baseline(_baseline())  # no raise


def test_unsorted_observations_rejected() -> None:
    with pytest.raises(ValueError, match="uncataloged_tools_on_tainted_paths"):
        BaselineObservations(uncataloged_tools_on_tainted_paths=["z_tool", "a_tool"])


def test_decode_rejects_unknown_fields() -> None:
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        decode_flow_baseline(b'{"bogus": true}')


def test_required_must_match_allowed_byte_for_byte() -> None:
    fact = _fact()
    variant = _fact(witness=["n-9", "n-10"])
    bad = _baseline(required=[fact], allowed=[variant])
    with pytest.raises(ValueError, match="allowed set"):
        validate_flow_baseline(bad)


def test_fact_lists_must_be_sorted() -> None:
    ordered = sorted([_fact(), _fact(destination_class="external-novel")], key=canonical_fact_bytes)
    with pytest.raises(ValueError, match="sorted canonical fact order"):
        _baseline(required=[], allowed=list(reversed(ordered)))


def test_fact_lists_reject_duplicate_identities() -> None:
    # Same identity, DIFFERENT content: the state that used to be legal and is
    # exactly what identity-keyed uniqueness exists to forbid. Sorted first so
    # the order check cannot fire before the uniqueness check.
    pair = sorted([_fact(), _fact(witness=["n-9", "n-10"])], key=canonical_fact_bytes)
    with pytest.raises(ValueError, match="one fact per identity"):
        _baseline(required=[], allowed=pair)


def test_digest_is_independent_of_capture_order() -> None:
    # Content addressing means one fact set has exactly one address. Because
    # the schema rejects unsorted lists, any valid baseline over the same facts
    # has the same bytes no matter what order the runs were captured in.
    a = _fact()
    b = _fact(destination_class="external-novel")
    one = _baseline(required=[], allowed=sorted([a, b], key=canonical_fact_bytes))
    two = _baseline(required=[], allowed=sorted([b, a], key=canonical_fact_bytes))
    assert baseline_digest(one) == baseline_digest(two)


def test_n_runs_must_be_positive() -> None:
    with pytest.raises(ValueError, match="n_runs"):
        _baseline(n_runs=0)


def test_observation_counts_must_cover_allowed_identities() -> None:
    with pytest.raises(ValueError, match="cover exactly"):
        validate_flow_baseline(_baseline(counts={}))


def test_orphan_observation_count_rejected() -> None:
    fact = _fact()
    ghost = _fact(sink_tool_name="ghost_tool")
    counts = {identity_digest(fact): 5, identity_digest(ghost): 5}
    with pytest.raises(ValueError, match="cover exactly"):
        validate_flow_baseline(_baseline(counts=counts))


def test_malformed_digests_rejected() -> None:
    with pytest.raises(ValueError, match="catalog_digest"):
        BaselineMetadata(
            weir_version="0.1.0",
            catalog_digest="short",
            dialect_profile_id=NATIVE_SEAM1.profile_id,
            dialect_profile_digest=profile_digest(NATIVE_SEAM1),
        )
    with pytest.raises(ValueError, match="parent_digest"):
        BaselineMetadata(
            weir_version="0.1.0",
            catalog_digest="a" * 64,
            dialect_profile_id=NATIVE_SEAM1.profile_id,
            dialect_profile_digest=profile_digest(NATIVE_SEAM1),
            parent_digest="nope",
        )


def test_scenarios_must_be_sorted_and_unique() -> None:
    base = _baseline()
    only = base.scenarios[0]
    second = msgspec.structs.replace(only, scenario_id="aaa-first")
    with pytest.raises(ValueError, match="sorted by scenario_id"):
        msgspec.structs.replace(base, scenarios=[only, second])
    with pytest.raises(ValueError, match="unique"):
        msgspec.structs.replace(base, scenarios=[only, only])


def test_decode_validates_cross_field_invariants() -> None:
    fact = _fact()
    bad = _baseline(counts={identity_digest(fact): 3}, n_runs=5)
    raw = canonical_baseline_bytes(bad)
    with pytest.raises(ValueError, match="all runs"):
        decode_flow_baseline(raw)


def test_accepted_fact_needs_no_observation_count() -> None:
    # spec section 5: --accept admits a fact observed in 0 of the N capture
    # runs. Inventing a count for it would corrupt the flap diagnostic that
    # counts exist for, so accepted identities are exempt instead.
    captured = _fact()
    admitted = _fact(sink_tool_name="post_to_webhook")
    base = _baseline(
        required=[captured],
        allowed=sorted([captured, admitted], key=canonical_fact_bytes),
        accepted=[identity_digest(admitted)],
    )
    validate_flow_baseline(base)
    assert identity_digest(admitted) not in base.scenarios[0].observation_counts


def test_accepted_must_be_present_in_allowed() -> None:
    ghost = _fact(sink_tool_name="ghost_tool")
    with pytest.raises(ValueError, match="accepted identities"):
        validate_flow_baseline(_baseline(accepted=[identity_digest(ghost)]))


def test_required_may_be_promoted_from_accepted() -> None:
    # `--require <identity-digest>` promotes an accepted fact into required.
    # An operator policy assertion, not an observation, so the all-runs rule
    # does not apply.
    fact = _fact()
    validate_flow_baseline(
        _baseline(required=[fact], allowed=[fact], accepted=[identity_digest(fact)])
    )


def test_source_trace_digests_must_match_n_runs() -> None:
    with pytest.raises(ValueError, match="exactly n_runs"):
        ScenarioBaseline(
            scenario_id="s",
            n_runs=5,
            required=[],
            allowed=[],
            observations=BaselineObservations(uncataloged_tools_on_tainted_paths=[]),
            observation_counts={},
            source_trace_digests=["b" * 64],
        )


def test_baseline_metadata_carries_dialect_profile_provenance() -> None:
    metadata = BaselineMetadata(
        weir_version="0.1.0",
        catalog_digest="a" * 64,
        dialect_profile_id=NATIVE_SEAM1.profile_id,
        dialect_profile_digest=profile_digest(NATIVE_SEAM1),
    )
    assert metadata.dialect_profile_id == "native-seam1/1"
    with pytest.raises(ValueError, match="dialect_profile_digest"):
        BaselineMetadata(
            weir_version="0.1.0", catalog_digest="a" * 64,
            dialect_profile_id="native-seam1/1", dialect_profile_digest="short",
        )
