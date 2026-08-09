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
from weir.schema.flowfact import (
    FACT_SCHEMA_VERSION,
    EvidenceConfidence,
    FlowFact,
    TaintMode,
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
) -> FlowBaseline:
    fact = _fact()
    required = [fact] if required is None else required
    allowed = [fact] if allowed is None else allowed
    counts = {identity_digest(fact): n_runs} if counts is None else counts
    return FlowBaseline(
        fact_schema_version=FACT_SCHEMA_VERSION,
        scenarios=[
            ScenarioBaseline(
                scenario_id="injection-exfil",
                required=required,
                allowed=allowed,
                observations=BaselineObservations(uncataloged_tools_on_tainted_paths=[]),
            )
        ],
        metadata=BaselineMetadata(
            n_runs=n_runs,
            weir_version="0.1.0",
            catalog_digest="a" * 64,
            source_trace_digests=["b" * 64],
            observation_counts=counts,
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


def test_counts_survive_a_witness_change() -> None:
    # The reason counts key on identity, not the full fact digest: the same
    # flow seen with a different witness in another run is the same fact.
    fact = _fact()
    other_witness = _fact(witness=["n-9", "n-10"])
    base = _baseline(required=[fact], allowed=[other_witness])
    validate_flow_baseline(base)


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
