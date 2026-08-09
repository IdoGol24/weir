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
) -> FlowBaseline:
    fact = _fact()
    required = [fact] if required is None else required
    allowed = [fact] if allowed is None else allowed
    counts = {identity_digest(f): n_runs for f in allowed} if counts is None else counts
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
                source_trace_digests=["b" * 64],
            )
        ],
        metadata=BaselineMetadata(weir_version="0.1.0", catalog_digest="a" * 64),
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


def test_counts_key_on_identity_not_content() -> None:
    # Why counts key on identity rather than the full fact digest: the same
    # flow observed with a different witness in a different run merges to one
    # fact, and its count must still reach n_runs. Content-keyed counts would
    # split it into two entries of 1 and the required check would never fire.
    fact = _fact()
    variant = _fact(witness=["n-9", "n-10"])
    assert identity_digest(fact) == identity_digest(variant)
    assert canonical_fact_bytes(fact) != canonical_fact_bytes(variant)


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
    fact = _fact()
    with pytest.raises(ValueError, match="one fact per identity"):
        _baseline(required=[], allowed=[fact, fact])


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
        BaselineMetadata(weir_version="0.1.0", catalog_digest="short")
    with pytest.raises(ValueError, match="parent_digest"):
        BaselineMetadata(weir_version="0.1.0", catalog_digest="a" * 64, parent_digest="nope")


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
