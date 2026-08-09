"""Ground-truth baselines are BY CONSTRUCTION (the L9 pattern): tracegen knows
the red scenario plants exactly one flow, so it can state the baseline without
any engine derivation."""

from weir.schema.baseline import baseline_digest, validate_flow_baseline
from weir.schema.flowfact import EvidenceConfidence, TaintMode, identity_digest
from weir_tracegen.diffspec_ground_truth import (
    SKEW_CATALOG_DIGEST,
    red_baseline,
    red_fact,
)

_CATALOG_DIGEST = "c" * 64
# Must hold exactly n_runs entries, sorted: ScenarioBaseline enforces both.
_TRACE_DIGESTS = [f"{i:064x}" for i in range(5)]


def test_red_fact_shape() -> None:
    fact = red_fact()
    assert fact.source_class == "financial_account_identifier"
    assert fact.sink_tool_name == "send_email"
    assert fact.destination_class == "known-contact"
    assert fact.guards_on_path == []
    assert fact.mode == TaintMode.VERBATIM
    assert fact.evidence_confidence == EvidenceConfidence.FULL
    assert fact.sink_arg_roles == ["body"]
    assert fact.witness == [f"native-injection-exfil-{i}" for i in range(2, 7)]


def test_red_baseline_validates() -> None:
    base = red_baseline(
        catalog_digest=_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=_TRACE_DIGESTS,
    )
    validate_flow_baseline(base)
    scenario = base.scenarios[0]
    assert scenario.n_runs == 5
    assert scenario.required == scenario.allowed == [red_fact()]
    assert scenario.observation_counts == {identity_digest(red_fact()): 5}
    assert scenario.accepted == []
    assert base.metadata.catalog_digest == _CATALOG_DIGEST


def test_context_only_baseline_differs_in_mode_only() -> None:
    verbatim = red_baseline(
        catalog_digest=_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=_TRACE_DIGESTS,
    )
    context = red_baseline(
        catalog_digest=_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=_TRACE_DIGESTS,
        mode=TaintMode.CONTEXT,
        scenario_id="injection-exfil-context-only",
    )
    validate_flow_baseline(context)
    assert context.scenarios[0].required[0].mode == TaintMode.CONTEXT
    assert baseline_digest(context) != baseline_digest(verbatim)
    # Identity is unchanged: the escalation candidate must match this fact's
    # identity, or a mode escalation has nothing to escalate FROM.
    assert identity_digest(context.scenarios[0].required[0]) == identity_digest(
        verbatim.scenarios[0].required[0]
    )


def test_observations_variant() -> None:
    base = red_baseline(
        catalog_digest=_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=_TRACE_DIGESTS,
        uncataloged_tools=["translate_text"],
    )
    validate_flow_baseline(base)
    tools = base.scenarios[0].observations.uncataloged_tools_on_tainted_paths
    assert tools == ["translate_text"]


def test_skew_sentinel_is_a_valid_but_impossible_digest() -> None:
    # Valid SHAPE (so it is a schema-legal baseline) but a value no real
    # catalog produces, so comparing against it MUST be refused as skew.
    assert SKEW_CATALOG_DIGEST == "0" * 64


def test_skew_baseline_is_structurally_valid() -> None:
    # Skew is a COMPARE-time failure, not a schema one: the baseline itself
    # must be perfectly well-formed, or the fixture would test the wrong thing.
    base = red_baseline(
        catalog_digest=SKEW_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=_TRACE_DIGESTS,
    )
    validate_flow_baseline(base)


def test_source_trace_digests_are_sorted_and_counted() -> None:
    base = red_baseline(
        catalog_digest=_CATALOG_DIGEST,
        weir_version="0.1.0",
        source_trace_digests=list(reversed(_TRACE_DIGESTS)),
    )
    scenario = base.scenarios[0]
    assert scenario.source_trace_digests == sorted(_TRACE_DIGESTS)
    assert len(scenario.source_trace_digests) == scenario.n_runs
