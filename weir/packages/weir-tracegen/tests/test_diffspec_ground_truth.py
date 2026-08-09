"""Ground-truth baselines are BY CONSTRUCTION (the L9 pattern): tracegen knows
the red scenario plants exactly one flow, so it can state the baseline without
any engine derivation."""

from weir.evaluate.witness import joins_on_path, shortest_witness_path
from weir.graph.builder import build_session_graph
from weir.schema.baseline import baseline_digest, validate_flow_baseline
from weir.schema.flowfact import EvidenceConfidence, TaintMode, identity_digest
from weir.schema.trace import JoinConfidence, ToolCallPayload
from weir.taint.canon import canon
from weir_tracegen.diffspec_ground_truth import (
    SKEW_CATALOG_DIGEST,
    red_baseline,
    red_fact,
)
from weir_tracegen.emitter import emit
from weir_tracegen.scenarios._common import PLANTED_IBAN

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


def test_sink_arg_roles_derived_from_trace() -> None:
    """sink_arg_roles must be derivable from the real trace, not merely
    restated: find the send_email tool_call, confirm the planted IBAN
    appears in the body arg and no other arg, then assert red_fact()'s claim
    equals exactly the sorted set of arg names that contain it - so this
    test fails if either the fixture or the claim moves out of step."""
    trace = emit("injection-exfil", seed=1)
    sink_calls = [
        node
        for node in trace.nodes
        if isinstance(node.payload, ToolCallPayload) and node.payload.tool_name == "send_email"
    ]
    assert len(sink_calls) == 1
    args = sink_calls[0].payload
    assert isinstance(args, ToolCallPayload)
    contains_iban = {
        key: canon(PLANTED_IBAN) in canon(value)
        for key, value in args.args.items()
        if isinstance(value, str)
    }
    assert contains_iban["body"] is True
    derived_roles = sorted(key for key, present in contains_iban.items() if present)
    assert derived_roles == ["body"]
    assert red_fact().sink_arg_roles == derived_roles


def test_evidence_confidence_full_conditions_hold_on_witness_path() -> None:
    """FULL is only correct while all three conditions from flowfact.py's
    EvidenceConfidence docstring hold on the witness path: no degraded node,
    every join crossed is explicit, every tool_call's args are non-empty.
    This test is what pins that claim to the real trace - if the fixture or
    emitter ever drifts to break one of these, red_fact()'s FULL claim goes
    false and this test catches it."""
    trace = emit("injection-exfil", seed=1)
    graph = build_session_graph(trace)
    source_ref_to_index = {node.source_ref: i for i, node in enumerate(trace.nodes)}
    witness = red_fact().witness
    source_index = source_ref_to_index[witness[0]]
    sink_index = source_ref_to_index[witness[-1]]

    path = shortest_witness_path(graph, source_index, sink_index)
    assert path is not None
    assert [trace.nodes[i].source_ref for i in path] == witness

    # condition 1: no degraded node on the path
    assert all(not trace.nodes[i].degraded for i in path)

    # condition 2: every join crossed on the path is explicit
    joins = joins_on_path(graph, path)
    assert joins
    assert all(join.join_confidence == JoinConfidence.EXPLICIT for join in joins)

    # condition 3: every tool_call node on the path has non-empty args
    for i in path:
        payload = trace.nodes[i].payload
        if isinstance(payload, ToolCallPayload):
            assert payload.args

    assert red_fact().evidence_confidence == EvidenceConfidence.FULL


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
