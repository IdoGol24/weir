"""Multi-run variance dial (spec section 6): seeded benign variance in
wording and step count - same flows, different traces."""

from weir.catalog import DEFAULT_CATALOG
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import (
    JoinConfidence,
    LlmCallPayload,
    ToolCallPayload,
    ToolResultPayload,
    encode_canonical_trace,
)
from weir.taint import build_tainted_graph
from weir_tracegen.emitter import emit, emit_run

_IBAN = "DE89370400440532013000"

# The N the baseline capture and the fixture family actually use (spec
# section 3). Testing at a different N makes the tests evidence about
# something other than the artifact.
_N = 5


def test_emit_run_deterministic() -> None:
    a = emit_run("injection-exfil", seed=1, run=0)
    b = emit_run("injection-exfil", seed=1, run=0)
    assert encode_canonical_trace(a) == encode_canonical_trace(b)


def test_wording_dial_actually_varies() -> None:
    # Assert on the dial's own output, not on trace bytes: every run draws a
    # different ticket id, so byte-difference alone proves nothing about the
    # dial. Node 3 is the drafting step the wording dial controls.
    wordings: set[str] = set()
    for r in range(_N):
        node = emit_run("injection-exfil", seed=1, run=r).nodes[3]
        assert isinstance(node.payload, LlmCallPayload)
        wordings.add(node.payload.content)
    assert len(wordings) >= 2, f"wording dial produced only {wordings}"


def test_variance_preserves_the_flow() -> None:
    # Benign variance must not change WHAT flows where: every run still has
    # the injected ticket_result source and a send_email sink carrying the
    # planted secret. If this ever fails, the dial is not benign.
    for r in range(_N):
        trace = emit_run("injection-exfil", seed=1, run=r)
        # The injection itself must still be present in some tool_result, not
        # just the (module-constant) send_email body - this is what catches
        # a dial that silently drops `injected` while the sink body stays hard-coded.
        assert any(
            isinstance(n.payload, ToolResultPayload) and _IBAN in n.payload.content
            for n in trace.nodes
        )
        send_calls = [
            n
            for n in trace.nodes
            if isinstance(n.payload, ToolCallPayload)
            and n.payload.tool_name == "send_email"
        ]
        assert len(send_calls) == 1
        body = send_calls[0].payload.args["body"]
        assert isinstance(body, str)
        assert _IBAN in body


def test_benign_variance_stays_clean() -> None:
    for r in range(_N):
        trace = emit_run("injection-exfil-benign", seed=1, run=r)
        send_calls = [
            n
            for n in trace.nodes
            if isinstance(n.payload, ToolCallPayload)
            and n.payload.tool_name == "send_email"
        ]
        assert len(send_calls) == 1
        body = send_calls[0].payload.args["body"]
        assert isinstance(body, str)
        assert _IBAN not in body


def test_step_count_actually_varies_somewhere() -> None:
    # The dial claims to vary step count, which is what makes fact identity's
    # exclusion of step index meaningful. Prove at least one run differs.
    counts = {len(emit_run("injection-exfil", seed=1, run=r).nodes) for r in range(_N)}
    assert len(counts) > 1


def test_joins_stay_consistent_under_variance() -> None:
    # An extra step shifts later indices. Joins are recorded by source_ref, so
    # they must still point at real nodes whatever the dial did.
    for r in range(_N):
        trace = emit_run("injection-exfil", seed=1, run=r)
        refs = {n.source_ref for n in trace.nodes}
        for join in trace.joins:
            assert join.tool_call_source_ref in refs
            assert join.tool_result_source_ref in refs


def test_unvaried_emission_is_stable() -> None:
    a = encode_canonical_trace(emit("injection-exfil", seed=1))
    b = encode_canonical_trace(emit("injection-exfil", seed=1))
    assert a == b


def test_fact_identity_stable_across_variance_runs() -> None:
    # Guards the too-strict fixture family's root premise (spec sections 3
    # and 6): baseline capture treats facts seen in ALL N runs as required
    # and facts in ANY run as allowed, which only makes sense if benign
    # variance changes incidental detail (wording, step count, evidence) and
    # never WHICH flows exist. If a run's dial output split one real flow
    # into two distinct (source_class, sink, destination) identities - e.g.
    # by varying the sink's true destination - the too-strict family's
    # "empty diff against itself" premise breaks at the root.
    identities: set[tuple[str, str, str | None]] = set()
    for r in range(_N):
        trace = emit_run("injection-exfil", seed=1, run=r)
        assert all(not node.degraded for node in trace.nodes)
        assert all(join.join_confidence == JoinConfidence.EXPLICIT for join in trace.joins)

        graph = build_session_graph(trace)
        labeled = label_graph(graph, DEFAULT_CATALOG)
        tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)

        assert len(tainted.verbatim_matches) == 1
        (match,) = tainted.verbatim_matches
        sink_labels = [
            label for label in labeled.sink_labels if label.node_index == match.sink_node_index
        ]
        assert len(sink_labels) == 1
        (sink_label,) = sink_labels
        identities.add((match.source_class, sink_label.tool_name, sink_label.true_destination))

    assert len(identities) == 1, f"variance split one flow into distinct identities: {identities}"


def test_benign_variance_yields_zero_verbatim_matches_in_every_run() -> None:
    for r in range(_N):
        trace = emit_run("injection-exfil-benign", seed=1, run=r)
        graph = build_session_graph(trace)
        labeled = label_graph(graph, DEFAULT_CATALOG)
        tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
        assert tainted.verbatim_matches == []
