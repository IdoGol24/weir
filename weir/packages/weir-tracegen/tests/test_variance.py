"""Multi-run variance dial (spec section 6): seeded benign variance in
wording, step count, and sampled path - same flows, different traces."""

from weir.schema.trace import ToolCallPayload, encode_canonical_trace
from weir_tracegen.emitter import emit, emit_run

_IBAN = "DE89370400440532013000"


def test_emit_run_deterministic() -> None:
    a = emit_run("injection-exfil", seed=1, run=0)
    b = emit_run("injection-exfil", seed=1, run=0)
    assert encode_canonical_trace(a) == encode_canonical_trace(b)


def test_runs_differ_from_each_other() -> None:
    traces = {
        encode_canonical_trace(emit_run("injection-exfil", seed=1, run=r))
        for r in range(8)
    }
    assert len(traces) > 1, "variance dial produced identical runs"


def test_variance_preserves_the_flow() -> None:
    # Benign variance must not change WHAT flows where: every run still has
    # the injected ticket_result source and a send_email sink carrying the
    # planted secret. If this ever fails, the dial is not benign.
    for r in range(8):
        trace = emit_run("injection-exfil", seed=1, run=r)
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
    for r in range(8):
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
    counts = {len(emit_run("injection-exfil", seed=1, run=r).nodes) for r in range(8)}
    assert len(counts) > 1


def test_joins_stay_consistent_under_variance() -> None:
    # An extra step shifts later indices. Joins are recorded by source_ref, so
    # they must still point at real nodes whatever the dial did.
    for r in range(8):
        trace = emit_run("injection-exfil", seed=1, run=r)
        refs = {n.source_ref for n in trace.nodes}
        for join in trace.joins:
            assert join.tool_call_source_ref in refs
            assert join.tool_result_source_ref in refs


def test_unvaried_emission_is_stable() -> None:
    a = encode_canonical_trace(emit("injection-exfil", seed=1))
    b = encode_canonical_trace(emit("injection-exfil", seed=1))
    assert a == b
