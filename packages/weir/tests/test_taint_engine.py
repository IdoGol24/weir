from pathlib import Path

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.graph import Edge, SessionGraph, build_session_graph
from weir.label import LabeledGraph, label_graph
from weir.schema.trace import (
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceNode,
    decode_canonical_trace,
)
from weir.taint import build_tainted_graph

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_PLANTED_IBAN = "DE89370400440532013000"


def _tainted_from_fixture(filename: str):  # noqa: ANN201
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    return build_tainted_graph(labeled, DEFAULT_CATALOG)


def _synthetic_labeled(
    *,
    source_content: str,
    sink_args: dict[str, object],
    source_degraded: bool = False,
    sink_degraded: bool = False,
) -> LabeledGraph:
    nodes = [
        TraceNode(
            id="n0",
            kind=NodeKind.TOOL_RESULT,
            timestamp="2026-01-01T00:00:00Z",
            actor="tool",
            source_ref="s0",
            payload=ToolResultPayload(content=source_content),
            degraded=source_degraded,
        ),
        TraceNode(
            id="n1",
            kind=NodeKind.TOOL_CALL,
            timestamp="2026-01-01T00:00:01Z",
            actor="agent",
            source_ref="s1",
            payload=ToolCallPayload(tool_name="send_email", args=sink_args),
            degraded=sink_degraded,
        ),
    ]
    graph = SessionGraph(nodes=nodes, next_edges=[Edge(src=0, dst=1)], spawns_edges=[], joins=[])
    return label_graph(graph, DEFAULT_CATALOG)


def test_red_fixture_fires_exactly_one_verbatim_match_on_the_planted_iban() -> None:
    tainted = _tainted_from_fixture("injection-exfil.json")
    assert len(tainted.verbatim_matches) == 1
    (match,) = tainted.verbatim_matches
    assert match.source_node_index == 2
    assert match.sink_node_index == 6
    assert match.source_class == "financial_account_identifier"
    assert match.matched_value == _PLANTED_IBAN


def test_benign_fixture_fires_zero_verbatim_matches() -> None:
    tainted = _tainted_from_fixture("injection-exfil-benign.json")
    assert tainted.verbatim_matches == []


def test_negative_control_ticket_id_never_produces_a_match_in_either_fixture() -> None:
    red = _tainted_from_fixture("injection-exfil.json")
    benign = _tainted_from_fixture("injection-exfil-benign.json")
    assert all(m.matched_value != "18134063" for m in red.verbatim_matches)
    assert all(m.matched_value != "18134063" for m in benign.verbatim_matches)


def test_synthetic_control_confirms_the_harness_can_produce_a_match() -> None:
    # Sanity control for the degraded-node tests below: proves the synthetic
    # setup itself is capable of firing a match when nothing is degraded, so
    # a "no match" result in those tests is meaningful, not a setup artifact.
    labeled = _synthetic_labeled(
        source_content=f"Account: {_PLANTED_IBAN}",
        sink_args={"to": "a@b.com", "body": f"ref {_PLANTED_IBAN}"},
    )
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    assert len(tainted.verbatim_matches) == 1


def test_bare_numeral_reaching_a_sink_is_still_ruled_ineligible() -> None:
    # THE critical R5.9 test: construct a case where a bare numeral DOES flow
    # verbatim to a sink - without the eligibility floor this would fire a
    # false positive. It must not.
    labeled = _synthetic_labeled(
        source_content="Ticket #18134063 needs review",
        sink_args={"to": "a@b.com", "body": "See ticket 18134063 for details"},
    )
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    assert tainted.verbatim_matches == []


def test_degraded_source_excluded_from_verbatim_but_still_context_tainted() -> None:
    labeled = _synthetic_labeled(
        source_content=f"Account: {_PLANTED_IBAN}",
        sink_args={"to": "a@b.com", "body": f"ref {_PLANTED_IBAN}"},
        source_degraded=True,
    )
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    assert tainted.verbatim_matches == []
    assert 1 in tainted.context_tainted[0]


def test_degraded_sink_excluded_from_verbatim_matching() -> None:
    labeled = _synthetic_labeled(
        source_content=f"Account: {_PLANTED_IBAN}",
        sink_args={"to": "a@b.com", "body": f"ref {_PLANTED_IBAN}"},
        sink_degraded=True,
    )
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    assert tainted.verbatim_matches == []


def test_context_taint_reaches_session_end_from_the_injection_node() -> None:
    tainted = _tainted_from_fixture("injection-exfil.json")
    assert set(tainted.context_tainted[2]) == {3, 4, 5, 6, 7}


def test_taint_engine_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil.json"
    code = (
        "from pathlib import Path\n"
        "from weir.catalog import DEFAULT_CATALOG\n"
        "from weir.graph import build_session_graph\n"
        "from weir.label import label_graph\n"
        "from weir.taint import build_tainted_graph\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)\n"
        "tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)\n"
        "print([(m.source_node_index, m.sink_node_index, m.matched_value)\n"
        "       for m in tainted.verbatim_matches])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
