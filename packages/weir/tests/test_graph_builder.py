from pathlib import Path

import msgspec.structs
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.graph import Edge, build_session_graph
from weir.schema.trace import JoinConfidence, JoinRecord, decode_canonical_trace

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"


def _load(filename: str):  # noqa: ANN201
    return decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())


def test_next_edges_form_a_temporal_chain() -> None:
    trace = _load("injection-exfil.json")
    graph = build_session_graph(trace)
    assert graph.next_edges == [Edge(src=i, dst=i + 1) for i in range(7)]


def test_joins_carry_through_with_confidence_and_resolved_indices() -> None:
    trace = _load("injection-exfil.json")
    graph = build_session_graph(trace)
    assert len(graph.joins) == 3
    assert graph.joins[0].call_index == 1
    assert graph.joins[0].result_index == 2
    assert graph.joins[0].join_confidence == JoinConfidence.EXPLICIT
    assert graph.joins[1].call_index == 4
    assert graph.joins[1].result_index == 5
    assert graph.joins[2].call_index == 6
    assert graph.joins[2].result_index == 7


def test_source_ref_preserved() -> None:
    trace = _load("injection-exfil.json")
    graph = build_session_graph(trace)
    assert [n.source_ref for n in graph.nodes] == [n.source_ref for n in trace.nodes]


def test_spawns_edges_empty_for_this_demo() -> None:
    trace = _load("injection-exfil.json")
    graph = build_session_graph(trace)
    assert graph.spawns_edges == []


def test_degraded_node_included_and_its_join_still_resolves() -> None:
    trace = _load("injection-exfil-benign.degraded.json")
    graph = build_session_graph(trace)
    assert graph.nodes[1].degraded is True
    assert any(j.call_index == 1 for j in graph.joins)


def test_dangling_join_reference_degrades_instead_of_crashing() -> None:
    trace = _load("injection-exfil.json")
    corrupt_join = JoinRecord(
        tool_call_source_ref="does-not-exist",
        tool_result_source_ref="also-does-not-exist",
        join_confidence=JoinConfidence.EXPLICIT,
    )
    corrupt_trace = msgspec.structs.replace(trace, joins=[*trace.joins, corrupt_join])
    graph = build_session_graph(corrupt_trace)  # must not raise
    assert len(graph.joins) == 3  # the corrupt join was dropped, not crashed on


def test_build_session_graph_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil.json"
    code = (
        "from pathlib import Path\n"
        "from weir.graph import build_session_graph\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "graph = build_session_graph(trace)\n"
        "print(len(graph.next_edges), len(graph.joins), [j.call_index for j in graph.joins])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
