from weir.graph import SessionGraph
from weir.label import LabeledGraph
from weir.taint import ProvenanceMatch, TaintedGraph


def test_provenance_match_fields() -> None:
    m = ProvenanceMatch(source_node_index=1, sink_node_index=4,
                        origin_tool="read_file", matched_value="GB29NWBK60161331926819")
    assert m.source_node_index == 1
    assert m.sink_node_index == 4
    assert m.origin_tool == "read_file"
    assert m.matched_value == "GB29NWBK60161331926819"


def test_provenance_match_origin_tool_may_be_none() -> None:
    assert ProvenanceMatch(source_node_index=0, sink_node_index=1,
                          origin_tool=None, matched_value="x").origin_tool is None


def test_tainted_graph_provenance_matches_defaults_empty() -> None:
    labeled = LabeledGraph(
        graph=SessionGraph(nodes=[], next_edges=[], spawns_edges=[], joins=[]),
        source_labels=[], sink_labels=[])
    tg = TaintedGraph(labeled=labeled, verbatim_matches=[], context_tainted={})
    assert tg.provenance_matches == []
