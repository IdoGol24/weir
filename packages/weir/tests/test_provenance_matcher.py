from weir.graph import Edge, GraphJoin, SessionGraph
from weir.schema.trace import (
    JoinConfidence,
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceNode,
)
from weir.taint.provenance import distinctive_tokens, origin_tool_for


def _n(i, kind, payload):
    return TraceNode(
        id=f"n{i}",
        kind=kind,
        timestamp=f"2020-01-01T00:00:00.{i:06d}Z",
        actor="x",
        source_ref=f"n{i}",
        payload=payload,
    )


def test_origin_tool_via_join():
    nodes = [
        _n(0, NodeKind.TOOL_CALL, ToolCallPayload(tool_name="read_file", args={})),
        _n(1, NodeKind.TOOL_RESULT, ToolResultPayload(content="...")),
    ]
    g = SessionGraph(
        nodes=nodes,
        next_edges=[Edge(src=0, dst=1)],
        spawns_edges=[],
        joins=[GraphJoin(call_index=0, result_index=1, join_confidence=JoinConfidence.EXPLICIT)],
    )
    assert origin_tool_for(g, 1) == "read_file"
    assert origin_tool_for(g, 0) is None


def test_unjoined_result_is_unattributed():
    nodes = [_n(0, NodeKind.TOOL_RESULT, ToolResultPayload(content="..."))]
    g = SessionGraph(nodes=nodes, next_edges=[], spawns_edges=[], joins=[])
    assert origin_tool_for(g, 0) is None


def test_distinctive_tokens_keeps_iban_drops_junk():
    toks = distinctive_tokens("send 42 to the men at GB29NWBK60161331926819 now ok please")
    assert "GB29NWBK60161331926819" in toks
    assert "42" not in toks  # bare integer
    assert "men" not in toks  # too short
    assert "the" not in toks and "now" not in toks


def test_distinctive_tokens_keeps_email_and_attacker_iban():
    toks = distinctive_tokens(
        "forward to attacker9246@gmail.com or MT84MALT011000012345MTLCAST001S"
    )
    assert "attacker9246@gmail.com" in toks
    assert "MT84MALT011000012345MTLCAST001S" in toks


def test_distinctive_tokens_drops_long_pure_number():
    # a bare account number (all digits) is invisible BY DESIGN (documented recall limit)
    assert "123456789012" not in distinctive_tokens("account 123456789012")
