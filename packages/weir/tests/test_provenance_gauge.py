from weir.catalog._types import Catalog, SinkSpec
from weir.gauge.provenance import provenance_gauge_lines
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import (
    CanonicalTrace,
    JoinConfidence,
    JoinRecord,
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceMetadata,
    TraceNode,
)

_IBAN = "DE89370400440532013000"


def _node(i, kind, payload, degraded=False):
    return TraceNode(
        id=f"n{i}",
        kind=kind,
        timestamp=f"2020-01-01T00:00:00.{i:06d}Z",
        actor="x",
        source_ref=f"n{i}",
        payload=payload,
        degraded=degraded,
    )


def _labeled(nodes, joins):
    trace = CanonicalTrace(
        schema_version="1.2.0",
        nodes=nodes,
        joins=joins,
        metadata=TraceMetadata(adapter_name="t", adapter_version="0"),
    )
    catalog = Catalog(
        sources=[],
        sinks=[SinkSpec(tool_name="send_money", destination_arg_keys=["recipient"])],
        remediations={},
    )
    return label_graph(build_session_graph(trace), catalog)


def _two_readfile_one_lookup():
    # two read_file->send_money flows and one lookup->send_money flow
    nodes, joins = [], []
    idx = 0

    def add_flow(tool, val):
        nonlocal idx
        c = _node(idx, NodeKind.TOOL_CALL, ToolCallPayload(tool_name=tool, args={}))
        ci = idx
        idx += 1
        r = _node(idx, NodeKind.TOOL_RESULT, ToolResultPayload(content=f"pay {val}"))
        ri = idx
        idx += 1
        s = _node(
            idx,
            NodeKind.TOOL_CALL,
            ToolCallPayload(tool_name="send_money", args={"recipient": val}),
        )
        idx += 1
        joins.append(
            JoinRecord(
                tool_call_source_ref=f"n{ci}",
                tool_result_source_ref=f"n{ri}",
                join_confidence=JoinConfidence.EXPLICIT,
            )
        )
        return [c, r, s]

    nodes += add_flow("read_file", _IBAN)
    nodes += add_flow("read_file", "DE89370400440532013001")
    nodes += add_flow("lookup", "DE89370400440532013002")
    return _labeled(nodes, joins)


def test_undeclared_reports_no_with_grouped_counts():
    lines = provenance_gauge_lines(
        _two_readfile_one_lookup(), provenance_sink_names={"send_money"}, untrusted_sources=[]
    )
    text = "\n".join(lines)
    assert "provenance: NO" in text
    assert "read_file" in text and "lookup" in text
    assert "declare untrusted_sources" in text


def test_declared_reports_yes():
    lines = provenance_gauge_lines(
        _two_readfile_one_lookup(),
        provenance_sink_names={"send_money"},
        untrusted_sources=["read_file"],
    )
    assert any("provenance: YES" in ln for ln in lines)


def test_declared_untrusted_sources_without_rule_emits_note():
    # untrusted_sources declared but NO provenance sink rules -> a note, not silence
    lines = provenance_gauge_lines(
        _two_readfile_one_lookup(), provenance_sink_names=set(), untrusted_sources=["read_file"]
    )
    text = "\n".join(lines)
    assert "untrusted_sources declared" in text
    assert "no provenance rule" in text


def test_attribution_coverage_reported():
    lines = provenance_gauge_lines(
        _two_readfile_one_lookup(), provenance_sink_names={"send_money"}, untrusted_sources=[]
    )
    assert any("attributable" in ln for ln in lines)
