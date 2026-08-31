from weir.evaluate import evaluate
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.taint import build_tainted_graph
from weir.catalog._types import Catalog, SinkSpec, SourceSpec, VerbatimEligibility
from weir.rules_commons._types import RuleSpec
from weir.schema.trace import (
    CanonicalTrace, JoinConfidence, JoinRecord, NodeKind, ToolCallPayload,
    ToolResultPayload, TraceMetadata, TraceNode,
)

# Only the DE structure class is registered in the shipped IBAN validator, so a
# GB IBAN would not clear iban-eligibility for the structural test. Use the
# canonical valid DE IBAN throughout.
_IBAN = "DE89370400440532013000"


def _node(i, kind, payload):
    return TraceNode(id=f"n{i}", kind=kind, timestamp=f"2020-01-01T00:00:00.{i:06d}Z",
                     actor="x", source_ref=f"n{i}", payload=payload)


def _run_provenance(*, untrusted_sources, result_tool, result_content, sink_tool,
                    sink_args, extra_sources=(), extra_rules=()):
    """Build read_tool->result->sink trace, run the pipeline, return findings."""
    nodes = [
        _node(0, NodeKind.TOOL_CALL, ToolCallPayload(tool_name=result_tool, args={})),
        _node(1, NodeKind.TOOL_RESULT, ToolResultPayload(content=result_content)),
        _node(2, NodeKind.TOOL_CALL, ToolCallPayload(tool_name=sink_tool, args=sink_args)),
    ]
    joins = [JoinRecord(tool_call_source_ref="n0", tool_result_source_ref="n1",
                        join_confidence=JoinConfidence.EXPLICIT)]
    trace = CanonicalTrace(schema_version="1.2.0", nodes=nodes, joins=joins,
                           metadata=TraceMetadata(adapter_name="t", adapter_version="0"))
    catalog = Catalog(sources=list(extra_sources),
                      sinks=[SinkSpec(tool_name=sink_tool, destination_arg_keys=["recipient"])],
                      remediations={}, untrusted_sources=untrusted_sources)
    rules = [RuleSpec(id="prov", version="1.0.0", stage="active",
                      description="untrusted->sink", source_class="untrusted_origin",
                      sink_tool_name=sink_tool, mode="provenance"), *extra_rules]
    labeled = label_graph(build_session_graph(trace), catalog)
    tainted = build_tainted_graph(labeled, catalog)
    return evaluate(tainted, rules).findings


def test_declared_provenance_flow_is_verdict_grade():
    findings = _run_provenance(untrusted_sources=["read_file"], result_tool="read_file",
        result_content=f"pay {_IBAN}", sink_tool="send_money", sink_args={"recipient": _IBAN})
    prov = [f for f in findings if f.kind == "provenance"]
    assert len(prov) == 1
    assert prov[0].is_verdict_grade is True
    assert prov[0].matched_value == _IBAN
    assert prov[0].witness_path


def test_no_provenance_rule_for_sink_means_no_finding():
    from weir.rules_commons._types import RuleSpec as R
    # A provenance rule scoped to a DIFFERENT sink must not fire for send_money;
    # only the send_money rule does.
    findings2 = _run_provenance(untrusted_sources=["read_file"], result_tool="read_file",
        result_content=f"pay {_IBAN}", sink_tool="send_money", sink_args={"recipient": _IBAN},
        extra_rules=[R(id="other", version="1.0.0", stage="active", description="x",
                       source_class="untrusted_origin", sink_tool_name="run_shell", mode="provenance")])
    assert len([f for f in findings2 if f.kind == "provenance"]) == 1  # only the send_money rule fires


def test_double_fire_prefers_structural():
    # A flow caught by BOTH a structural verbatim rule (IBAN source class) and provenance.
    ibansrc = SourceSpec(name="financial_account_identifier",
                         content_pattern=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b",
                         eligibility=VerbatimEligibility(structure_class="iban"))
    verbatim_rule = RuleSpec(id="struct", version="1.0.0", stage="active", description="x",
                             source_class="financial_account_identifier",
                             sink_tool_name="send_money", mode="verbatim")
    findings = _run_provenance(untrusted_sources=["read_file"], result_tool="read_file",
        result_content=f"pay {_IBAN}", sink_tool="send_money", sink_args={"recipient": _IBAN},
        extra_sources=[ibansrc], extra_rules=[verbatim_rule])
    same_flow = [f for f in findings if f.sink_node_index == 2 and f.matched_value == _IBAN]
    assert len(same_flow) == 1
    assert same_flow[0].kind == "structural"
