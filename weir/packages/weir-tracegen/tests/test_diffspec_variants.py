"""The four diffspec scenario variants (spec section 6, families 2 and 4)."""

from weir.catalog import DEFAULT_CATALOG
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import NodeKind, ToolCallPayload, encode_canonical_trace
from weir.taint import build_tainted_graph
from weir_tracegen.emitter import emit

_IBAN = "DE89370400440532013000"

_VARIANTS = (
    "injection-exfil-context-only",
    "injection-exfil-external",
    "injection-exfil-webhook",
    "injection-exfil-uncataloged",
)


def _tool_calls(name: str) -> dict[str, dict[str, object]]:
    trace = emit(name, seed=1)
    return {
        node.payload.tool_name: node.payload.args
        for node in trace.nodes
        if isinstance(node.payload, ToolCallPayload)
    }


def _arg(name: str, tool: str, key: str) -> str:
    value = _tool_calls(name)[tool][key]
    assert isinstance(value, str)
    return value


def test_all_variants_emit_deterministically() -> None:
    for name in _VARIANTS:
        assert encode_canonical_trace(emit(name, seed=1)) == encode_canonical_trace(
            emit(name, seed=1)
        )


def test_all_variants_validate_against_the_schema() -> None:
    from weir.schema.trace import decode_canonical_trace

    for name in _VARIANTS:
        decode_canonical_trace(encode_canonical_trace(emit(name, seed=1)))


def test_joins_reference_real_nodes_in_every_variant() -> None:
    for name in _VARIANTS:
        trace = emit(name, seed=1)
        nodes_by_ref = {node.source_ref: node for node in trace.nodes}
        for join in trace.joins:
            assert join.tool_call_source_ref in nodes_by_ref
            assert join.tool_result_source_ref in nodes_by_ref
            # build_session_graph silently drops dangling joins and the schema
            # does not validate endpoint kinds, so a mis-targeted join (e.g. a
            # call ref pointed at a tool_result node) would otherwise pass.
            assert nodes_by_ref[join.tool_call_source_ref].kind == NodeKind.TOOL_CALL
            assert nodes_by_ref[join.tool_result_source_ref].kind == NodeKind.TOOL_RESULT


def test_context_only_keeps_the_injection_but_not_the_verbatim_secret() -> None:
    trace = emit("injection-exfil-context-only", seed=1)
    contents = " ".join(
        node.payload.content for node in trace.nodes if hasattr(node.payload, "content")
    )
    assert _IBAN in contents  # the tainted source still carries it
    assert _IBAN not in _arg("injection-exfil-context-only", "send_email", "body")


def test_external_variant_changes_only_the_destination() -> None:
    assert _arg("injection-exfil-external", "send_email", "to") == "exfil@attacker.example"
    assert _IBAN in _arg("injection-exfil-external", "send_email", "body")


def test_webhook_variant_adds_a_second_cataloged_sink() -> None:
    calls = _tool_calls("injection-exfil-webhook")
    assert "send_email" in calls
    assert _IBAN in _arg("injection-exfil-webhook", "post_to_webhook", "payload")
    assert _arg("injection-exfil-webhook", "post_to_webhook", "url").startswith("https://")


def test_uncataloged_variant_routes_taint_through_an_unknown_tool() -> None:
    assert _IBAN in _arg("injection-exfil-uncataloged", "translate_text", "text")
    # the underlying red flow is unchanged: the secret still reaches send_email
    assert _IBAN in _arg("injection-exfil-uncataloged", "send_email", "body")


def test_variants_do_not_disturb_the_base_pair() -> None:
    # The gold fixtures are byte-checked elsewhere; this asserts the base
    # scenarios are still registered and emit, so registering four new names
    # cannot have shadowed them.
    for name in ("injection-exfil", "injection-exfil-benign"):
        assert emit(name, seed=1).nodes


def _verbatim_identities(name: str) -> set[tuple[str, str, str | None]]:
    """The SET of (source_class, sink tool name, sink true_destination)
    triples over a scenario's verbatim matches, run through the real
    pipeline (build_session_graph -> label_graph -> build_tainted_graph)."""
    trace = emit(name, seed=1)
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    sink_labels_by_index = {label.node_index: label for label in labeled.sink_labels}
    identities: set[tuple[str, str, str | None]] = set()
    for match in tainted.verbatim_matches:
        sink_label = sink_labels_by_index[match.sink_node_index]
        identities.add((match.source_class, sink_label.tool_name, sink_label.true_destination))
    return identities


# The following four tests pin each variant's identity relationship to the
# injection-exfil reference at the pipeline level (not just raw trace args).
# Each variant exists to produce exactly ONE unambiguous delta against the
# reference; a variant that quietly acquires a second, unintended difference
# would make the future gold-fixture gate assert the wrong thing. These tests
# are what the "exactly one delta" property depends on.


def test_external_variant_changes_only_the_destination_identity() -> None:
    reference = _verbatim_identities("injection-exfil")
    variant = _verbatim_identities("injection-exfil-external")
    (reference_source, reference_tool, reference_destination) = next(iter(reference))
    (variant_source, variant_tool, variant_destination) = next(iter(variant))
    assert len(reference) == 1
    assert len(variant) == 1
    assert variant_source == reference_source
    assert variant_tool == reference_tool
    assert variant_destination != reference_destination


def test_webhook_variant_adds_exactly_one_identity_and_keeps_the_original() -> None:
    reference = _verbatim_identities("injection-exfil")
    variant = _verbatim_identities("injection-exfil-webhook")
    assert reference <= variant
    assert len(variant - reference) == 1


def test_uncataloged_variant_changes_no_identity() -> None:
    # This fixture isolates the catalog gap (an unknown tool on the path) and
    # nothing else - the underlying red flow's identity must be untouched.
    assert _verbatim_identities("injection-exfil-uncataloged") == _verbatim_identities(
        "injection-exfil"
    )


def test_context_only_shares_the_reference_identity_via_context_reach() -> None:
    # Zero verbatim matches is the point of this variant, so there is no
    # identity triple to compare directly. Assert the ingredients instead: if
    # the escalation baseline does not reach the sink via context taint, the
    # mode-escalation fixture has nothing to escalate from.
    assert _verbatim_identities("injection-exfil-context-only") == set()

    reference_trace = emit("injection-exfil", seed=1)
    reference_graph = build_session_graph(reference_trace)
    reference_labeled = label_graph(reference_graph, DEFAULT_CATALOG)
    reference_tainted = build_tainted_graph(reference_labeled, DEFAULT_CATALOG)
    (reference_match,) = reference_tainted.verbatim_matches
    (reference_sink_label,) = [
        label
        for label in reference_labeled.sink_labels
        if label.node_index == reference_match.sink_node_index
    ]

    trace = emit("injection-exfil-context-only", seed=1)
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)

    matching_sinks = [
        label
        for label in labeled.sink_labels
        if label.tool_name == reference_sink_label.tool_name
        and label.true_destination == reference_sink_label.true_destination
    ]
    assert matching_sinks
    sink_index = matching_sinks[0].node_index

    matching_sources = [
        label
        for label in labeled.source_labels
        if label.source_class == reference_match.source_class
    ]
    assert matching_sources
    source_index = matching_sources[0].node_index

    assert sink_index in tainted.context_tainted.get(source_index, [])
