"""The four diffspec scenario variants (spec section 6, families 2 and 4)."""

from weir.schema.trace import ToolCallPayload, encode_canonical_trace
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
        refs = {node.source_ref for node in trace.nodes}
        for join in trace.joins:
            assert join.tool_call_source_ref in refs
            assert join.tool_result_source_ref in refs


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
