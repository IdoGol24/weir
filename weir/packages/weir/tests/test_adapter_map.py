"""Stage 2: kind from real OTel signals only, actor from kind (the pinned
invariant), payloads with named degradations."""

from weir.adapters.otel._contract import DegradationReason
from weir.adapters.otel._map import (
    MappedSpan,
    attr_str,
    build_joins,
    derive_kind,
    parse_json_object,
)
from weir.adapters.otel._wire import WireSpan
from weir.schema.trace import JoinConfidence, NodeKind


def _span(kind: int | str, attrs: dict[str, str]) -> WireSpan:
    return WireSpan(
        trace_id="ab" * 16, span_id="cd" * 8, name="n", kind=kind,
        start_time_unix_nano="1", end_time_unix_nano="2",
        attributes=[{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    )


def test_kind_derivation_from_operation_and_span_kind() -> None:
    assert derive_kind(_span(3, {"gen_ai.operation.name": "chat"})) == NodeKind.LLM_CALL
    assert derive_kind(_span(1, {"gen_ai.operation.name": "chat"})) == NodeKind.USER_INPUT
    assert derive_kind(_span(3, {"gen_ai.operation.name": "execute_tool"})) == NodeKind.TOOL_CALL
    assert derive_kind(_span(1, {"gen_ai.operation.name": "execute_tool"})) == NodeKind.TOOL_RESULT


def test_kind_falls_back_to_tool_name_presence_without_operation() -> None:
    assert derive_kind(_span(3, {"gen_ai.tool.name": "search"})) == NodeKind.TOOL_CALL
    assert derive_kind(_span(1, {"gen_ai.tool.name": "search"})) == NodeKind.TOOL_RESULT


def test_unknown_operation_is_unmappable() -> None:
    assert derive_kind(_span(3, {"gen_ai.operation.name": "embeddings"})) is None


def test_kind_derivation_from_string_enum_span_kind() -> None:
    # Vanilla protojson (default MessageToJson) emits proto enum NAMES for
    # span kind, not the OTLP/JSON-mandated int - same permissive-scalar
    # rationale as the nanos fields.
    assert (
        derive_kind(_span("SPAN_KIND_CLIENT", {"gen_ai.operation.name": "chat"}))
        == NodeKind.LLM_CALL
    )
    assert (
        derive_kind(_span("SPAN_KIND_INTERNAL", {"gen_ai.operation.name": "chat"}))
        == NodeKind.USER_INPUT
    )
    # Unknown name treated as 0/unspecified: falls to the non-client branch.
    assert (
        derive_kind(_span("SPAN_KIND_MADE_UP", {"gen_ai.operation.name": "chat"}))
        == NodeKind.USER_INPUT
    )


def test_kind_never_reads_weir_attributes() -> None:
    # weir.* is producer self-description: untrusted. A weir.kind "hint" must
    # not rescue an otherwise unmappable span.
    assert derive_kind(_span(3, {"weir.kind": "tool_call"})) is None


def test_attr_str_reads_string_values_only() -> None:
    span = _span(3, {"gen_ai.operation.name": "chat"})
    assert attr_str(span.attributes, "gen_ai.operation.name") == "chat"
    assert attr_str(span.attributes, "absent") is None


def _mapped(source_ref: str, kind: NodeKind, *, call_id: str | None = None,
            parent: str = "", mined: str | None = None) -> MappedSpan:
    return MappedSpan(source_ref=source_ref, kind=kind, call_id_attr=call_id,
                      parent_token=parent, mined_id=mined)


def test_explicit_attribute_join() -> None:
    call = _mapped("aa", NodeKind.TOOL_CALL, call_id="c1")
    result = _mapped("bb", NodeKind.TOOL_RESULT, call_id="c1")
    joins, degradations = build_joins([call, result])
    assert len(joins) == 1
    assert joins[0].join_confidence == JoinConfidence.EXPLICIT
    assert joins[0].join_source == "attr:gen_ai.tool.call.id"
    assert degradations == []


def test_nested_join_when_attribute_absent() -> None:
    call = _mapped("aa", NodeKind.TOOL_CALL)
    result = _mapped("bb", NodeKind.TOOL_RESULT, parent="aa")
    joins, _ = build_joins([call, result])
    assert joins[0].join_confidence == JoinConfidence.NESTED
    assert joins[0].join_source == "parent_span"


def test_content_mined_fills_absence_only() -> None:
    call = _mapped("aa", NodeKind.TOOL_CALL, mined="m1")
    result = _mapped("bb", NodeKind.TOOL_RESULT, mined="m1")
    joins, degradations = build_joins([call, result])
    assert joins[0].join_confidence == JoinConfidence.CONTENT_MINED
    assert joins[0].join_source == "content:tool_call_id"
    assert degradations == []


def test_envelope_beats_mined_and_conflict_is_ledgered() -> None:
    # Nesting says aa<-bb; mined ids say aa<-cc. Envelope wins; conflict named.
    call = _mapped("aa", NodeKind.TOOL_CALL, mined="m1")
    nested_result = _mapped("bb", NodeKind.TOOL_RESULT, parent="aa")
    mined_result = _mapped("cc", NodeKind.TOOL_RESULT, mined="m1")
    joins, degradations = build_joins([call, nested_result, mined_result])
    assert [(j.tool_call_source_ref, j.tool_result_source_ref, j.join_confidence)
            for j in joins] == [("aa", "bb", JoinConfidence.NESTED)]
    assert [d.reason for d in degradations] == [
        DegradationReason.CONFLICTING_JOIN_EVIDENCE
    ]


def test_ambiguous_mined_id_yields_no_join() -> None:
    call = _mapped("aa", NodeKind.TOOL_CALL, mined="m1")
    r1 = _mapped("bb", NodeKind.TOOL_RESULT, mined="m1")
    r2 = _mapped("cc", NodeKind.TOOL_RESULT, mined="m1")
    joins, degradations = build_joins([call, r1, r2])
    assert joins == []
    assert [d.reason for d in degradations] == [DegradationReason.AMBIGUOUS_JOIN]


def test_duplicated_call_side_explicit_id_is_ambiguous_not_greedy() -> None:
    # Symmetric ambiguity: two CALLS sharing an id must not resolve by
    # processing order (silent greedy stealing) - an injected document can
    # manufacture a duplicate call-side id, and a positional pick would be
    # exactly the "ambiguity resolved silently" shape the spec forbids.
    c1 = _mapped("aa", NodeKind.TOOL_CALL, call_id="c1")
    c2 = _mapped("bb", NodeKind.TOOL_CALL, call_id="c1")
    result = _mapped("cc", NodeKind.TOOL_RESULT, call_id="c1")
    joins, degradations = build_joins([c1, c2, result])
    assert joins == []
    assert [d.reason for d in degradations] == [DegradationReason.AMBIGUOUS_JOIN]


def test_duplicated_call_side_mined_id_is_ambiguous_not_greedy() -> None:
    c1 = _mapped("aa", NodeKind.TOOL_CALL, mined="m1")
    c2 = _mapped("bb", NodeKind.TOOL_CALL, mined="m1")
    result = _mapped("cc", NodeKind.TOOL_RESULT, mined="m1")
    joins, degradations = build_joins([c1, c2, result])
    assert joins == []
    assert [d.reason for d in degradations] == [DegradationReason.AMBIGUOUS_JOIN]


def test_call_with_ambiguous_explicit_id_can_still_join_by_nesting() -> None:
    # Ambiguity kills the ambiguous EVIDENCE tier, not the call's other,
    # unambiguous envelope evidence.
    c1 = _mapped("aa", NodeKind.TOOL_CALL, call_id="c1")
    c2 = _mapped("bb", NodeKind.TOOL_CALL, call_id="c1")
    nested_result = _mapped("cc", NodeKind.TOOL_RESULT, parent="aa")
    joins, degradations = build_joins([c1, c2, nested_result])
    assert [(j.tool_call_source_ref, j.join_confidence) for j in joins] == [
        ("aa", JoinConfidence.NESTED)
    ]
    assert [d.reason for d in degradations] == [DegradationReason.AMBIGUOUS_JOIN]


def test_heuristic_is_never_assigned() -> None:
    # Two unlinked spans adjacent in time: NO temporal-proximity join (owner
    # decision - that tier is out of M4 entirely). Unjoined = absent record.
    call = _mapped("aa", NodeKind.TOOL_CALL)
    result = _mapped("bb", NodeKind.TOOL_RESULT)
    joins, degradations = build_joins([call, result])
    assert joins == [] and degradations == []


def test_empty_string_ids_are_not_join_evidence() -> None:
    # Semantically absent ids ("") must not create joins at any tier.
    call = _mapped("aa", NodeKind.TOOL_CALL, call_id="")
    result = _mapped("bb", NodeKind.TOOL_RESULT, call_id="")
    assert build_joins([call, result]) == ([], [])
    call = _mapped("aa", NodeKind.TOOL_CALL, mined="")
    result = _mapped("bb", NodeKind.TOOL_RESULT, mined="")
    assert build_joins([call, result]) == ([], [])


def test_envelope_beats_mined_regardless_of_call_order() -> None:
    # A mined call that sorts EARLIER must not steal a result whose envelope
    # evidence points at a later call - precedence is global, not positional.
    mined_call = _mapped("aa", NodeKind.TOOL_CALL, mined="m1")
    env_call = _mapped("bb", NodeKind.TOOL_CALL)
    result = _mapped("cc", NodeKind.TOOL_RESULT, parent="bb", mined="m1")
    joins, degradations = build_joins([mined_call, env_call, result])
    assert [(j.tool_call_source_ref, j.tool_result_source_ref, j.join_confidence)
            for j in joins] == [("bb", "cc", JoinConfidence.NESTED)]
    # aa's mined id points at a claimed result: fill-absences leaves it
    # unjoined, silently (the result is not absent - it is claimed).
    assert degradations == []


def test_truncation_fingerprint_catches_mid_string_cut() -> None:
    # A payload limit usually cuts inside an open string; json reports the
    # error at the OPENING quote, so the fingerprint must not rely on
    # position alone.
    parsed, truncated = parse_json_object('{"mailbox":"suppo')
    assert parsed is None and truncated is True


def test_mid_string_garbage_is_not_truncation() -> None:
    parsed, truncated = parse_json_object('{"query": nope, "x": 1}')
    assert parsed is None and truncated is False
