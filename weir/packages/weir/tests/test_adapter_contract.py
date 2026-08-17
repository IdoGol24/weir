"""The reject-vs-degrade contract, executable form (M4 design section 2)."""

from weir.adapters.otel._contract import REMEDIATION, Degradation, DegradationReason


def test_every_reason_has_a_remediation_string() -> None:
    # The enum IS the contract: a reason without remediation text is a
    # malformation the capability ladder cannot explain to a user.
    assert set(REMEDIATION) == set(DegradationReason)
    assert all(isinstance(v, str) and v for v in REMEDIATION.values())


def test_degradation_is_frozen_and_carries_reason_subject_note() -> None:
    d = Degradation(reason=DegradationReason.ORPHANED_PARENT, subject="ab12", note="x")
    assert (d.reason, d.subject, d.note) == (DegradationReason.ORPHANED_PARENT, "ab12", "x")


def test_mapper_attribute_keys_come_from_the_profile() -> None:
    # Row-one inlining is legal only while pinned to the profile data.
    from weir.schema.dialect import OTEL_GENAI_1_42_0
    profile_keys = {spec.key for spec in OTEL_GENAI_1_42_0.attributes}
    for key in (
        "gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.tool.name",
        "gen_ai.tool.call.id", "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result", "gen_ai.input.messages",
        "gen_ai.output.messages",
    ):
        assert key in profile_keys
