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
