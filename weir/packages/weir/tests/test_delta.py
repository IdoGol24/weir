"""Tests for the delta schema (spec section 4 severity table + section 5 exit codes)."""

import msgspec
import pytest

from weir.schema.delta import (
    DEFAULT_SEVERITY,
    EXIT_FAIL_DELTA,
    EXIT_INPUT_ERROR,
    EXIT_INVALID_COMPARE,
    EXIT_PASS,
    Attribution,
    DeltaKind,
    ExpectedDelta,
    ExpectedDiff,
    Severity,
    decode_expected_diff,
)


def test_exit_codes_extend_g6() -> None:
    assert (EXIT_PASS, EXIT_FAIL_DELTA, EXIT_INPUT_ERROR, EXIT_INVALID_COMPARE) == (
        0,
        1,
        2,
        3,
    )


def test_default_severity_matches_spec_table() -> None:
    assert DEFAULT_SEVERITY[DeltaKind.NEW_FACT_UNGUARDED] == Severity.FAIL
    assert DEFAULT_SEVERITY[DeltaKind.NEW_FACT_GUARDED] == Severity.WARN
    assert DEFAULT_SEVERITY[DeltaKind.GUARD_REMOVED] == Severity.FAIL
    assert DEFAULT_SEVERITY[DeltaKind.GUARD_SWAP] == Severity.FAIL
    assert DEFAULT_SEVERITY[DeltaKind.MODE_ESCALATION] == Severity.FAIL
    assert DEFAULT_SEVERITY[DeltaKind.MODE_DEESCALATION] == Severity.INFO
    assert DEFAULT_SEVERITY[DeltaKind.REQUIRED_FACT_MISSING] == Severity.WARN
    assert DEFAULT_SEVERITY[DeltaKind.ALLOWED_FACT_MISSING] == Severity.INFO
    assert DEFAULT_SEVERITY[DeltaKind.NEW_UNCATALOGED_TOOL] == Severity.WARN


def test_every_kind_has_a_default_severity() -> None:
    assert set(DEFAULT_SEVERITY) == set(DeltaKind)


def test_expected_diff_roundtrip() -> None:
    diff = ExpectedDiff(
        baseline_fixture="diffspec/baselines/injection-exfil.baseline.json",
        candidate_fixtures=["diffspec/variants/injection-exfil-external.json"],
        expected_exit_code=EXIT_FAIL_DELTA,
        deltas=[
            ExpectedDelta(
                kind=DeltaKind.NEW_FACT_UNGUARDED,
                severity=Severity.FAIL,
                attribution=Attribution.BEHAVIORAL,
                note="replaces previous known-contact flow",
            )
        ],
    )
    raw = msgspec.json.encode(diff)
    assert decode_expected_diff(raw) == diff


def test_note_defaults_to_none() -> None:
    delta = ExpectedDelta(
        kind=DeltaKind.MODE_ESCALATION,
        severity=Severity.FAIL,
        attribution=Attribution.BEHAVIORAL,
    )
    assert delta.note is None


def test_decode_rejects_unknown_kind() -> None:
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        decode_expected_diff(
            b'{"baseline_fixture": "x", "candidate_fixtures": [], '
            b'"expected_exit_code": 0, "deltas": [{"kind": "nonsense", '
            b'"severity": "fail", "attribution": "behavioral"}]}'
        )


def test_decode_rejects_unknown_fields() -> None:
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        decode_expected_diff(b'{"bogus": true}')


def test_expected_exit_code_must_be_a_known_code() -> None:
    with pytest.raises(ValueError, match="expected_exit_code"):
        ExpectedDiff(
            baseline_fixture="x",
            candidate_fixtures=[],
            expected_exit_code=7,
            deltas=[],
        )


def test_fail_class_delta_requires_exit_one() -> None:
    # Spec section 5: exit 1 is "any fail-class delta". An expectation that
    # lists a fail-severity delta but expects a passing exit contradicts the
    # gate contract, and these files are the future engine's gold gate.
    with pytest.raises(ValueError, match="fail-class"):
        ExpectedDiff(
            baseline_fixture="x",
            candidate_fixtures=[],
            expected_exit_code=EXIT_PASS,
            deltas=[
                ExpectedDelta(
                    kind=DeltaKind.NEW_FACT_UNGUARDED,
                    severity=Severity.FAIL,
                    attribution=Attribution.BEHAVIORAL,
                )
            ],
        )


def test_warn_class_delta_may_pass() -> None:
    # The uncataloged-tool delta warns by default: it reports without gating.
    diff = ExpectedDiff(
        baseline_fixture="x",
        candidate_fixtures=[],
        expected_exit_code=EXIT_PASS,
        deltas=[
            ExpectedDelta(
                kind=DeltaKind.NEW_UNCATALOGED_TOOL,
                severity=Severity.WARN,
                attribution=Attribution.EVIDENTIARY,
                note="register or classify this tool: translate_text",
            )
        ],
    )
    assert diff.expected_exit_code == EXIT_PASS
