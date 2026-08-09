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
    assert DEFAULT_SEVERITY[DeltaKind.COVERAGE_BELOW_FLOOR] == Severity.INSUFFICIENT_EVIDENCE
    assert DEFAULT_SEVERITY[DeltaKind.COMPARE_SKEW] == Severity.INSUFFICIENT_EVIDENCE


def test_every_kind_has_a_default_severity() -> None:
    assert set(DEFAULT_SEVERITY) == set(DeltaKind)


def test_expected_diff_roundtrip() -> None:
    diff = ExpectedDiff(
        baseline_fixture="diffspec/baselines/injection-exfil.baseline.json",
        scenario_id="injection-exfil",
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
            b'{"baseline_fixture": "x", "scenario_id": "injection-exfil", '
            b'"candidate_fixtures": [], '
            b'"expected_exit_code": 1, "deltas": [{"kind": "nonsense", '
            b'"severity": "fail", "attribution": "behavioral"}]}'
        )


def test_decode_rejects_unknown_fields() -> None:
    with pytest.raises((msgspec.ValidationError, msgspec.DecodeError)):
        decode_expected_diff(b'{"bogus": true}')


def test_expected_exit_code_must_be_a_known_code() -> None:
    with pytest.raises(ValueError, match="expected_exit_code"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
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
            scenario_id="injection-exfil",
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
        scenario_id="injection-exfil",
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


def _delta(kind: DeltaKind, severity: Severity, attribution: Attribution) -> ExpectedDelta:
    return ExpectedDelta(kind=kind, severity=severity, attribution=attribution)


def test_exit_three_requires_an_insufficient_evidence_delta() -> None:
    with pytest.raises(ValueError, match="exit 3"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
            candidate_fixtures=[],
            expected_exit_code=EXIT_INVALID_COMPARE,
            deltas=[],
        )


def test_insufficient_evidence_delta_requires_exit_three() -> None:
    with pytest.raises(ValueError, match="exit 3"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
            candidate_fixtures=[],
            expected_exit_code=EXIT_PASS,
            deltas=[
                _delta(
                    DeltaKind.COVERAGE_BELOW_FLOOR,
                    Severity.INSUFFICIENT_EVIDENCE,
                    Attribution.EVIDENTIARY,
                )
            ],
        )


def test_exit_one_requires_a_fail_delta() -> None:
    with pytest.raises(ValueError, match="fail-class"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
            candidate_fixtures=[],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[],
        )


def test_untrusted_compare_cannot_also_fail() -> None:
    with pytest.raises(ValueError, match="could not be trusted"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
            candidate_fixtures=[],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[
                _delta(DeltaKind.MODE_ESCALATION, Severity.FAIL, Attribution.BEHAVIORAL),
                _delta(
                    DeltaKind.COMPARE_SKEW,
                    Severity.INSUFFICIENT_EVIDENCE,
                    Attribution.EVIDENTIARY,
                ),
            ],
        )


def test_the_two_exit_three_causes_are_distinguishable() -> None:
    # The point of FIX 1: a degraded-telemetry expectation and a skew
    # expectation must not be the same assertion, or the gate cannot tell an
    # engine that reports the wrong cause from one that is right.
    coverage = ExpectedDiff(
        baseline_fixture="x",
        scenario_id="injection-exfil",
        candidate_fixtures=[],
        expected_exit_code=EXIT_INVALID_COMPARE,
        deltas=[
            _delta(
                DeltaKind.COVERAGE_BELOW_FLOOR,
                Severity.INSUFFICIENT_EVIDENCE,
                Attribution.EVIDENTIARY,
            )
        ],
    )
    skew = ExpectedDiff(
        baseline_fixture="x",
        scenario_id="injection-exfil",
        candidate_fixtures=[],
        expected_exit_code=EXIT_INVALID_COMPARE,
        deltas=[
            _delta(
                DeltaKind.COMPARE_SKEW,
                Severity.INSUFFICIENT_EVIDENCE,
                Attribution.EVIDENTIARY,
            )
        ],
    )
    assert msgspec.json.encode(coverage) != msgspec.json.encode(skew)


def test_severity_must_match_the_default_for_the_kind() -> None:
    with pytest.raises(ValueError, match="severity for"):
        _delta(DeltaKind.NEW_FACT_UNGUARDED, Severity.INFO, Attribution.BEHAVIORAL)


def test_uncataloged_tool_may_be_escalated_to_fail() -> None:
    # spec section 4: this row is config-escalatable to fail, and nothing else is.
    diff = ExpectedDiff(
        baseline_fixture="x",
        scenario_id="injection-exfil",
        candidate_fixtures=[],
        expected_exit_code=EXIT_FAIL_DELTA,
        deltas=[
            _delta(
                DeltaKind.NEW_UNCATALOGED_TOOL, Severity.FAIL, Attribution.EVIDENTIARY
            )
        ],
    )
    assert diff.expected_exit_code == EXIT_FAIL_DELTA


def test_pinned_attribution_enforced() -> None:
    with pytest.raises(ValueError, match="attribution for"):
        _delta(
            DeltaKind.NEW_UNCATALOGED_TOOL, Severity.WARN, Attribution.BEHAVIORAL
        )


def test_attribution_stays_free_where_the_spec_leaves_it_free() -> None:
    # A missing fact can be behavioral (your fix removed the flow) or
    # evidentiary (telemetry degraded). Both must be expressible.
    for attribution in (Attribution.BEHAVIORAL, Attribution.EVIDENTIARY):
        assert (
            _delta(
                DeltaKind.REQUIRED_FACT_MISSING, Severity.WARN, attribution
            ).attribution
            is attribution
        )


def test_candidate_fixtures_must_be_sorted_and_unique() -> None:
    with pytest.raises(ValueError, match="candidate_fixtures"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="injection-exfil",
            candidate_fixtures=["b.json", "a.json"],
            expected_exit_code=EXIT_PASS,
            deltas=[],
        )


def test_default_severity_is_read_only() -> None:
    with pytest.raises(TypeError):
        DEFAULT_SEVERITY[DeltaKind.NEW_UNCATALOGED_TOOL] = Severity.FAIL  # type: ignore[index]


def test_invariants_fire_on_the_decode_path_too() -> None:
    # These files are read back from disk by the future engine's gold gate, so
    # the decode path is the one that matters. msgspec.ValidationError subclasses
    # ValueError, so a caller mapping input errors to exit 2 catches both paths
    # with one except - that is load-bearing and non-obvious.
    payload = (
        b'{"baseline_fixture": "x", "scenario_id": "injection-exfil", '
        b'"candidate_fixtures": [], '
        b'"expected_exit_code": 0, "deltas": [{"kind": "new_fact_unguarded", '
        b'"severity": "fail", "attribution": "behavioral"}]}'
    )
    with pytest.raises(ValueError):
        decode_expected_diff(payload)
    assert issubclass(msgspec.ValidationError, ValueError)


def test_scenario_id_must_be_non_empty() -> None:
    with pytest.raises(ValueError, match="scenario_id"):
        ExpectedDiff(
            baseline_fixture="x",
            scenario_id="",
            candidate_fixtures=[],
            expected_exit_code=EXIT_PASS,
            deltas=[],
        )
