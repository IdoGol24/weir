"""Delta classes, default severities, exit codes, and the expected-diff
fixture schema (spec sections 4-5).

The diff ENGINE that produces real deltas is post-M4. This module fixes the
vocabulary now so the fixture families (spec section 6) can commit their
expectations as data the future engine's gold gate consumes - the L9
ground-truth pattern applied to the diff.
"""

from __future__ import annotations

import enum
import types
from collections.abc import Mapping

import msgspec

# Exit codes extending G6 (spec section 5). Exit 1 is ANY fail-class delta
# (the report carries behavioral vs evidentiary attribution); exit 3 means
# the compare itself is invalid (coverage floor or catalog/fact-schema skew).
EXIT_PASS = 0
EXIT_FAIL_DELTA = 1
EXIT_INPUT_ERROR = 2
EXIT_INVALID_COMPARE = 3

_KNOWN_EXIT_CODES = frozenset(
    {EXIT_PASS, EXIT_FAIL_DELTA, EXIT_INPUT_ERROR, EXIT_INVALID_COMPARE}
)


class DeltaKind(enum.StrEnum):
    NEW_FACT_UNGUARDED = "new_fact_unguarded"
    NEW_FACT_GUARDED = "new_fact_guarded"
    GUARD_REMOVED = "guard_removed"  # paired; live when guards land
    GUARD_SWAP = "guard_swap"  # paired; reserved, wording lands with guards
    MODE_ESCALATION = "mode_escalation"
    MODE_DEESCALATION = "mode_deescalation"
    REQUIRED_FACT_MISSING = "required_fact_missing"
    ALLOWED_FACT_MISSING = "allowed_fact_missing"
    NEW_UNCATALOGED_TOOL = "new_uncataloged_tool"
    # The two exit-3 rows of the spec's section 4 table. Modeled as delta
    # kinds rather than as a bare exit code so a fixture can assert WHY the
    # compare was refused: without them the degraded-telemetry family and the
    # skew family are the same assertion, and an engine that reported skew on
    # a degraded trace would pass the gate.
    COVERAGE_BELOW_FLOOR = "coverage_below_floor"
    COMPARE_SKEW = "compare_skew"


class Severity(enum.StrEnum):
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"
    # Not a gradient below FAIL: a distinct verdict meaning the compare itself
    # could not be trusted (spec section 4, fail-closed on exit 3).
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class Attribution(enum.StrEnum):
    BEHAVIORAL = "behavioral"
    EVIDENTIARY = "evidentiary"


_DEFAULT_SEVERITY: dict[DeltaKind, Severity] = {
    DeltaKind.NEW_FACT_UNGUARDED: Severity.FAIL,
    DeltaKind.NEW_FACT_GUARDED: Severity.WARN,
    DeltaKind.GUARD_REMOVED: Severity.FAIL,
    DeltaKind.GUARD_SWAP: Severity.FAIL,
    DeltaKind.MODE_ESCALATION: Severity.FAIL,
    DeltaKind.MODE_DEESCALATION: Severity.INFO,
    DeltaKind.REQUIRED_FACT_MISSING: Severity.WARN,
    DeltaKind.ALLOWED_FACT_MISSING: Severity.INFO,
    DeltaKind.NEW_UNCATALOGED_TOOL: Severity.WARN,
    DeltaKind.COVERAGE_BELOW_FLOOR: Severity.INSUFFICIENT_EVIDENCE,
    DeltaKind.COMPARE_SKEW: Severity.INSUFFICIENT_EVIDENCE,
}

if set(_DEFAULT_SEVERITY) != set(DeltaKind):
    raise RuntimeError("DEFAULT_SEVERITY must cover every DeltaKind")

# Read-only. Config escalation must build a per-run overlay
# ({**DEFAULT_SEVERITY, **overrides}), never mutate the shared table: a
# process-wide mutation would leak across scenarios and across tests.
DEFAULT_SEVERITY: Mapping[DeltaKind, Severity] = types.MappingProxyType(_DEFAULT_SEVERITY)

# Severities a fixture may declare for a kind: normally exactly the default.
# The spec makes the uncataloged-tool delta "config-escalatable to fail", so
# that single row admits an upward override and nothing else does.
_ALLOWED_SEVERITIES: dict[DeltaKind, frozenset[Severity]] = {
    kind: frozenset({severity}) for kind, severity in _DEFAULT_SEVERITY.items()
}
_ALLOWED_SEVERITIES[DeltaKind.NEW_UNCATALOGED_TOOL] = frozenset(
    {Severity.WARN, Severity.FAIL}
)

# Kinds whose attribution the spec pins. The rest stay free on purpose: a new
# or missing fact can genuinely arise behaviorally OR evidentiarily, and that
# duality is the whole point of the attribution field.
_PINNED_ATTRIBUTION: dict[DeltaKind, Attribution] = {
    DeltaKind.NEW_UNCATALOGED_TOOL: Attribution.EVIDENTIARY,
    DeltaKind.COVERAGE_BELOW_FLOOR: Attribution.EVIDENTIARY,
    DeltaKind.COMPARE_SKEW: Attribution.EVIDENTIARY,
}


class ExpectedDelta(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    kind: DeltaKind
    severity: Severity
    attribution: Attribution
    note: str | None = None

    def __post_init__(self) -> None:
        allowed = _ALLOWED_SEVERITIES[self.kind]
        if self.severity not in allowed:
            raise ValueError(
                f"severity for {self.kind} must be one of "
                f"{sorted(s.value for s in allowed)}"
            )
        pinned = _PINNED_ATTRIBUTION.get(self.kind)
        if pinned is not None and self.attribution is not pinned:
            raise ValueError(f"attribution for {self.kind} must be {pinned.value}")


class ExpectedDiff(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """One fixture family expectation: baseline + candidates -> deltas + exit.
    Fixture paths are relative to the repo's `weir/fixtures/` directory."""

    baseline_fixture: str
    candidate_fixtures: list[str]
    expected_exit_code: int
    deltas: list[ExpectedDelta]

    def __post_init__(self) -> None:
        if self.expected_exit_code not in _KNOWN_EXIT_CODES:
            raise ValueError(
                f"expected_exit_code must be one of {sorted(_KNOWN_EXIT_CODES)}"
            )
        if self.candidate_fixtures != sorted(set(self.candidate_fixtures)):
            raise ValueError("candidate_fixtures must be sorted and duplicate-free")
        has_fail = any(d.severity is Severity.FAIL for d in self.deltas)
        has_insufficient = any(
            d.severity is Severity.INSUFFICIENT_EVIDENCE for d in self.deltas
        )
        if has_fail and has_insufficient:
            raise ValueError(
                "a compare that could not be trusted cannot also report a "
                "fail-class delta"
            )
        if has_fail != (self.expected_exit_code == EXIT_FAIL_DELTA):
            raise ValueError(
                "exit 1 and a fail-class delta imply each other (spec section 5)"
            )
        if has_insufficient != (self.expected_exit_code == EXIT_INVALID_COMPARE):
            raise ValueError(
                "exit 3 and an insufficient-evidence delta imply each other"
            )


def decode_expected_diff(data: bytes | str) -> ExpectedDiff:
    return msgspec.json.decode(data, type=ExpectedDiff, strict=True)
