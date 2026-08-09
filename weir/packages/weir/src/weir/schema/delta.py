"""Delta classes, default severities, exit codes, and the expected-diff
fixture schema (spec sections 4-5).

The diff ENGINE that produces real deltas is post-M4. This module fixes the
vocabulary now so the fixture families (spec section 6) can commit their
expectations as data the future engine's gold gate consumes - the L9
ground-truth pattern applied to the diff.
"""

from __future__ import annotations

import enum

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


class Severity(enum.StrEnum):
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


class Attribution(enum.StrEnum):
    BEHAVIORAL = "behavioral"
    EVIDENTIARY = "evidentiary"


DEFAULT_SEVERITY: dict[DeltaKind, Severity] = {
    DeltaKind.NEW_FACT_UNGUARDED: Severity.FAIL,
    DeltaKind.NEW_FACT_GUARDED: Severity.WARN,
    DeltaKind.GUARD_REMOVED: Severity.FAIL,
    DeltaKind.GUARD_SWAP: Severity.FAIL,
    DeltaKind.MODE_ESCALATION: Severity.FAIL,
    DeltaKind.MODE_DEESCALATION: Severity.INFO,
    DeltaKind.REQUIRED_FACT_MISSING: Severity.WARN,
    DeltaKind.ALLOWED_FACT_MISSING: Severity.INFO,
    DeltaKind.NEW_UNCATALOGED_TOOL: Severity.WARN,
}

if set(DEFAULT_SEVERITY) != set(DeltaKind):
    raise RuntimeError("DEFAULT_SEVERITY must cover every DeltaKind")


class ExpectedDelta(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    kind: DeltaKind
    severity: Severity
    attribution: Attribution
    note: str | None = None


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
        has_fail = any(d.severity is Severity.FAIL for d in self.deltas)
        if has_fail and self.expected_exit_code != EXIT_FAIL_DELTA:
            raise ValueError(
                "a fail-class delta requires expected_exit_code == EXIT_FAIL_DELTA"
            )


def decode_expected_diff(data: bytes | str) -> ExpectedDiff:
    return msgspec.json.decode(data, type=ExpectedDiff, strict=True)
