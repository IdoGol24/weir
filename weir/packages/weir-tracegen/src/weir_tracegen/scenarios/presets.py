"""Generation presets: which conformance clauses a generated corpus
deliberately satisfies.

These are NOT profile ids. The spec defines exactly one conformance profile,
`weir-provable/1`, whose contract is per-clause pass/fail reporting by the
gauge. A preset is a tracegen generation label, stamped as
`weir.tracegen.preset`. An emitter that stamped its own conformance level
would be marking its own homework.

A preset name without a clause set is the spec's prose bug reborn one layer
down, so every preset here carries its clause set explicitly.
"""

from __future__ import annotations

import enum

import msgspec

from weir_tracegen.scenarios._types import ScenarioSpec
from weir_tracegen.scenarios.dials import without_content, without_linkage


class Clause(enum.StrEnum):
    """The four conformance clauses, named so a preset can declare which it
    meets."""

    EXPLICIT_TOOL_CALL_LINKAGE = "explicit_tool_call_linkage"
    FULL_ARGUMENT_PAYLOADS = "full_argument_payloads"
    PRESERVED_SOURCE_REF = "preserved_source_ref"
    STABLE_ACTOR_IDENTIFIERS = "stable_actor_identifiers"


class Preset(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    name: str
    clauses: frozenset[Clause]
    description: str


_ALL = frozenset(Clause)

PRESETS: dict[str, Preset] = {
    "full": Preset(
        name="full",
        clauses=_ALL,
        description="Every clause satisfied. The verdict-grade-eligible corpus.",
    ),
    "partial": Preset(
        name="partial",
        clauses=_ALL - {Clause.EXPLICIT_TOOL_CALL_LINKAGE},
        description=(
            "Content ON, explicit tool_call linkage ABSENT: the join must fall back "
            "to parent/child nesting. Note that content smuggles linkage, so this "
            "preset does not fully isolate the nesting fallback until the adapter "
            "milestone rules on the join-source taxonomy."
        ),
    ),
    "default-realistic": Preset(
        name="default-realistic",
        clauses=_ALL - {Clause.FULL_ARGUMENT_PAYLOADS},
        description=(
            "Content capture OFF, linkage present. The wild's privacy default and "
            "therefore the most common real trace weir will ever gauge."
        ),
    ),
}


def apply_preset(plan: ScenarioSpec, preset_name: str) -> ScenarioSpec:
    preset = PRESETS[preset_name]
    dialed = plan
    if Clause.FULL_ARGUMENT_PAYLOADS not in preset.clauses:
        dialed = without_content(dialed)
    if Clause.EXPLICIT_TOOL_CALL_LINKAGE not in preset.clauses:
        dialed = without_linkage(dialed)
    return dialed
