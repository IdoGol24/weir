"""Scenario library data model (L7).

A ScenarioSpec is a declarative, composable trace template. Turning one into
a schema-validated CanonicalTrace (assigning ids/source_refs/timestamps via
the L6 seeded core) is L8's job, the native Seam-1 emitter - this module only
defines the data.
"""

from __future__ import annotations

import msgspec


class StepSpec(msgspec.Struct, frozen=True):
    kind: str
    actor: str
    content: str | None = None
    tool_name: str | None = None
    args: dict[str, object] | None = None


class JoinSpec(msgspec.Struct, frozen=True):
    """Ties a tool_call step to its tool_result step by position in
    ScenarioSpec.steps - L8 resolves these into real JoinRecords once each
    step has been assigned a source_ref."""

    call_index: int
    result_index: int
    join_confidence: str = "explicit"


class ScenarioSpec(msgspec.Struct, frozen=True):
    name: str
    description: str
    steps: list[StepSpec]
    joins: list[JoinSpec]
