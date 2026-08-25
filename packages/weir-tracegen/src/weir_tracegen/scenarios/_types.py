"""Scenario library data model (L7).

A ScenarioSpec is a declarative, composable trace template. Turning one into
a schema-validated CanonicalTrace (assigning ids/source_refs/timestamps via
the L6 seeded core) is L8's job, the native Seam-1 emitter - this module only
defines the data.
"""

from __future__ import annotations

import msgspec


class StepSpec(msgspec.Struct, frozen=True):
    """One step of a scenario plan.

    The last two fields are DECLARATIVE DIAL STATE, not renderer instructions.
    A dial is a pure plan-to-plan function; each renderer maps these fields
    into its own dialect and never knows a dial exists. The defaults are the
    undialed values, which is what keeps the committed fixtures byte-identical.
    """

    kind: str
    actor: str
    content: str | None = None
    tool_name: str | None = None
    args: dict[str, object] | None = None
    # False means the instrumentation captured no payload for this step. The
    # native renderer maps that to empty args plus degraded=True; the OTLP
    # renderer omits the content-bearing attributes. This is the wild's
    # privacy default and therefore the most common real trace weir will see.
    content_captured: bool = True
    # Nanosecond offset applied to this step's timestamp, modelling clock skew,
    # which is legal OTLP and real. The plan has no other notion of time: the
    # seeded clock lives inside the renderers, so without this field a timing
    # dial could not be a plan transform at all.
    clock_offset_ns: int = 0


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
