"""Flow-baseline schema for the version-diff gate (spec section 3).

The serialized baseline is content-addressed (canonical bytes, SHA-256) so it
is the same object family M5 later signs - one format for the CI baseline and
the compliance witness. Required = facts in ALL capture runs (intersection);
allowed = facts in ANY run (union). N=1 baselines are valid; n_runs==1 IS the
flag the spec asks for. The observations section makes the uncataloged-tool
rule stateful (spec section 4): diff flags only tools NOT in that set.
"""

from __future__ import annotations

import hashlib
import json

import msgspec

from weir.schema.flowfact import FlowFact, identity_digest


class BaselineObservations(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uncataloged_tools_on_tainted_paths: list[str]

    def __post_init__(self) -> None:
        tools = self.uncataloged_tools_on_tainted_paths
        if tools != sorted(set(tools)):
            raise ValueError(
                "uncataloged_tools_on_tainted_paths must be sorted and duplicate-free"
            )


class ScenarioBaseline(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    scenario_id: str
    required: list[FlowFact]
    allowed: list[FlowFact]
    observations: BaselineObservations


class BaselineMetadata(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    n_runs: int
    weir_version: str
    catalog_digest: str
    source_trace_digests: list[str]
    # IDENTITY digest -> number of capture runs the fact was observed in.
    # Identity, not the full fact digest: the same flow seen with a different
    # witness in another run is the same fact for counting purposes.
    observation_counts: dict[str, int]
    # accept-chain parent (spec section 5); None for a fresh capture
    parent_digest: str | None = None


class FlowBaseline(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    fact_schema_version: str
    scenarios: list[ScenarioBaseline]
    metadata: BaselineMetadata


def canonical_baseline_bytes(baseline: FlowBaseline) -> bytes:
    data = msgspec.to_builtins(baseline, str_keys=True)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def baseline_digest(baseline: FlowBaseline) -> str:
    """The content address (and accept-chain link target)."""
    return hashlib.sha256(canonical_baseline_bytes(baseline)).hexdigest()


def decode_flow_baseline(data: bytes | str) -> FlowBaseline:
    return msgspec.json.decode(data, type=FlowBaseline, strict=True)


def validate_flow_baseline(baseline: FlowBaseline) -> None:
    """Structural invariants beyond field validation.

    - required is a subset of allowed (intersection cannot exceed union)
    - every required fact was observed in all n_runs
    - every observation count is within [1, n_runs]

    All keyed by identity_digest, never fact_digest: a fact observed with a
    different witness in a different run is the same fact for these purposes.
    """
    n_runs = baseline.metadata.n_runs
    counts = baseline.metadata.observation_counts
    for digest, count in counts.items():
        if not 1 <= count <= n_runs:
            raise ValueError(
                f"observation count for {digest} out of range [1, {n_runs}]: {count}"
            )
    for scenario in baseline.scenarios:
        allowed_digests = {identity_digest(f) for f in scenario.allowed}
        for fact in scenario.required:
            digest = identity_digest(fact)
            if digest not in allowed_digests:
                raise ValueError(
                    f"scenario {scenario.scenario_id!r}: required fact {digest} "
                    "is not in the allowed set"
                )
            if counts.get(digest) != n_runs:
                raise ValueError(
                    f"scenario {scenario.scenario_id!r}: required fact {digest} "
                    f"must be observed in all runs (n_runs={n_runs})"
                )
