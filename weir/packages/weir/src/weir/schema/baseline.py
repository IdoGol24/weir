"""Flow-baseline schema for the version-diff gate (spec section 3).

The serialized baseline is content-addressed (canonical bytes, SHA-256) so it
is the same object family M5 later signs - one format for the CI baseline and
the compliance witness. Required = facts in ALL capture runs (intersection);
allowed = facts in ANY run (union), both held in sorted canonical order so one
set of facts has exactly one content address. Capture happens per scenario, so
`n_runs`, the source traces, and the observation counts live on the scenario
rather than on the baseline as a whole (spec section 3: N is configurable per
scenario, and two scenarios can hold the same flow identity at different flap
rates). The observations section makes the uncataloged-tool rule stateful
(spec section 4): diff flags only tools NOT in that set.
"""

from __future__ import annotations

import hashlib
import json
import re

import msgspec

from weir.schema.flowfact import FlowFact, canonical_fact_bytes, identity_digest

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _require_digest(name: str, value: str) -> None:
    if not _SHA256_HEX.match(value):
        raise ValueError(f"{name} must be a lowercase 64-character sha256 hex digest")


def _check_fact_list(name: str, facts: list[FlowFact]) -> None:
    """Sorted canonical order, one entry per identity. Rejecting rather than
    silently sorting matches FlowFact's own convention: a producer that emits
    an unordered set is broken at the source, and silently repairing it here
    would hide a nondeterministic capture path."""
    keys = [canonical_fact_bytes(f) for f in facts]
    if keys != sorted(keys):
        raise ValueError(f"{name} must be in sorted canonical fact order")
    identities = [identity_digest(f) for f in facts]
    if len(set(identities)) != len(identities):
        raise ValueError(f"{name} must hold at most one fact per identity")


class BaselineObservations(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uncataloged_tools_on_tainted_paths: list[str]

    def __post_init__(self) -> None:
        tools = self.uncataloged_tools_on_tainted_paths
        if tools != sorted(set(tools)):
            raise ValueError(
                "uncataloged_tools_on_tainted_paths must be sorted and duplicate-free"
            )


class ScenarioBaseline(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """One scenario's capture: its N runs, the facts they yielded, and the
    uncataloged tools seen while capturing them."""

    scenario_id: str
    n_runs: int
    required: list[FlowFact]
    allowed: list[FlowFact]
    observations: BaselineObservations
    # IDENTITY digest -> number of capture runs the fact was observed in.
    # Identity, not the full fact digest: the same flow seen with a different
    # witness in another run merges to one fact, and its count must still
    # reach n_runs.
    observation_counts: dict[str, int]
    source_trace_digests: list[str]

    def __post_init__(self) -> None:
        if self.n_runs < 1:
            raise ValueError("n_runs must be at least 1")
        _check_fact_list("required", self.required)
        _check_fact_list("allowed", self.allowed)
        if self.source_trace_digests != sorted(self.source_trace_digests):
            raise ValueError("source_trace_digests must be sorted")
        for digest in self.source_trace_digests:
            _require_digest("source_trace_digests entry", digest)
        for digest in self.observation_counts:
            _require_digest("observation_counts key", digest)


class BaselineMetadata(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Baseline-wide facts: the tooling that produced it, the skew-policy
    input, and the accept-chain link. Per-scenario capture facts live on
    ScenarioBaseline."""

    weir_version: str
    catalog_digest: str
    # accept-chain parent (spec section 5); None for a fresh capture
    parent_digest: str | None = None

    def __post_init__(self) -> None:
        _require_digest("catalog_digest", self.catalog_digest)
        if self.parent_digest is not None:
            _require_digest("parent_digest", self.parent_digest)


class FlowBaseline(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    fact_schema_version: str
    scenarios: list[ScenarioBaseline]
    metadata: BaselineMetadata

    def __post_init__(self) -> None:
        ids = [s.scenario_id for s in self.scenarios]
        if ids != sorted(ids):
            raise ValueError("scenarios must be sorted by scenario_id")
        if len(set(ids)) != len(ids):
            raise ValueError("scenario_id must be unique within a baseline")


def canonical_baseline_bytes(baseline: FlowBaseline) -> bytes:
    data = msgspec.to_builtins(baseline, str_keys=True)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def baseline_digest(baseline: FlowBaseline) -> str:
    """The content address (and accept-chain link target)."""
    return hashlib.sha256(canonical_baseline_bytes(baseline)).hexdigest()


def validate_flow_baseline(baseline: FlowBaseline) -> None:
    """Cross-field invariants. Field-level ones live in __post_init__ so they
    cannot be bypassed at all; these need more than one field to check.

    - observation counts cover exactly the allowed identities, each in [1, n_runs]
    - every required fact appears in allowed as the SAME fact, byte for byte
      (spec 2.3's merge rules yield exactly one fact per identity, so identity
      containment alone would let required and allowed make contradictory
      attribute claims about one flow)
    - every required fact was observed in all of that scenario's n_runs
    """
    for scenario in baseline.scenarios:
        counts = scenario.observation_counts
        n_runs = scenario.n_runs
        allowed_identities = {identity_digest(f) for f in scenario.allowed}
        allowed_objects = {canonical_fact_bytes(f) for f in scenario.allowed}
        if set(counts) != allowed_identities:
            raise ValueError(
                f"scenario {scenario.scenario_id!r}: observation_counts must cover "
                "exactly the allowed identities"
            )
        for digest, count in counts.items():
            if not 1 <= count <= n_runs:
                raise ValueError(
                    f"scenario {scenario.scenario_id!r}: observation count for "
                    f"{digest} out of range [1, {n_runs}]: {count}"
                )
        for fact in scenario.required:
            if canonical_fact_bytes(fact) not in allowed_objects:
                raise ValueError(
                    f"scenario {scenario.scenario_id!r}: required fact "
                    f"{identity_digest(fact)} is not in the allowed set"
                )
            if counts.get(identity_digest(fact)) != n_runs:
                raise ValueError(
                    f"scenario {scenario.scenario_id!r}: required fact "
                    f"{identity_digest(fact)} must be observed in all runs "
                    f"(n_runs={n_runs})"
                )


def decode_flow_baseline(data: bytes | str) -> FlowBaseline:
    """Decode, validate, then return. Validation is NOT optional on the read
    path: baselines are read back from committed files by the future diff
    engine, and a structurally invalid one reaching a compare is the same
    class of outcome as a malformed one (input error), so there is no reason
    to let it through."""
    baseline = msgspec.json.decode(data, type=FlowBaseline, strict=True)
    validate_flow_baseline(baseline)
    return baseline
