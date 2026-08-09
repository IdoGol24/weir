"""By-construction ground truth for the diffspec fixture corpus.

The L9 pattern: tracegen knows the red scenario plants exactly one flow
(financial_account_identifier -> send_email, body role, known-contact
destination, verbatim mode, full evidence) because it planted it. No engine
derivation happens here. When the diff engine lands, its gold gate compares
derived facts against these stated ones.

Import contract: `weir.schema` ONLY. The catalog digest and weir version are
parameters, computed by the caller, so this module never reaches into
`weir.catalog`.

The witness node ids below are coupled to the native emitter's id scheme
(`native-{scenario}-{index}`). That coupling is deliberate and is pinned by
the byte-identity constraint on the committed fixtures, but it does mean any
future change to the emitter's id scheme is a corpus regeneration.
"""

from __future__ import annotations

from weir.schema.baseline import (
    BaselineMetadata,
    BaselineObservations,
    FlowBaseline,
    ScenarioBaseline,
)
from weir.schema.flowfact import (
    FACT_SCHEMA_VERSION,
    EvidenceConfidence,
    FlowFact,
    TaintMode,
    identity_digest,
)

# Valid in SHAPE but a value no real catalog digest can take, so a compare
# against it is refused as skew (spec section 4) rather than rejected as a
# malformed baseline.
SKEW_CATALOG_DIGEST = "0" * 64

# The red scenario's witness: the injected tool_result at index 2 through to
# the send_email sink at index 6.
_WITNESS = [f"native-injection-exfil-{i}" for i in range(2, 7)]


def red_fact(*, mode: TaintMode = TaintMode.VERBATIM) -> FlowFact:
    return FlowFact(
        source_class="financial_account_identifier",
        sink_tool_name="send_email",
        destination_class="known-contact",
        guards_on_path=[],
        mode=mode,
        evidence_confidence=EvidenceConfidence.FULL,
        sink_arg_roles=["body"],
        witness=list(_WITNESS),
    )


def red_baseline(
    *,
    catalog_digest: str,
    weir_version: str,
    source_trace_digests: list[str],
    n_runs: int = 5,
    mode: TaintMode = TaintMode.VERBATIM,
    scenario_id: str = "injection-exfil",
    uncataloged_tools: list[str] | None = None,
) -> FlowBaseline:
    fact = red_fact(mode=mode)
    return FlowBaseline(
        fact_schema_version=FACT_SCHEMA_VERSION,
        scenarios=[
            ScenarioBaseline(
                scenario_id=scenario_id,
                n_runs=n_runs,
                required=[fact],
                allowed=[fact],
                observations=BaselineObservations(
                    uncataloged_tools_on_tainted_paths=sorted(uncataloged_tools or [])
                ),
                observation_counts={identity_digest(fact): n_runs},
                source_trace_digests=sorted(source_trace_digests),
            )
        ],
        metadata=BaselineMetadata(
            weir_version=weir_version,
            catalog_digest=catalog_digest,
        ),
    )
