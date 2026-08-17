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
`witness_prefix` names which trace the witness was actually observed on
(`native-injection-exfil` for the run fixtures, `native-injection-exfil-
context-only` for the context-only trace): a baseline's stated witness must
point at the trace it claims to have captured, or the baseline's provenance
is false even though its shape validates.
"""

from __future__ import annotations

from weir.schema.baseline import (
    BaselineMetadata,
    BaselineObservations,
    FlowBaseline,
    ScenarioBaseline,
)
from weir.schema.dialect import NATIVE_SEAM1, profile_digest
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

def red_fact(
    *,
    mode: TaintMode = TaintMode.VERBATIM,
    witness_prefix: str = "native-injection-exfil",
) -> FlowFact:
    """The one flow the red scenario plants: the injected tool_result at index
    2 through to the send_email sink at index 6, on whichever trace
    `witness_prefix` names."""
    return FlowFact(
        source_class="financial_account_identifier",
        sink_tool_name="send_email",
        # `known-contact`, not `internal-domain`: the destination is pinned by
        # the explicit lookup_customer_contact join whose result confirms this
        # address, not by its domain (which happens to be the agent's own).
        # This is the one identity field no code checks yet, so it is the
        # constraint the future destination classifier must satisfy - and a
        # classifier that keyed on domain instead would regenerate the corpus.
        destination_class="known-contact",
        guards_on_path=[],
        mode=mode,
        evidence_confidence=EvidenceConfidence.FULL,
        # In VERBATIM mode this is derived and pinned by a test: the planted
        # value reaches `body` and no other argument. In CONTEXT mode no value
        # reaches the sink at all, so spec section 2.2 defines the roles as
        # the arguments the context taint INFLUENCED - the context-only
        # trace's body text is derived from the injected ticket content. That
        # reading is now normative, not a local choice: it keeps the two modes
        # comparable so a mode escalation reads as an escalation rather than
        # as a role change, and the derivation engine is bound by it.
        sink_arg_roles=["body"],
        witness=[f"{witness_prefix}-{i}" for i in range(2, 7)],
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
    witness_prefix: str = "native-injection-exfil",
) -> FlowBaseline:
    fact = red_fact(mode=mode, witness_prefix=witness_prefix)
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
            dialect_profile_id=NATIVE_SEAM1.profile_id,
            dialect_profile_digest=profile_digest(NATIVE_SEAM1),
        ),
    )
