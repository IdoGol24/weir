"""Renders the complete diffspec fixture corpus (spec section 6, all four
families) as a pure mapping of repo-relative path -> file content. Shared by
the one-off generation command and the CI drift test so the two can never
diverge, the same discipline as fixture_io.render_fixture_json.

Import contract: weir.schema only. `catalog_digest` and `weir_version` are
parameters supplied by the caller, so this module never reaches into
weir.catalog.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import msgspec

from weir.schema.baseline import FlowBaseline
from weir.schema.delta import (
    EXIT_FAIL_DELTA,
    EXIT_INVALID_COMPARE,
    EXIT_PASS,
    Attribution,
    DeltaKind,
    ExpectedDelta,
    ExpectedDiff,
    Severity,
)
from weir.schema.flowfact import TaintMode
from weir.schema.trace import ToolCallPayload
from weir_tracegen.diffspec_ground_truth import SKEW_CATALOG_DIGEST, red_baseline
from weir_tracegen.emitter import emit, emit_degraded, emit_run
from weir_tracegen.fixture_io import render_fixture_json

_SEED = 1
_N_RUNS = 5

# The send_email tool_call's node index in the injection-exfil trace. Degrading
# it strips the sink's args, which is what drops evidentiary coverage below the
# floor while leaving the underlying behavior identical. Below the floor: this
# fixture measures 6666 bp of evidentiary coverage against 10000 bp for the
# plain red trace, so whoever wires up the R3.6 threshold gate must pick a
# floor above 6666 bp for this fixture to mean what it says - nothing else
# records that constraint.
_SINK_NODE_INDEX = 6

# lookup_customer_contact sits on the tainted path (node 4, reachable from the
# injected tool_result at node 2 via context taint) in every injection-exfil
# variant, and it is not one of DEFAULT_CATALOG's two sinks (send_email,
# post_to_webhook). A truthful capture therefore records it as an uncataloged
# tool on every baseline - it is not a fixture-specific addition, it is
# ambient. Sorted, as BaselineObservations.__post_init__ requires.
_BASE_UNCATALOGED = ["lookup_customer_contact"]

_VARIANTS = (
    "injection-exfil-context-only",
    "injection-exfil-external",
    "injection-exfil-uncataloged",
    "injection-exfil-webhook",
)


def _render_pretty(obj: object) -> str:
    return json.dumps(msgspec.to_builtins(obj, str_keys=True), indent=2) + "\n"


def _behavioral(kind: DeltaKind, note: str | None = None) -> ExpectedDelta:
    return ExpectedDelta(
        kind=kind,
        severity=Severity.FAIL,
        attribution=Attribution.BEHAVIORAL,
        note=note,
    )


def _insufficient(kind: DeltaKind, note: str) -> ExpectedDelta:
    """An exit-3 cause. Naming the cause is what stops the degraded-telemetry
    family and the skew family from being the same assertion."""
    return ExpectedDelta(
        kind=kind,
        severity=Severity.INSUFFICIENT_EVIDENCE,
        attribution=Attribution.EVIDENTIARY,
        note=note,
    )


def render_all(*, catalog_digest: str, weir_version: str) -> dict[str, str]:
    files: dict[str, str] = {}

    # Family 1 (too-strict): N benign-variance runs of the red scenario.
    run_files: list[str] = []
    for run in range(_N_RUNS):
        rel = f"diffspec/runs/injection-exfil.run{run}.json"
        files[rel] = render_fixture_json(emit_run("injection-exfil", seed=_SEED, run=run))
        run_files.append(rel)
    run_digests = sorted(
        hashlib.sha256(files[rel].encode("utf-8")).hexdigest() for rel in run_files
    )

    # Families 2 and 4 candidates: the four variant scenarios.
    for name in _VARIANTS:
        files[f"diffspec/variants/{name}.json"] = render_fixture_json(emit(name, seed=_SEED))

    # M1 guard: `_degrade_node` only checks that the target is A tool_call, not
    # that it is THE right one. If the scenario's shape ever drifts and index 6
    # slides onto a different tool_call (e.g. lookup_customer_contact), this
    # fails loudly here instead of silently degrading the wrong node while the
    # drift test's "regenerate the corpus" message points the fixer the wrong
    # way.
    _plain_red_trace = emit("injection-exfil", seed=_SEED)
    _sink_node = _plain_red_trace.nodes[_SINK_NODE_INDEX]
    if not (
        isinstance(_sink_node.payload, ToolCallPayload)
        and _sink_node.payload.tool_name == "send_email"
    ):
        raise ValueError(
            f"expected node {_SINK_NODE_INDEX} of injection-exfil to be the "
            "send_email tool_call sink; the scenario's shape has drifted"
        )

    # Family 3 candidate: same behavior, degraded telemetry at the sink.
    files["diffspec/degraded/injection-exfil.degraded.json"] = render_fixture_json(
        emit_degraded(
            "injection-exfil", seed=_SEED, degrade_tool_call_indices=[_SINK_NODE_INDEX]
        )
    )

    def _baseline(
        *,
        catalog: str,
        uncataloged_tools: list[str],
        mode: TaintMode = TaintMode.VERBATIM,
    ) -> FlowBaseline:
        return red_baseline(
            catalog_digest=catalog,
            weir_version=weir_version,
            source_trace_digests=run_digests,
            mode=mode,
            uncataloged_tools=uncataloged_tools,
        )

    files["diffspec/baselines/injection-exfil.baseline.json"] = _render_pretty(
        _baseline(catalog=catalog_digest, uncataloged_tools=_BASE_UNCATALOGED)
    )
    files["diffspec/baselines/injection-exfil.with-observations.baseline.json"] = (
        _render_pretty(
            _baseline(
                catalog=catalog_digest,
                uncataloged_tools=sorted([*_BASE_UNCATALOGED, "translate_text"]),
            )
        )
    )

    # The context-only baseline must be captured from the context-only trace
    # ITSELF, not restated from the plain red trace's runs: those five runs
    # demonstrably produce `verbatim`, so citing them as the provenance for a
    # `context` claim would be false, and their `native-injection-exfil-*`
    # witness refs do not even resolve on this trace. N=1 here is deliberate
    # and honest: this baseline was captured from the one committed
    # context-only run, and n_runs=1 says exactly that - it is not a stand-in
    # for the five-run dial. scenario_id stays "injection-exfil": a version
    # diff compares the SAME scenario across two agent versions, and this
    # trace is version 1's (context-only) behavior of injection-exfil, not a
    # different scenario. The filename stays distinct so the two baselines
    # remain two separate fixtures.
    context_only_digest = hashlib.sha256(
        files["diffspec/variants/injection-exfil-context-only.json"].encode("utf-8")
    ).hexdigest()
    files["diffspec/baselines/injection-exfil-context-only.baseline.json"] = _render_pretty(
        red_baseline(
            catalog_digest=catalog_digest,
            weir_version=weir_version,
            source_trace_digests=[context_only_digest],
            n_runs=1,
            mode=TaintMode.CONTEXT,
            scenario_id="injection-exfil",
            uncataloged_tools=_BASE_UNCATALOGED,
            witness_prefix="native-injection-exfil-context-only",
        )
    )

    files["diffspec/baselines/injection-exfil.skew.baseline.json"] = _render_pretty(
        _baseline(catalog=SKEW_CATALOG_DIGEST, uncataloged_tools=_BASE_UNCATALOGED)
    )

    baseline = "diffspec/baselines/injection-exfil.baseline.json"
    _scenario = "injection-exfil"
    expectations: dict[str, ExpectedDiff] = {
        "too-strict-variance": ExpectedDiff(
            baseline_fixture=baseline,
            scenario_id=_scenario,
            candidate_fixtures=run_files,
            expected_exit_code=EXIT_PASS,
            deltas=[],
        ),
        "too-loose-escalation": ExpectedDiff(
            baseline_fixture="diffspec/baselines/injection-exfil-context-only.baseline.json",
            scenario_id=_scenario,
            candidate_fixtures=["injection-exfil.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[_behavioral(DeltaKind.MODE_ESCALATION)],
        ),
        "too-loose-destination": ExpectedDiff(
            baseline_fixture=baseline,
            scenario_id=_scenario,
            candidate_fixtures=["diffspec/variants/injection-exfil-external.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[
                _behavioral(
                    DeltaKind.NEW_FACT_UNGUARDED,
                    "replaces previous known-contact flow (pairing annotation)",
                ),
                # The destination change both mints a new identity AND retires
                # the old one. Guard pairing does not pair them (the guard-free
                # projection includes destination_class, which differs), and
                # destination pairing only annotates - it never consumes. So
                # the retired baseline fact is genuinely missing, not merely
                # superseded, and a correct engine reports both deltas.
                ExpectedDelta(
                    kind=DeltaKind.REQUIRED_FACT_MISSING,
                    severity=Severity.WARN,
                    attribution=Attribution.BEHAVIORAL,
                    note="the known-contact flow it replaces is gone",
                ),
            ],
        ),
        "too-loose-new-pair": ExpectedDiff(
            baseline_fixture=baseline,
            scenario_id=_scenario,
            candidate_fixtures=["diffspec/variants/injection-exfil-webhook.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[_behavioral(DeltaKind.NEW_FACT_UNGUARDED)],
        ),
        "evidentiary-degraded": ExpectedDiff(
            baseline_fixture=baseline,
            scenario_id=_scenario,
            candidate_fixtures=["diffspec/degraded/injection-exfil.degraded.json"],
            expected_exit_code=EXIT_INVALID_COMPARE,
            deltas=[
                _insufficient(
                    DeltaKind.COVERAGE_BELOW_FLOOR,
                    "the sink's arguments were not captured, so the flow could "
                    "not be compared either way",
                )
            ],
        ),
        "gate-skew": ExpectedDiff(
            baseline_fixture="diffspec/baselines/injection-exfil.skew.baseline.json",
            scenario_id=_scenario,
            candidate_fixtures=["injection-exfil.json"],
            expected_exit_code=EXIT_INVALID_COMPARE,
            deltas=[
                _insufficient(
                    DeltaKind.COMPARE_SKEW,
                    "baseline catalog digest does not match the current catalog: "
                    "re-capture the baseline",
                )
            ],
        ),
        "uncataloged-new": ExpectedDiff(
            baseline_fixture=baseline,
            scenario_id=_scenario,
            candidate_fixtures=["diffspec/variants/injection-exfil-uncataloged.json"],
            expected_exit_code=EXIT_PASS,
            deltas=[
                ExpectedDelta(
                    kind=DeltaKind.NEW_UNCATALOGED_TOOL,
                    severity=Severity.WARN,
                    attribution=Attribution.EVIDENTIARY,
                    note="register or classify this tool: translate_text",
                )
            ],
        ),
        "uncataloged-preexisting": ExpectedDiff(
            baseline_fixture=(
                "diffspec/baselines/injection-exfil.with-observations.baseline.json"
            ),
            scenario_id=_scenario,
            candidate_fixtures=["diffspec/variants/injection-exfil-uncataloged.json"],
            expected_exit_code=EXIT_PASS,
            deltas=[],
        ),
    }
    for name, diff in expectations.items():
        files[f"diffspec/expected/{name}.json"] = _render_pretty(diff)

    return files


def write_all(fixtures_dir: Path, *, catalog_digest: str, weir_version: str) -> None:
    """`fixtures_dir` is the repo's `weir/fixtures/` directory; render_all's
    keys are relative to it and already start with `diffspec/`.

    Writes with an explicit LF newline so the committed bytes do not depend on
    the platform: the drift test reads back in universal-newline mode, and the
    per-run digests are taken over the in-memory LF strings."""
    for rel, content in render_all(
        catalog_digest=catalog_digest, weir_version=weir_version
    ).items():
        path = fixtures_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
