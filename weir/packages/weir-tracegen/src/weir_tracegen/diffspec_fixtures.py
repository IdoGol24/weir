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
from weir_tracegen.diffspec_ground_truth import SKEW_CATALOG_DIGEST, red_baseline
from weir_tracegen.emitter import emit, emit_degraded, emit_run
from weir_tracegen.fixture_io import render_fixture_json

_SEED = 1
_N_RUNS = 5

# The send_email tool_call's node index in the injection-exfil trace. Degrading
# it strips the sink's args, which is what drops evidentiary coverage below the
# floor while leaving the underlying behavior identical.
_SINK_NODE_INDEX = 6

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

    # Family 3 candidate: same behavior, degraded telemetry at the sink.
    files["diffspec/degraded/injection-exfil.degraded.json"] = render_fixture_json(
        emit_degraded(
            "injection-exfil", seed=_SEED, degrade_tool_call_indices=[_SINK_NODE_INDEX]
        )
    )

    def _baseline(
        *,
        catalog: str,
        mode: TaintMode = TaintMode.VERBATIM,
        scenario_id: str = "injection-exfil",
        uncataloged_tools: list[str] | None = None,
    ) -> FlowBaseline:
        return red_baseline(
            catalog_digest=catalog,
            weir_version=weir_version,
            source_trace_digests=run_digests,
            mode=mode,
            scenario_id=scenario_id,
            uncataloged_tools=uncataloged_tools,
        )

    files["diffspec/baselines/injection-exfil.baseline.json"] = _render_pretty(
        _baseline(catalog=catalog_digest)
    )
    files["diffspec/baselines/injection-exfil.with-observations.baseline.json"] = (
        _render_pretty(
            _baseline(catalog=catalog_digest, uncataloged_tools=["translate_text"])
        )
    )
    files["diffspec/baselines/injection-exfil-context-only.baseline.json"] = _render_pretty(
        _baseline(
            catalog=catalog_digest,
            mode=TaintMode.CONTEXT,
            scenario_id="injection-exfil-context-only",
        )
    )
    files["diffspec/baselines/injection-exfil.skew.baseline.json"] = _render_pretty(
        _baseline(catalog=SKEW_CATALOG_DIGEST)
    )

    baseline = "diffspec/baselines/injection-exfil.baseline.json"
    expectations: dict[str, ExpectedDiff] = {
        "too-strict-variance": ExpectedDiff(
            baseline_fixture=baseline,
            candidate_fixtures=run_files,
            expected_exit_code=EXIT_PASS,
            deltas=[],
        ),
        "too-loose-escalation": ExpectedDiff(
            baseline_fixture="diffspec/baselines/injection-exfil-context-only.baseline.json",
            candidate_fixtures=["injection-exfil.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[_behavioral(DeltaKind.MODE_ESCALATION)],
        ),
        "too-loose-destination": ExpectedDiff(
            baseline_fixture=baseline,
            candidate_fixtures=["diffspec/variants/injection-exfil-external.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[
                _behavioral(
                    DeltaKind.NEW_FACT_UNGUARDED,
                    "replaces previous known-contact flow (pairing annotation)",
                )
            ],
        ),
        "too-loose-new-pair": ExpectedDiff(
            baseline_fixture=baseline,
            candidate_fixtures=["diffspec/variants/injection-exfil-webhook.json"],
            expected_exit_code=EXIT_FAIL_DELTA,
            deltas=[_behavioral(DeltaKind.NEW_FACT_UNGUARDED)],
        ),
        "evidentiary-degraded": ExpectedDiff(
            baseline_fixture=baseline,
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
