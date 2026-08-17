"""Section 6 drift check for the diffspec corpus: regenerate everything from
seeds and by-construction ground truth, and fail on any byte difference. Also
fails on stray files, so the committed corpus is exactly what render_all
produces and nothing else.

This TEST may import weir.catalog - tests sit outside the tracegen import
contract that binds the package source."""

import importlib.metadata
from pathlib import Path

from weir.catalog import DEFAULT_CATALOG
from weir.catalog.digest import catalog_digest
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.baseline import decode_flow_baseline
from weir.schema.trace import CanonicalTrace, ToolCallPayload, decode_canonical_trace
from weir.taint import build_tainted_graph
from weir_tracegen.diffspec_fixtures import render_all

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"

# The exact committed corpus (M2): pinning the literal set of relative paths,
# not just per-directory counts, so a fixture that lands in the wrong
# directory (or a family that silently loses one file while another silently
# gains one) cannot pass by coincidence.
_EXPECTED_FILES = frozenset(
    {
        "diffspec/runs/injection-exfil.run0.json",
        "diffspec/runs/injection-exfil.run1.json",
        "diffspec/runs/injection-exfil.run2.json",
        "diffspec/runs/injection-exfil.run3.json",
        "diffspec/runs/injection-exfil.run4.json",
        "diffspec/variants/injection-exfil-context-only.json",
        "diffspec/variants/injection-exfil-external.json",
        "diffspec/variants/injection-exfil-uncataloged.json",
        "diffspec/variants/injection-exfil-webhook.json",
        "diffspec/degraded/injection-exfil.degraded.json",
        "diffspec/baselines/injection-exfil.baseline.json",
        "diffspec/baselines/injection-exfil.with-observations.baseline.json",
        "diffspec/baselines/injection-exfil-context-only.baseline.json",
        "diffspec/baselines/injection-exfil.skew.baseline.json",
        "diffspec/expected/too-strict-variance.json",
        "diffspec/expected/too-loose-escalation.json",
        "diffspec/expected/too-loose-destination.json",
        "diffspec/expected/too-loose-new-pair.json",
        "diffspec/expected/evidentiary-degraded.json",
        "diffspec/expected/gate-skew.json",
        "diffspec/expected/uncataloged-new.json",
        "diffspec/expected/uncataloged-preexisting.json",
    }
)


def _rendered() -> dict[str, str]:
    return render_all(
        catalog_digest=catalog_digest(DEFAULT_CATALOG),
        weir_version=importlib.metadata.version("weir-scan"),
    )


def _uncataloged_tools_on_tainted_path(trace: CanonicalTrace) -> list[str]:
    """FIX C1b: derive, rather than restate, which tool_call names a baseline's
    `observations.uncataloged_tools_on_tainted_paths` must list - run the real
    pipeline (build_session_graph -> label_graph -> build_tainted_graph) and
    collect every tool_call node that (a) is reachable in some source's
    context-taint set and (b) is not one of DEFAULT_CATALOG's own sinks."""
    graph = build_session_graph(trace)
    labeled = label_graph(graph, DEFAULT_CATALOG)
    tainted = build_tainted_graph(labeled, DEFAULT_CATALOG)
    sink_tool_names = {sink.tool_name for sink in DEFAULT_CATALOG.sinks}
    tainted_indices: set[int] = set()
    for reachable in tainted.context_tainted.values():
        tainted_indices.update(reachable)
    tools = {
        node.payload.tool_name
        for index, node in enumerate(trace.nodes)
        if isinstance(node.payload, ToolCallPayload)
        and index in tainted_indices
        and node.payload.tool_name not in sink_tool_names
    }
    return sorted(tools)


def test_diffspec_corpus_matches_committed() -> None:
    for rel, content in _rendered().items():
        committed = (_FIXTURES_DIR / rel).read_text(encoding="utf-8")
        assert content == committed, (
            f"fixtures/{rel} is stale - regenerate via diffspec_fixtures.write_all; "
            "fixtures are generated, never hand-edited (section 6)"
        )


def test_no_stray_files_in_diffspec_dir() -> None:
    expected = {(_FIXTURES_DIR / rel).resolve() for rel in _rendered()}
    actual = {path.resolve() for path in (_FIXTURES_DIR / "diffspec").rglob("*.json")}
    assert actual == expected


def test_corpus_covers_all_four_families() -> None:
    assert set(_rendered()) == _EXPECTED_FILES


def test_run_fixture_observations_match_derivation() -> None:
    # FIX C1b: the plain baseline's stated observations must equal what the
    # real pipeline derives from each of the five COMMITTED run fixtures -
    # not merely be internally consistent with what diffspec_fixtures.py
    # asserts about itself.
    baseline = decode_flow_baseline(
        (_FIXTURES_DIR / "diffspec/baselines/injection-exfil.baseline.json").read_bytes()
    )
    expected = baseline.scenarios[0].observations.uncataloged_tools_on_tainted_paths
    for i in range(5):
        rel = f"diffspec/runs/injection-exfil.run{i}.json"
        trace = decode_canonical_trace((_FIXTURES_DIR / rel).read_bytes())
        assert _uncataloged_tools_on_tainted_path(trace) == expected


def test_uncataloged_variant_observations_match_derivation() -> None:
    # The with-observations baseline's list must equal what the pipeline
    # derives from the committed uncataloged-variant trace - the fixture that
    # exercises "already known, not new" (uncataloged-preexisting) depends on
    # this being exactly right, not merely plausible.
    baseline = decode_flow_baseline(
        (
            _FIXTURES_DIR / "diffspec/baselines/injection-exfil.with-observations.baseline.json"
        ).read_bytes()
    )
    expected = baseline.scenarios[0].observations.uncataloged_tools_on_tainted_paths
    trace = decode_canonical_trace(
        (_FIXTURES_DIR / "diffspec/variants/injection-exfil-uncataloged.json").read_bytes()
    )
    assert _uncataloged_tools_on_tainted_path(trace) == expected
