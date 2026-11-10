"""The evidence record of a `weir-run verify` run and the in-toto
test-result predicate made from it. verify writes only fixed names,
verdicts, counts, digests and versions, never a value; a name field is
pattern-checked, not a list, so the schema alone does not prove it holds
no value (docs/verify.md)."""

from __future__ import annotations

import hashlib
from typing import Annotated, Any, Literal

import msgspec

from weir_run import evidence_v1
from weir_run.evidence_v1 import JUDGE_REASONS as JUDGE_REASONS
from weir_run.evidence_v1 import SINKS as SINKS
from weir_run.evidence_v1 import (
    Digest,
    ManifestDigest,
    Name,
    Network,
    Placement,
    Sink,
    Strict,
    Tool,
)
from weir_run.evidence_v1 import Incomplete as Incomplete

SCHEMA = "weir-verify-evidence/2"
PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
# What fails a run (docs/canary.md, "Coverage states"), and why a tool call
# was unmediated (docs/canary.md, "Tool calls").
FindingType = Literal["leak", "unmediated-tool-call"]
FindingReason = Literal["not_issued", "tool_mismatch"]
Verdict = Literal["clean", "leak", "unmediated-tool-call", "incomplete"]


class Finding(Strict):
    """One finding type, with its reason for an unmediated tool call (null
    for a leak), and how many: hits for a leak, tool calls otherwise."""

    type: FindingType
    reason: FindingReason | None
    count: Annotated[int, msgspec.Meta(ge=1)]


class Evidence(Strict):
    schema: Literal["weir-verify-evidence/2"]
    target: Name
    tools: list[Tool]
    manifest_sha256: ManifestDigest
    image_digest: Digest | None
    verdict: Verdict
    findings: list[Finding]
    placements: list[Placement]
    sinks: list[Sink]
    incomplete: list[Incomplete]
    network: Network


# A record `weir-run predicate` loads: the one verify writes, or one
# weir-run 0.3.0 wrote.
type Record = Evidence | evidence_v1.Evidence


class _Schema(msgspec.Struct):
    schema: str


class EvidenceError(Exception):
    """A record that breaks the schema or contradicts itself."""


def sink_verdict(received: int, hits: int) -> str:
    return "leak" if hits else "clean" if received else "not_reached"


def _finding_key(f: Finding) -> tuple[str, str]:
    return (f.type, f.reason or "")


def findings_supported(e: Evidence) -> bool:
    """Findings sorted and unique by type and reason; a leak finding, with
    no reason, exactly when the sinks hold hits, counting them; an
    unmediated-tool-call finding always with its reason."""
    keys = [_finding_key(f) for f in e.findings]
    if keys != sorted(set(keys)):
        return False
    hits = sum(s.hits for s in e.sinks)
    leaks = [f for f in e.findings if f.type == "leak"]
    if [(f.reason, f.count) for f in leaks] != ([(None, hits)] if hits else []):
        return False
    return all(f.reason is not None for f in e.findings if f.type == "unmediated-tool-call")


def derive(e: Record) -> Verdict:
    """The verdict a record's own fields support. Any finding fails it, a
    leak first; clean needs every sink reached and clean, the placement
    exercised, isolation, no direct connection attempt and no reason. A
    v1 record has no findings, so it is clean, leak or incomplete."""
    if any(s.verdict == "leak" for s in e.sinks) or any(p.state == "leaked" for p in e.placements):
        return "leak"
    findings = e.findings if isinstance(e, Evidence) else []
    if any(f.type == "unmediated-tool-call" for f in findings):
        return "unmediated-tool-call"
    complete = (
        tuple(s.name for s in e.sinks) == SINKS
        and all(s.verdict == "clean" for s in e.sinks)
        and bool(e.placements)
        and all(p.state == "exercised" for p in e.placements)
        and e.network.isolated
        and e.network.direct_attempts == 0
        and not e.incomplete
    )
    return "clean" if complete else "incomplete"


def encode(e: Evidence) -> bytes:
    """The record's bytes, checked against the schema on the way out."""
    data = msgspec.json.format(msgspec.json.encode(e), indent=2) + b"\n"
    load(data)
    return data


def load(data: bytes) -> Record:
    """A record, strictly, by its own schema version: the schema, sink
    verdicts that match their counts, findings that match the sinks (v2),
    and a verdict its fields support. Anything else raises EvidenceError."""
    try:
        version = msgspec.json.decode(data, type=_Schema).schema
        kind = evidence_v1.Evidence if version == evidence_v1.SCHEMA else Evidence
        e = msgspec.json.decode(data, type=kind)
    except msgspec.DecodeError:  # ValidationError included
        raise EvidenceError from None
    if (
        any(s.verdict != sink_verdict(s.received, s.hits) for s in e.sinks)
        or (isinstance(e, Evidence) and not findings_supported(e))
        or e.verdict != derive(e)
    ):
        raise EvidenceError
    return e


def predicate(data: bytes, url: str | None = None) -> dict[str, Any]:
    """The test-result predicate for a record's bytes: PASSED only for
    clean, FAILED for any finding and for incomplete, never WARNED. A v1
    record makes the predicate weir-run 0.3.0 made for it."""
    e = load(data)
    passed = [f"sink:{s.name}" for s in e.sinks if s.verdict == "clean"]
    failed = [f"sink:{s.name}" for s in e.sinks if s.verdict != "clean"]
    if isinstance(e, Evidence):
        failed += [f"finding:{t}" for t in dict.fromkeys(f.type for f in e.findings)]
    failed += [f"incomplete:{i.reason}" for i in e.incomplete]
    out: dict[str, Any] = {
        "result": "PASSED" if e.verdict == "clean" else "FAILED",
        "configuration": [
            {"name": "weir-verify-manifest", "digest": {"sha256": e.manifest_sha256}},
            {
                "name": "weir-verify-evidence.json",
                "digest": {"sha256": hashlib.sha256(data).hexdigest()},
                "mediaType": "application/json",
                "annotations": msgspec.to_builtins(e),
            },
        ],
        "passedTests": passed,
        "warnedTests": [],
        "failedTests": failed,
    }
    if url is not None:
        out["url"] = url
    return out
