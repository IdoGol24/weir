"""The evidence record of a `weir-run verify` run and the in-toto
test-result predicate made from it. verify writes only fixed names,
verdicts, counts, digests and versions, never a value; a name field is
pattern-checked, not a list, so the schema alone does not prove it holds
no value (docs/verify.md)."""

from __future__ import annotations

import hashlib
from typing import Annotated, Any, Literal, get_args

import msgspec

SCHEMA = "weir-verify-evidence/1"
PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
# In the order the schema lists them, which is the order of a record's sinks.
SinkName = Literal["console", "model", "outbound", "telemetry"]
# The judge's (docs/canary.md, "Coverage states").
JudgeReason = Literal[
    "required_not_exercised",
    "flow_not_ok",
    "unexpected_credential",
    "not_scanned",
    "unparsed_record",
    "empty_capture",
    "network_not_isolated",
    "direct_connection",
]
JUDGE_REASONS: frozenset[str] = frozenset(get_args(JudgeReason))
Reason = Literal[
    JudgeReason,
    # verify's own; judge_other stands for any judge reason not listed above
    "judge_other",
    "target_missing",
    "sink_not_reached",
    "judge_not_clean",
    "value_fragment",
]
SINKS: tuple[SinkName, ...] = get_args(SinkName)
Verdict = Literal["clean", "leak", "incomplete"]
Count = Annotated[int, msgspec.Meta(ge=0)]
Digest = Annotated[str, msgspec.Meta(pattern="^sha256:[0-9a-f]{64}$")]
Name = Annotated[str, msgspec.Meta(pattern="^[a-z0-9][a-z0-9.-]{0,39}$")]


class _Struct(msgspec.Struct, forbid_unknown_fields=True, kw_only=True):
    pass


class Tool(_Struct):
    name: Name
    version: Annotated[str, msgspec.Meta(pattern="^[0-9][0-9A-Za-z.+-]{0,63}$")]


class Placement(_Struct):
    id: Annotated[str, msgspec.Meta(pattern="^env\\.[A-Z_][A-Z0-9_]{0,63}$")]
    state: Literal["leaked", "exercised", "not_exercised"]
    hits: Count


class Sink(_Struct):
    name: SinkName
    verdict: Literal["clean", "leak", "not_reached"]
    received: Count
    hits: Count


class Incomplete(_Struct):
    reason: Reason
    count: Annotated[int, msgspec.Meta(ge=1)]


class Network(_Struct):
    isolated: bool
    direct_attempts: Count


class Evidence(_Struct):
    schema: Literal["weir-verify-evidence/1"]
    target: Name
    tools: list[Tool]
    manifest_sha256: Annotated[str, msgspec.Meta(pattern="^[0-9a-f]{64}$")]
    image_digest: Digest | None
    verdict: Verdict
    placements: list[Placement]
    sinks: list[Sink]
    incomplete: list[Incomplete]
    network: Network


class EvidenceError(Exception):
    """A record that breaks the schema or contradicts itself."""


def sink_verdict(received: int, hits: int) -> str:
    return "leak" if hits else "clean" if received else "not_reached"


def derive(e: Evidence) -> Verdict:
    """The verdict a record's own fields support. Clean needs every sink
    reached and clean, the placement exercised, isolation, no direct
    connection attempt and no reason."""
    if any(s.verdict == "leak" for s in e.sinks) or any(p.state == "leaked" for p in e.placements):
        return "leak"
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


def load(data: bytes) -> Evidence:
    """A record, strictly: the schema, sink verdicts that match their counts,
    and a verdict its fields support. Anything else raises EvidenceError."""
    try:
        e = msgspec.json.decode(data, type=Evidence)
    except msgspec.DecodeError:  # ValidationError included
        raise EvidenceError from None
    if any(s.verdict != sink_verdict(s.received, s.hits) for s in e.sinks) or (
        e.verdict != derive(e)
    ):
        raise EvidenceError
    return e


def predicate(data: bytes, url: str | None = None) -> dict[str, Any]:
    """The test-result predicate for a record's bytes: PASSED only for
    clean, FAILED for leak and incomplete, never WARNED."""
    e = load(data)
    passed = [f"sink:{s.name}" for s in e.sinks if s.verdict == "clean"]
    failed = [f"sink:{s.name}" for s in e.sinks if s.verdict != "clean"]
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
