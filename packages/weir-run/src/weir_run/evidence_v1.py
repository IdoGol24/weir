"""weir-verify-evidence/1, the evidence record weir-run 0.3.0 wrote, and the
parts of it weir-verify-evidence/2 keeps (docs/verify.md). `weir-run
predicate` still loads a v1 record; its JSON Schema artifact is generated
from `Evidence` here and never changes."""

from __future__ import annotations

from typing import Annotated, Literal, get_args

import msgspec

SCHEMA = "weir-verify-evidence/1"
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
ManifestDigest = Annotated[str, msgspec.Meta(pattern="^[0-9a-f]{64}$")]


class Strict(msgspec.Struct, forbid_unknown_fields=True, kw_only=True):
    pass


class Tool(Strict):
    name: Name
    version: Annotated[str, msgspec.Meta(pattern="^[0-9][0-9A-Za-z.+-]{0,63}$")]


class Placement(Strict):
    id: Annotated[str, msgspec.Meta(pattern="^env\\.[A-Z_][A-Z0-9_]{0,63}$")]
    state: Literal["leaked", "exercised", "not_exercised"]
    hits: Count


class Sink(Strict):
    name: SinkName
    verdict: Literal["clean", "leak", "not_reached"]
    received: Count
    hits: Count


class Incomplete(Strict):
    reason: Reason
    count: Annotated[int, msgspec.Meta(ge=1)]


class Network(Strict):
    isolated: bool
    direct_attempts: Count


class Evidence(Strict):
    schema: Literal["weir-verify-evidence/1"]
    target: Name
    tools: list[Tool]
    manifest_sha256: ManifestDigest
    image_digest: Digest | None
    verdict: Verdict
    placements: list[Placement]
    sinks: list[Sink]
    incomplete: list[Incomplete]
    network: Network
