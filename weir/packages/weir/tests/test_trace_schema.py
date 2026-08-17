import json
from pathlib import Path

import msgspec
import pytest

from weir.schema.trace import (
    CanonicalTrace,
    JoinConfidence,
    JoinRecord,
    NodeKind,
    ToolCallPayload,
    ToolResultPayload,
    TraceMetadata,
    TraceNode,
    canonical_trace_json_schema,
    decode_canonical_trace,
    encode_canonical_trace,
)

_ARTIFACT_PATH = (
    Path(__file__).parents[1] / "schema_artifacts" / "canonical_trace.v1.schema.json"
)


def _sample_trace() -> CanonicalTrace:
    return CanonicalTrace(
        schema_version="1.0.0",
        nodes=[
            TraceNode(
                id="n1",
                kind=NodeKind.TOOL_CALL,
                timestamp="2026-01-01T00:00:00Z",
                actor="agent",
                source_ref="span-1",
                payload=ToolCallPayload(tool_name="send_email", args={"to": "x@y.com"}),
            ),
            TraceNode(
                id="n2",
                kind=NodeKind.TOOL_RESULT,
                timestamp="2026-01-01T00:00:01Z",
                actor="tool",
                source_ref="span-2",
                payload=ToolResultPayload(content="ok"),
            ),
        ],
        joins=[
            JoinRecord(
                tool_call_source_ref="span-1",
                tool_result_source_ref="span-2",
                join_confidence=JoinConfidence.EXPLICIT,
            )
        ],
        metadata=TraceMetadata(adapter_name="native", adapter_version="0.1.0"),
    )


def test_committed_json_schema_artifact_matches_generated() -> None:
    generated = canonical_trace_json_schema()
    committed = json.loads(_ARTIFACT_PATH.read_text())
    assert generated == committed, (
        "packages/weir/schema_artifacts/canonical_trace.v1.schema.json is stale - "
        "regenerate it from weir.schema.trace.canonical_trace_json_schema()"
    )


def test_valid_trace_round_trips() -> None:
    trace = _sample_trace()
    data = encode_canonical_trace(trace)
    assert decode_canonical_trace(data) == trace


def test_rejects_wrong_field_type_with_precise_path() -> None:
    bad = msgspec.json.encode(
        {
            "schema_version": "1.0.0",
            "nodes": [
                {
                    "id": "n1",
                    "kind": "tool_call",
                    "timestamp": "t",
                    "actor": "a",
                    "source_ref": "s1",
                    "payload": {"type": "tool_call", "tool_name": 123, "args": {}},
                }
            ],
            "joins": [],
            "metadata": {"adapter_name": "n", "adapter_version": "1"},
        }
    )
    with pytest.raises(msgspec.ValidationError, match=r"\$\.nodes\[0\]\.payload\.tool_name"):
        decode_canonical_trace(bad)


def test_rejects_unknown_field() -> None:
    bad = msgspec.json.encode(
        {
            "schema_version": "1.0.0",
            "nodes": [],
            "joins": [],
            "metadata": {"adapter_name": "n", "adapter_version": "1"},
            "unexpected_field": True,
        }
    )
    with pytest.raises(msgspec.ValidationError, match="unknown field"):
        decode_canonical_trace(bad)


def test_rejects_malformed_json() -> None:
    with pytest.raises(msgspec.DecodeError):
        decode_canonical_trace(b"not json at all")


def test_content_mined_tier_and_join_source_field() -> None:
    join = JoinRecord(
        tool_call_source_ref="span-1",
        tool_result_source_ref="span-2",
        join_confidence=JoinConfidence.CONTENT_MINED,
        join_source="content:tool_call_id",
    )
    assert join.join_source == "content:tool_call_id"
    # join_source is optional and defaults to None: existing producers are untouched.
    bare = JoinRecord(
        tool_call_source_ref="a", tool_result_source_ref="b",
        join_confidence=JoinConfidence.EXPLICIT,
    )
    assert bare.join_source is None


def test_schema_version_is_1_1_0() -> None:
    from weir.schema.trace import SCHEMA_VERSION
    assert SCHEMA_VERSION == "1.1.0"
