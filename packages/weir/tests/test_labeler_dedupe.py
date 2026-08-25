"""A value repeated inside one node is one label, not two.

`SourceLabel` carries only (node_index, source_class, matched_value) and no
position, so two labels from two occurrences of the same value in the same
node are indistinguishable - they carry zero extra information and travel
the whole pipeline as duplicates, surfacing as byte-identical findings with
the same witness path. The first thing a visitor sees printed twice reads as
a bug in the engine's arithmetic, not as thoroughness.

Deduping here rather than at the evaluator is deliberate: this is where the
duplication is created, and every downstream stage (taint, evaluate, report)
inherits the fix for free.
"""

from __future__ import annotations

import msgspec

from weir.catalog import DEFAULT_CATALOG
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import decode_canonical_trace

_IBAN = "DE89370400440532013000"


def _trace_with_content(content: str) -> bytes:
    """A minimal one-node trace whose tool_result carries `content`."""
    return msgspec.json.encode(
        {
            "schema_version": "1.2.0",
            "nodes": [
                {
                    "id": "n0",
                    "kind": "tool_result",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "tool",
                    "source_ref": "dedupe-0",
                    "payload": {"type": "tool_result", "content": content},
                    "degraded": False,
                }
            ],
            "joins": [],
            "metadata": {"adapter_name": "native", "adapter_version": "0.1.0"},
        }
    )


def _labels_for(content: str) -> list[str]:
    trace = decode_canonical_trace(_trace_with_content(content))
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    return [label.matched_value for label in labeled.source_labels]


def test_a_value_repeated_in_one_node_is_labeled_once() -> None:
    twice = _labels_for(f"Account {_IBAN}. Repeat: {_IBAN}.")
    assert twice == [_IBAN]


def test_deduping_does_not_collapse_distinct_values() -> None:
    # The failure mode of a careless dedupe: two genuinely different values
    # in one node must both survive.
    other = "DE75512108001245126199"
    labels = _labels_for(f"From {_IBAN} to {other}.")
    assert sorted(labels) == sorted([_IBAN, other])


def test_deduping_does_not_collapse_across_nodes() -> None:
    # The same value in two different nodes is two labels, because
    # node_index differs and the witness path depends on it.
    trace = decode_canonical_trace(
        msgspec.json.encode(
            {
                "schema_version": "1.2.0",
                "nodes": [
                    {
                        "id": f"n{i}",
                        "kind": "tool_result",
                        "timestamp": f"2026-01-01T00:00:0{i}Z",
                        "actor": "tool",
                        "source_ref": f"dedupe-{i}",
                        "payload": {"type": "tool_result", "content": f"Account {_IBAN}."},
                        "degraded": False,
                    }
                    for i in range(2)
                ],
                "joins": [],
                "metadata": {"adapter_name": "native", "adapter_version": "0.1.0"},
            }
        )
    )
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    iban_labels = [label for label in labeled.source_labels if label.matched_value == _IBAN]
    assert sorted(label.node_index for label in iban_labels) == [0, 1]
