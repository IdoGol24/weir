"""Labeler (L14, R4.1-R4.5): SessionGraph + Catalog -> LabeledGraph.

Pure, order-independent (purity core, constitution #2; enforced by the
import-linter contract). Source labels use the catalog's content-pattern,
which is deliberately loose (see weir.catalog.SourceSpec) — R5.9 eligibility
filtering happens downstream in the taint engine (L15), not here. Sink
labels extract the true destination via recursive descent over (possibly
nested) tool_call args, keyed by the catalog's destination_arg_keys — never
the tool name itself.

Guard satisfaction (R4.1-4.5) is deferred: no guard-bearing scenario exists
in this demo slice, and the catalog defines no guards (see L10 notes).
R4.6 event annotations are out of scope for this slice entirely.
"""

from __future__ import annotations

import re
from typing import cast

from weir.catalog import Catalog
from weir.graph import SessionGraph
from weir.label._types import LabeledGraph, SinkLabel, SourceLabel
from weir.schema.trace import LlmCallPayload, ToolCallPayload, ToolResultPayload, UserInputPayload


def _textual_content(payload: object) -> str | None:
    if isinstance(payload, ToolResultPayload | LlmCallPayload | UserInputPayload):
        return payload.content
    return None


def _find_destination(args: dict[str, object], keys: list[str]) -> str | None:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str):
            return value
    for value in args.values():
        if isinstance(value, dict):
            found = _find_destination(cast("dict[str, object]", value), keys)
            if found is not None:
                return found
        elif isinstance(value, list):
            for item in cast("list[object]", value):
                if isinstance(item, dict):
                    found = _find_destination(cast("dict[str, object]", item), keys)
                    if found is not None:
                        return found
    return None


def label_graph(graph: SessionGraph, catalog: Catalog) -> LabeledGraph:
    source_labels: list[SourceLabel] = []
    for i, node in enumerate(graph.nodes):
        content = _textual_content(node.payload)
        if content is None:
            continue
        for source in catalog.sources:
            for match in re.finditer(source.content_pattern, content):
                source_labels.append(
                    SourceLabel(
                        node_index=i,
                        source_class=source.name,
                        matched_value=match.group(0),
                    )
                )

    sink_labels: list[SinkLabel] = []
    for i, node in enumerate(graph.nodes):
        if not isinstance(node.payload, ToolCallPayload):
            continue
        for sink in catalog.sinks:
            if node.payload.tool_name != sink.tool_name:
                continue
            destination = _find_destination(node.payload.args, sink.destination_arg_keys)
            sink_labels.append(
                SinkLabel(node_index=i, tool_name=sink.tool_name, true_destination=destination)
            )

    return LabeledGraph(graph=graph, source_labels=source_labels, sink_labels=sink_labels)
