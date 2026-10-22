"""Drift checks: the committed audit schema artifact is generated from the
structs, and no struct in the report can carry a value (docs/audit.md,
"The JSON report")."""

from __future__ import annotations

import json
from pathlib import Path

import msgspec

from weir.audit import Report, report_json_schema

_ARTIFACT = Path(__file__).parents[1] / "schema_artifacts" / "audit.v1.schema.json"


def test_committed_schema_artifact_matches_generated() -> None:
    committed = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    assert report_json_schema() == committed, (
        "packages/weir/schema_artifacts/audit.v1.schema.json is stale - regenerate it from "
        "weir.audit.report_json_schema()"
    )


def test_no_struct_in_the_report_has_a_value_field() -> None:
    """Value-free by construction: walk every struct reachable from the
    report and refuse any field named like a value carrier."""
    banned = {
        "value", "values", "secret", "match", "fragment", "prefix", "last4", "masked",
        "hash", "digest", "fingerprint", "needle", "candidate", "key",
    }
    seen: set[type] = set()
    stack: list[object] = [msgspec.inspect.type_info(Report)]
    while stack:
        node = stack.pop()
        if isinstance(node, msgspec.inspect.StructType):
            if node.cls in seen:
                continue
            seen.add(node.cls)
            for field in node.fields:
                assert field.name not in banned, (node.cls.__name__, field.name)
                stack.append(field.type)
        for attr in ("item_type", "key_type", "value_type"):
            child = getattr(node, attr, None)
            if child is not None:
                stack.append(child)
        stack.extend(getattr(node, "types", ()) or ())
    assert len(seen) >= 6, "walked too few structs"
