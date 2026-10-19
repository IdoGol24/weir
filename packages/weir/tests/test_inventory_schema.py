"""Drift checks: the committed inventory schema artifacts and the generated
location list doc are derived from the code, so neither can silently diverge
from what `weir inventory --json` emits."""

from __future__ import annotations

import json
from pathlib import Path

import msgspec
import pytest

from weir.inventory import Inventory, Store, inventory_json_schema, store_json_schema
from weir.inventory.locations import render_locations_doc

_ARTIFACTS = Path(__file__).parents[1] / "schema_artifacts"
_DOCS = Path(__file__).parents[3] / "docs"


@pytest.mark.parametrize(
    ("artifact", "generate"),
    [
        ("inventory.v1.schema.json", inventory_json_schema),
        ("inventory-store.v1.schema.json", store_json_schema),
    ],
)
def test_committed_schema_artifact_matches_generated(artifact, generate) -> None:
    committed = json.loads((_ARTIFACTS / artifact).read_text(encoding="utf-8"))
    assert generate() == committed, (
        f"packages/weir/schema_artifacts/{artifact} is stale - regenerate it from "
        f"weir.inventory.{generate.__name__}()"
    )


def test_committed_locations_doc_matches_the_renderer() -> None:
    assert render_locations_doc() == (_DOCS / "inventory-locations.md").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("struct", [Inventory, Store])
def test_no_struct_in_the_report_or_store_has_a_value_field(struct) -> None:
    """Value-free by construction: walk every struct reachable from the
    report and the store and refuse any field named like a value carrier."""
    banned = {"value", "values", "secret", "raw", "match", "prefix", "last4", "masked"}
    seen: set[type] = set()

    def walk(tp: object) -> None:
        info = msgspec.inspect.type_info(tp)  # type: ignore[arg-type]
        stack = [info]
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
            for child in getattr(node, "types", ()) or ():
                stack.append(child)
            if isinstance(node, msgspec.inspect.TupleType):
                stack.extend(node.item_types)

    walk(struct)
    assert seen, "walked no structs"
