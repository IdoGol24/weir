"""Every catalog detector sees a value on line two of JSON-encoded text.

Tool arguments and tool results often arrive as JSON-encoded text, so a value
on any line after the first sits right after a literal backslash escape (`\\n`,
`\\t`, `\\r`) and the escape's letter is glued to it. A detector anchored with
a word boundary reads that letter and the value as one word and misses the
value. The expectation is never typed here: the decoded line on its own is
the control, and the encoded text must label exactly what it labels.

This runs the real labeler over the bundled catalog, so it covers every
detector the taint engine sees, exposure class or not.
"""

from __future__ import annotations

import json

import msgspec
import pytest

from weir.catalog import DEFAULT_CATALOG
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.schema.trace import decode_canonical_trace

# One synthetic, shape-correct value per catalog class. Each is obviously
# fake: FAKE padding, the well-known German test IBAN weir already plants, or
# AWS's own documented example key id.
_VALUES = {
    "financial_account_identifier": "DE89370400440532013000",
    "github_token": "ghp_" + "FAKE" * 9,
    "openai_api_key": "sk-proj-" + "FAKE" * 9,
    "anthropic_api_key": "sk-ant-api03-" + "FAKE" * 16,
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "google_api_key": "AIza" + "FAKE" * 9,
    "credential_field": "API_KEY=FAKE-CANARY-7Rk2Ls9Vn4Xb",
}

_ESCAPED_SEPARATORS = ("\n", "\t", "\r")


def _labels(source_class: str, content: str) -> list[str]:
    trace = decode_canonical_trace(msgspec.json.encode({
        "schema_version": "1.2.0",
        "nodes": [{
            "id": "n0",
            "kind": "tool_result",
            "timestamp": "2026-01-01T00:00:00Z",
            "actor": "tool",
            "source_ref": "escape-0",
            "payload": {"type": "tool_result", "content": content},
            "degraded": False,
        }],
        "joins": [],
        "metadata": {"adapter_name": "native", "adapter_version": "0.1.0"},
    }))
    labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)
    return [label.matched_value for label in labeled.source_labels
            if label.source_class == source_class]


def test_every_catalog_class_has_a_probe_value() -> None:
    # A detector added later must declare a probe here, so the escape
    # boundary is checked for it too rather than silently skipped.
    assert set(_VALUES) == {source.name for source in DEFAULT_CATALOG.sources}


@pytest.mark.parametrize("source_class", sorted(_VALUES))
@pytest.mark.parametrize("sep", _ESCAPED_SEPARATORS, ids=["n", "t", "r"])
def test_a_value_after_an_escape_is_labeled_as_decoded(source_class: str, sep: str) -> None:
    decoded = f"see below{sep}{_VALUES[source_class]}"
    encoded = json.dumps({"content": decoded})
    assert sep not in encoded
    control = _labels(source_class, decoded.split(sep)[-1])
    assert control, "the probe must match its own class on the decoded line"
    assert _labels(source_class, encoded) == control


@pytest.mark.parametrize("source_class", sorted(_VALUES))
@pytest.mark.parametrize("sep", _ESCAPED_SEPARATORS, ids=["n", "t", "r"])
def test_a_value_ends_at_the_escape_after_it(source_class: str, sep: str) -> None:
    decoded = f"{_VALUES[source_class]}{sep}next"
    control = _labels(source_class, decoded.split(sep)[0])
    assert control, "the probe must match its own class on the decoded line"
    assert _labels(source_class, json.dumps({"content": decoded})) == control


@pytest.mark.parametrize("source_class", sorted(_VALUES))
def test_a_value_glued_to_an_ordinary_letter_is_still_not_labeled(source_class: str) -> None:
    # The escape is a boundary; a plain letter is not, even the letter an
    # escape ends in, and an uppercase lookalike escape is not an escape.
    value = _VALUES[source_class]
    for glued in (f"x{value}", f"n{value}", f"t{value}", f"C:\\Windows\\N{value}",
                  json.dumps({"content": f"see below\nx{value}"})):
        assert _labels(source_class, glued) == [], glued
