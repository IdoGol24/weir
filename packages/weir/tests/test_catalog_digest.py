"""Tests for the catalog content digest (spec section 4 skew-policy input)."""

import json
import re

import msgspec
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.catalog._types import Catalog, SinkSpec, VerbatimEligibility
from weir.catalog.digest import canonical_catalog_bytes, catalog_digest


def test_digest_is_lowercase_sha256_hex_and_stable() -> None:
    d1 = catalog_digest(DEFAULT_CATALOG)
    d2 = catalog_digest(DEFAULT_CATALOG)
    assert d1 == d2
    # baseline.py requires exactly this shape for the recorded catalog digest
    assert re.fullmatch(r"[0-9a-f]{64}", d1)


def test_digest_changes_when_catalog_changes() -> None:
    modified = Catalog(
        sources=list(DEFAULT_CATALOG.sources),
        sinks=[*DEFAULT_CATALOG.sinks, SinkSpec(tool_name="extra", destination_arg_keys=["x"])],
        remediations=dict(DEFAULT_CATALOG.remediations),
    )
    assert catalog_digest(modified) != catalog_digest(DEFAULT_CATALOG)


def test_digest_is_hash_seed_independent() -> None:
    # G1: identical inputs must give byte-identical output across runs.
    code = (
        "from weir.catalog import DEFAULT_CATALOG;"
        "from weir.catalog.digest import catalog_digest;"
        "print(catalog_digest(DEFAULT_CATALOG))"
    )
    assert_byte_identical_across_hash_seeds(code)


def test_canonical_bytes_use_sorted_keys() -> None:
    # The assertion that actually pins json.dumps(sort_keys=True): struct
    # field order is not alphabetical, so dropping the flag fails here. No
    # catalog field is an insertion-ordered dict today now that remediations
    # is excluded, so this holds the convention for whatever dict-bearing
    # field lands next.
    payload = json.loads(canonical_catalog_bytes(DEFAULT_CATALOG))
    assert list(payload) == sorted(payload)
    for source in payload["sources"]:
        assert list(source) == sorted(source)
    for sink in payload["sinks"]:
        assert list(sink) == sorted(sink)


def test_digest_ignores_remediation_copy() -> None:
    # Rewording advisory prose must not trigger a forced re-capture.
    reworded = Catalog(
        sources=list(DEFAULT_CATALOG.sources),
        sinks=list(DEFAULT_CATALOG.sinks),
        remediations={"langchain": "completely different advice"},
    )
    assert catalog_digest(reworded) == catalog_digest(DEFAULT_CATALOG)


def test_digest_is_sensitive_to_every_classifying_field() -> None:
    # The denylist must never grow silently: anything that can reclassify a
    # flow has to move the digest, or a reclassifying change slips past the
    # skew gate, which is the exact failure the gate exists to prevent.
    base = catalog_digest(DEFAULT_CATALOG)
    source = DEFAULT_CATALOG.sources[0]
    sink = DEFAULT_CATALOG.sinks[0]
    variants = [
        Catalog(
            sources=[msgspec.structs.replace(source, name="renamed")],
            sinks=list(DEFAULT_CATALOG.sinks),
            remediations=dict(DEFAULT_CATALOG.remediations),
        ),
        Catalog(
            sources=[msgspec.structs.replace(source, content_pattern=r"\d+")],
            sinks=list(DEFAULT_CATALOG.sinks),
            remediations=dict(DEFAULT_CATALOG.remediations),
        ),
        Catalog(
            sources=[
                msgspec.structs.replace(
                    source, eligibility=VerbatimEligibility(min_length=4)
                )
            ],
            sinks=list(DEFAULT_CATALOG.sinks),
            remediations=dict(DEFAULT_CATALOG.remediations),
        ),
        Catalog(
            sources=list(DEFAULT_CATALOG.sources),
            sinks=[msgspec.structs.replace(sink, destination_arg_keys=["cc"])],
            remediations=dict(DEFAULT_CATALOG.remediations),
        ),
        Catalog(
            sources=list(DEFAULT_CATALOG.sources),
            sinks=list(reversed(DEFAULT_CATALOG.sinks)),
            remediations=dict(DEFAULT_CATALOG.remediations),
        ),
    ]
    for variant in variants:
        assert catalog_digest(variant) != base


def test_default_catalog_has_webhook_sink() -> None:
    tool_names = {sink.tool_name for sink in DEFAULT_CATALOG.sinks}
    assert "post_to_webhook" in tool_names


def test_webhook_sink_declares_url_as_destination_key() -> None:
    sink = next(s for s in DEFAULT_CATALOG.sinks if s.tool_name == "post_to_webhook")
    assert sink.destination_arg_keys == ["url"]


def test_existing_send_email_sink_unchanged() -> None:
    sink = next(s for s in DEFAULT_CATALOG.sinks if s.tool_name == "send_email")
    assert sink.destination_arg_keys == ["to"]
