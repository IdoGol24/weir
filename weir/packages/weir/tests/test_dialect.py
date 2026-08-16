"""Tests for the dialect profile registry (design sections 1 and 3)."""

import re

import pytest

from weir.schema.dialect import (
    DIALECT_REGISTRY,
    OTEL_GENAI_1_42_0,
    PLANNED_DIALECTS,
    AttributeSpec,
    DialectProfile,
    content_bearing_keys,
    profile_digest,
)


def test_pin_identity() -> None:
    assert OTEL_GENAI_1_42_0.profile_id == "otel-genai/1.42.0"
    assert OTEL_GENAI_1_42_0.schema_url == "https://opentelemetry.io/schemas/1.42.0"


def test_registry_holds_the_pin_and_nothing_else_yet() -> None:
    assert DIALECT_REGISTRY == {"otel-genai/1.42.0": OTEL_GENAI_1_42_0}


def test_planned_dialects_are_named_but_not_built() -> None:
    # Named so nobody mistakes row one for the schema; absent from the registry
    # so nothing can accidentally emit against an unimplemented dialect.
    assert "otel-genai-legacy/1.36-events" in PLANNED_DIALECTS
    for name in PLANNED_DIALECTS:
        assert name not in DIALECT_REGISTRY


def test_uses_the_post_v1_37_provider_attribute() -> None:
    keys = {spec.key for spec in OTEL_GENAI_1_42_0.attributes}
    assert "gen_ai.provider.name" in keys
    assert "gen_ai.system" not in keys  # renamed in v1.37.0


def test_content_bearing_keys_are_declared_not_inferred() -> None:
    keys = content_bearing_keys(OTEL_GENAI_1_42_0)
    assert "gen_ai.input.messages" in keys
    assert "gen_ai.output.messages" in keys
    assert "gen_ai.tool.call.arguments" in keys
    assert "gen_ai.tool.call.result" in keys
    # Linkage and naming are NOT content: dropping content must not drop these.
    assert "gen_ai.tool.call.id" not in keys
    assert "gen_ai.tool.name" not in keys


def test_profile_digest_is_hex_and_content_sensitive() -> None:
    digest = profile_digest(OTEL_GENAI_1_42_0)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    extra = AttributeSpec(key="zz.late", content_bearing=False)
    altered = DialectProfile(
        profile_id=OTEL_GENAI_1_42_0.profile_id,
        schema_url=OTEL_GENAI_1_42_0.schema_url,
        attributes=[*OTEL_GENAI_1_42_0.attributes, extra],
    )
    assert profile_digest(altered) != digest


def test_attribute_keys_are_unique_and_sorted() -> None:
    keys = [spec.key for spec in OTEL_GENAI_1_42_0.attributes]
    assert keys == sorted(set(keys))


def test_duplicate_attribute_keys_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        DialectProfile(
            profile_id="x/1",
            schema_url="https://example.invalid/1",
            attributes=[
                AttributeSpec(key="a", content_bearing=False),
                AttributeSpec(key="a", content_bearing=True),
            ],
        )


def test_unsorted_attribute_keys_rejected() -> None:
    with pytest.raises(ValueError, match="sorted"):
        DialectProfile(
            profile_id="x/1",
            schema_url="https://example.invalid/1",
            attributes=[
                AttributeSpec(key="b", content_bearing=False),
                AttributeSpec(key="a", content_bearing=False),
            ],
        )


def test_profile_digest_is_hash_seed_independent() -> None:
    # G1. The profile digest is stamped into every emitted trace, so an
    # unstable one would poison the whole corpus.
    from _harness.g1 import assert_byte_identical_across_hash_seeds

    assert_byte_identical_across_hash_seeds(
        "from weir.schema.dialect import OTEL_GENAI_1_42_0, profile_digest;"
        "print(profile_digest(OTEL_GENAI_1_42_0))"
    )
