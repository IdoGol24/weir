"""Tests for the generic content-digest helper (design section 3.1)."""

import re

import msgspec
import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.catalog.digest import catalog_digest
from weir.schema._digest import canonical_json_bytes, content_digest


class _Sample(msgspec.Struct, frozen=True):
    beta: str
    alpha: int


def test_canonical_bytes_sort_keys_and_omit_whitespace() -> None:
    assert canonical_json_bytes(_Sample(beta="x", alpha=1)) == b'{"alpha":1,"beta":"x"}'


def test_canonical_bytes_accept_plain_mappings() -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_digest_is_lowercase_sha256_hex() -> None:
    digest = content_digest(_Sample(beta="x", alpha=1))
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_digest_is_stable_and_content_sensitive() -> None:
    assert content_digest(_Sample(beta="x", alpha=1)) == content_digest(
        _Sample(beta="x", alpha=1)
    )
    assert content_digest(_Sample(beta="x", alpha=1)) != content_digest(
        _Sample(beta="x", alpha=2)
    )


def test_catalog_digest_is_deliberately_not_refactored_onto_this_helper() -> None:
    # catalog_digest EXCLUDES `remediations`; the generic helper digests
    # everything. They must stay different functions: catalog_digest's output is
    # baked into three committed baseline fixtures under fixtures/diffspec/
    # baselines/, so changing its implementation would silently invalidate the
    # frozen corpus. This test exists to make that separation deliberate rather
    # than an accident someone later "cleans up".
    assert catalog_digest(DEFAULT_CATALOG) != content_digest(DEFAULT_CATALOG)


class _WithSet(msgspec.Struct, frozen=True):
    tags: set[str]


class _Nested(msgspec.Struct, frozen=True):
    inner: _WithSet


def test_set_is_rejected_not_silently_reordered() -> None:
    # msgspec flattens a set to a list in hash-randomized order, so accepting
    # this would mean a different digest in every process, with no error.
    with pytest.raises(TypeError, match="cannot be digested stably"):
        canonical_json_bytes(_WithSet(tags={"a", "b"}))


def test_nested_set_is_rejected_with_its_path() -> None:
    with pytest.raises(TypeError, match=r"\$\.inner\.tags"):
        canonical_json_bytes(_Nested(inner=_WithSet(tags={"a"})))


def test_set_inside_a_plain_container_is_rejected() -> None:
    with pytest.raises(TypeError, match="cannot be digested stably"):
        canonical_json_bytes({"a": [1, {"b"}]})


def test_float_is_rejected() -> None:
    with pytest.raises(TypeError, match="cannot be digested stably"):
        canonical_json_bytes({"ratio": 0.5})


def test_bool_is_not_mistaken_for_a_float() -> None:
    # bool subclasses int, not float, so it must pass through untouched.
    assert canonical_json_bytes({"flag": True}) == b'{"flag":true}'


def test_digest_is_hash_seed_independent() -> None:
    # G1. The sibling test_catalog_digest.py does this; skipping it here would
    # mint the exact gap the previous slice's merge-review flagged, in the one
    # module least able to afford it.
    assert_byte_identical_across_hash_seeds(
        "from weir.schema._digest import content_digest;"
        "import msgspec;"
        "S = msgspec.defstruct('S', [('b', str), ('a', int)], frozen=True);"
        "T = msgspec.defstruct('T', [('items', list)], frozen=True);"
        "print(content_digest(T(items=[S(b='x', a=1), S(b='y', a=2)])))"
    )
