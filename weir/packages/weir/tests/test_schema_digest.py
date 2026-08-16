"""Tests for the generic content-digest helper (design section 3.1)."""

import re

import msgspec

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
    # baked into four committed baseline fixtures under fixtures/diffspec/
    # baselines/, so changing its implementation would silently invalidate the
    # frozen corpus. This test exists to make that separation deliberate rather
    # than an accident someone later "cleans up".
    assert catalog_digest(DEFAULT_CATALOG) != content_digest(DEFAULT_CATALOG)
