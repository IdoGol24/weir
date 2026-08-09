"""Tests for the catalog content digest (spec section 4 skew-policy input)."""

import re

from weir.catalog import DEFAULT_CATALOG
from weir.catalog._types import Catalog, SinkSpec
from weir.catalog.digest import catalog_digest


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
    # G1: identical inputs must give byte-identical output across runs. The
    # digest walks dicts, so a hash-order-dependent serialization would break
    # the skew policy in a way that only shows up intermittently.
    import subprocess
    import sys

    code = (
        "from weir.catalog import DEFAULT_CATALOG;"
        "from weir.catalog.digest import catalog_digest;"
        "print(catalog_digest(DEFAULT_CATALOG))"
    )
    digests = set()
    for seed in ("0", "1", "2"):
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": seed, "PATH": ""},
        )
        digests.add(result.stdout.strip())
    assert len(digests) == 1


def test_default_catalog_has_webhook_sink() -> None:
    tool_names = {sink.tool_name for sink in DEFAULT_CATALOG.sinks}
    assert "post_to_webhook" in tool_names


def test_webhook_sink_extracts_its_url() -> None:
    sink = next(s for s in DEFAULT_CATALOG.sinks if s.tool_name == "post_to_webhook")
    assert sink.destination_arg_keys == ["url"]


def test_existing_send_email_sink_unchanged() -> None:
    sink = next(s for s in DEFAULT_CATALOG.sinks if s.tool_name == "send_email")
    assert sink.destination_arg_keys == ["to"]
