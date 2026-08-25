"""Catalog loader (C1), mirroring `rules_commons.loader`.

The catalog is data on disk, never fabricated in code (constitution #4). It
was a Python literal until this change, which meant adding a data type
required engine-source access; it is JSON now so a contributor can add one by
editing a file.
"""

from __future__ import annotations

import re
from pathlib import Path

import msgspec

from weir.catalog._types import Catalog

_BUNDLED_CATALOG = Path(__file__).parent / "bundled" / "catalog.json"


def _compile_patterns(catalog: Catalog, source: Path) -> None:
    """Compile every contributor-authored regex at LOAD time.

    A bad regex must never reach the analysis path. `re.error` raised
    mid-scan surfaces as an uncaught traceback and exit 1, which inside a CI
    gate is indistinguishable from "a verdict-grade finding was found" - the
    worst possible way for a config typo to present. Bad config dies here,
    named by source and field.

    Both regex fields are compiled, not just the new one: `content_pattern`
    has the identical failure mode and is equally contributor-authored, and
    one loop over both is a smaller diff than a guard per field.
    """
    for spec in catalog.sources:
        for field, pattern in (
            ("content_pattern", spec.content_pattern),
            ("eligibility.pattern", spec.eligibility.pattern),
        ):
            if pattern is None:
                continue
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"{source}: source {spec.name!r} has an invalid {field} "
                    f"{pattern!r}: {exc}"
                ) from exc


def load_catalog(path: Path | None = None) -> Catalog:
    """Decode and validate a catalog. Raises msgspec.ValidationError or
    DecodeError with a precise field path on a malformed document (G9), and
    ValueError naming the source and field on an uncompilable pattern."""
    target = path if path is not None else _BUNDLED_CATALOG
    catalog = msgspec.json.decode(target.read_bytes(), type=Catalog, strict=True)
    _compile_patterns(catalog, target)
    return catalog
