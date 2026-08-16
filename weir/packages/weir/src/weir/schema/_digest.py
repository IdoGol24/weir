"""Generic content digest: canonical JSON with sorted keys, then SHA-256.

Used by `weir.schema.dialect` so tracegen can compute a profile digest without
reaching into `weir.catalog`, which the import boundary forbids.

DELIBERATELY NOT adopted by `weir.catalog.digest`, `weir.schema.flowfact` or
`weir.schema.baseline`. Those three carry module-specific field handling -
catalog excludes advisory copy, flowfact and baseline have their own field
semantics - and, decisively, `catalog_digest`'s output is embedded in committed
baseline fixtures. Refactoring it onto this helper would change those bytes and
silently invalidate the frozen corpus. The duplication is the cheap side of that
trade.
"""

from __future__ import annotations

import hashlib
import json

import msgspec


def canonical_json_bytes(value: object) -> bytes:
    """Canonical JSON: sorted keys, no whitespace. The digest input."""
    return json.dumps(
        msgspec.to_builtins(value, str_keys=True), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
