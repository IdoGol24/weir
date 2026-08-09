"""Catalog content digest - the skew-policy input recorded in a baseline
(spec section 4). `weir diff` refuses to compare when the baseline's catalog
digest differs from the current one and exits 3 with a re-capture remediation,
because a catalog change can reclassify a flow and would otherwise be
indistinguishable from an agent regression.

Canonical JSON with sorted keys, so the digest is a function of the catalog's
meaning and not of dict insertion or hash order (G1).
"""

from __future__ import annotations

import hashlib
import json

import msgspec

from weir.catalog._types import Catalog


def catalog_digest(catalog: Catalog) -> str:
    data = msgspec.to_builtins(catalog, str_keys=True)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
