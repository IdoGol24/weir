"""Catalog content digest - the skew-policy input recorded in a baseline
(spec section 4). `weir diff` refuses to compare when the baseline's catalog
digest differs from the current one and exits 3 with a re-capture remediation,
because a catalog change can reclassify a flow and would otherwise be
indistinguishable from an agent regression.

Two deliberate scoping decisions:

- `remediations` and `scope_remediations` are EXCLUDED. Both are advisory
  prose rendered into the gauge line; neither can reclassify a flow, so a
  reworded sentence must not force every user through a spurious re-capture.
  The exclusion is a DENYLIST, not an allowlist, so any field added to the
  catalog later is digested by default: a new analytical field silently
  escaping the skew gate is the far worse failure.
- List ORDER is significant here, unlike the sorted fact lists in
  `weir.schema.baseline`. A catalog is a hand-authored ordered document and
  its order is meaning-bearing - the labeler returns the FIRST match in
  `destination_arg_keys` - so sorting would hide a real change.
"""

from __future__ import annotations

import hashlib
import json

import msgspec

from weir.catalog._types import Catalog

# Advisory presentation copy; see the module docstring.
_NON_CLASSIFYING_FIELDS = frozenset({"remediations", "scope_remediations"})


def canonical_catalog_bytes(catalog: Catalog) -> bytes:
    """Canonical JSON over the classifying part of the catalog: sorted keys,
    author-declared list order preserved."""
    data = msgspec.to_builtins(catalog, str_keys=True)
    classifying = {
        key: value for key, value in data.items() if key not in _NON_CLASSIFYING_FIELDS
    }
    return json.dumps(classifying, sort_keys=True, separators=(",", ":")).encode("utf-8")


def catalog_digest(catalog: Catalog) -> str:
    return hashlib.sha256(canonical_catalog_bytes(catalog)).hexdigest()
