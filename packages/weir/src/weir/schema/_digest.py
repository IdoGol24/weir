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
from typing import cast

import msgspec

# Types that cannot produce a stable digest, rejected rather than coerced.
_UNSTABLE_TYPES: tuple[type, ...] = (set, frozenset, float)


def _reject_unstable(value: object, path: str = "$") -> None:
    """Walk the value and reject types that cannot be digested stably.

    `set` and `frozenset` iterate in hash-randomized order, and msgspec
    flattens them to a list BEFORE json.dumps could sort anything, so a set
    field yields a different digest in every process with no error at all.
    `float` is banned at weir's seams (spec section 3.3) as a cross-language
    determinism hazard; ratios belong in integer basis points.

    Rejecting beats normalizing here: a set or a float at a digest seam is a
    modelling error, and the caller's correct fix is a sorted list or an
    integer, not a silent repair in this function.
    """
    if isinstance(value, _UNSTABLE_TYPES):
        raise TypeError(
            f"{type(value).__name__} at {path} cannot be digested stably; "
            "use a sorted list for set-like data and integer basis points for ratios"
        )
    if isinstance(value, dict):
        for key, item in cast("dict[object, object]", value).items():
            _reject_unstable(item, f"{path}.{key}")
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(cast("list[object] | tuple[object, ...]", value)):
            _reject_unstable(item, f"{path}[{index}]")
        return
    if isinstance(value, msgspec.Struct):
        for field in value.__struct_fields__:
            _reject_unstable(getattr(value, field), f"{path}.{field}")


def canonical_json_bytes(value: object) -> bytes:
    """Canonical JSON: sorted keys, no whitespace. The digest input.

    `allow_nan=False` is belt and braces - floats are already rejected above -
    because a bare NaN or Infinity token is not legal JSON and would be
    rejected outright by a conforming parser in another language.
    """
    _reject_unstable(value)
    return json.dumps(
        msgspec.to_builtins(value, str_keys=True),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
