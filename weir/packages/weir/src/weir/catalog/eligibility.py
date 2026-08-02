"""R5.9 verbatim-eligibility check: applies a source class's floor (a named
structure class, or a minimum length) to a candidate value. This is what the
taint layer (L15) calls before it will count a match as verbatim — not the
labeler's content-pattern, which is deliberately loose."""

from __future__ import annotations

from weir.catalog._types import SourceSpec
from weir.catalog.structure_classes import STRUCTURE_CLASSES


def is_verbatim_eligible(value: str, source: SourceSpec) -> bool:
    eligibility = source.eligibility
    if eligibility.structure_class is not None:
        matcher = STRUCTURE_CLASSES.get(eligibility.structure_class)
        return matcher(value) if matcher is not None else False
    if eligibility.min_length is not None:
        return len(value) >= eligibility.min_length
    return False
