"""R5.9 verbatim-eligibility check: applies a source class's floor (a named
structure class, a shape pattern, or a minimum length) to a candidate value.
Precedence is declared, not left to field order. This is what the
taint layer (L15) calls before it will count a match as verbatim - not the
labeler's content-pattern, which is deliberately loose."""

from __future__ import annotations

import re

from weir.catalog._types import SourceSpec
from weir.catalog.structure_classes import STRUCTURE_CLASSES


def is_verbatim_eligible(value: str, source: SourceSpec) -> bool:
    eligibility = source.eligibility
    if eligibility.structure_class is not None:
        matcher = STRUCTURE_CLASSES.get(eligibility.structure_class)
        return matcher(value) if matcher is not None else False
    if eligibility.pattern is not None:
        # fullmatch, never search: a contributor should not have to remember
        # anchors, and an unanchored pattern must not match inside a longer
        # string. An invalid pattern raises re.error rather than silently
        # rejecting every value.
        return re.fullmatch(eligibility.pattern, value) is not None
    if eligibility.min_length is not None:
        return len(value) >= eligibility.min_length
    return False
