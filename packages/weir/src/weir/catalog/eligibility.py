"""R5.9 verbatim-eligibility check: applies a source class's floor (a named
structure class, a shape pattern, or a minimum length) to a candidate value.
Precedence is declared, not left to field order. This is what the
taint layer (L15) calls before it will count a match as verbatim - not the
labeler's content-pattern, which is deliberately loose.

Two more floors apply after the one above clears: `min_distinct_chars` (a
zeroed or masked value has too little entropy) and `reject_patterns` (a
named placeholder that is high-entropy enough to clear the floor anyway,
like AWS's own documented example key)."""

from __future__ import annotations

import re

from weir.catalog._types import SourceSpec
from weir.catalog.structure_classes import STRUCTURE_CLASSES

_SEPARATORS = "-_"
_PREFIX_WINDOW = 12


def class_prefix(value: str) -> str:
    """The class-identifying head of a value: everything through the last
    separator in the first 12 characters, or the first 4 when there is none.

    ponytail: a heuristic, not catalog data. It yields "sk-proj-", "sk-ant-"
    and "ghp_" for the separator-bearing shapes and a 4-character stub for
    AKIA/AIza, which is every bundled class. Add a per-class `exposure_prefix`
    catalog field only when a real class needs a head this cannot derive.
    """
    head = value[:_PREFIX_WINDOW]
    cut = max((i for i, ch in enumerate(head) if ch in _SEPARATORS), default=-1)
    return value[: cut + 1] if cut >= 0 else value[:4]


def is_verbatim_eligible(value: str, source: SourceSpec) -> bool:
    eligibility = source.eligibility
    if eligibility.structure_class is not None:
        matcher = STRUCTURE_CLASSES.get(eligibility.structure_class)
        cleared = matcher(value) if matcher is not None else False
    elif eligibility.pattern is not None:
        # fullmatch, never search: a contributor should not have to remember
        # anchors, and an unanchored pattern must not match inside a longer
        # string. An invalid pattern raises re.error rather than silently
        # rejecting every value.
        cleared = re.fullmatch(eligibility.pattern, value) is not None
    elif eligibility.min_length is not None:
        cleared = len(value) >= eligibility.min_length
    else:
        return False  # no declared floor: never eligible (triage by construction)
    if not cleared:
        return False
    if eligibility.min_distinct_chars is not None:
        # Count the SUFFIX, not the whole value: a class's own prefix is
        # constant across every value of that class, so counting it measures
        # the prefix's length rather than the secret's entropy - `sk-proj-`
        # alone supplies 7 distinct characters and would carry a zeroed key
        # over a floor of 8.
        suffix = value[len(class_prefix(value)) :]
        if len(set(suffix)) < eligibility.min_distinct_chars:
            return False
    return not any(re.fullmatch(p, value) is not None for p in eligibility.reject_patterns)
