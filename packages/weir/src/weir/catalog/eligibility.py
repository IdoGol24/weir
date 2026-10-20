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

# Every bundled class's literal head, most specific first. The display shows
# this head before `...last4`, so it must never reach into the secret body,
# which for OpenAI, Anthropic and Google keys itself contains '-' and '_'.
_CLASS_HEAD = re.compile(
    r"sk-ant-(?:api|admin)[0-9]{2}-|sk-ant-|sk-(?:proj|svcacct)-|sk-|ghp_|AKIA|ASIA|AIza"
)
_FALLBACK_HEAD_LEN = 4


def class_prefix(value: str) -> str:
    """The class-identifying head of a value: the bundled class's literal
    prefix ("sk-proj-", "sk-ant-api03-", "ghp_", "AKIA", "AIza", ...), never
    any character of the body after it. A value with no known head yields its
    first 4 characters.

    ponytail: a list of heads, not catalog data. A contributor class with a
    longer literal prefix gets the 4-character fallback (safe for display,
    but `min_distinct_chars` then counts part of that prefix) until it is
    added here or the catalog grows an `exposure_prefix` field. Also assumes
    `value` has already cleared a length floor: on a very short string the
    fallback returns the whole thing.
    """
    head = _CLASS_HEAD.match(value)
    return head.group(0) if head is not None else value[:_FALLBACK_HEAD_LEN]


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
