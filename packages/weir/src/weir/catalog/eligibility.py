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
_SEPARATORS = "-_"
_PREFIX_WINDOW = 16


def class_prefix(value: str) -> str:
    """The class-identifying head of a value: the bundled class's literal
    prefix ("sk-proj-", "sk-ant-api03-", "ghp_", "AKIA", "AIza", ...), never
    any character of the body after it. A value with no known head yields its
    first 4 characters.

    ponytail: a list of heads, not catalog data. A contributor class with a
    longer literal prefix gets the 4-character fallback (safe for display)
    until it is added here or the catalog grows an `exposure_prefix` field.
    Also assumes `value` has already cleared a length floor: on a very short
    string the fallback returns the whole thing.
    """
    head = _CLASS_HEAD.match(value)
    return head.group(0) if head is not None else value[:_FALLBACK_HEAD_LEN]


# An escaped line break (the two characters `\n`, as after `[` in indented,
# escaped JSON) is a separator too, so its letter never shows as a word, and
# so are a URL-encoded space (`%20`, or `+` in a form body) and colon
# (`%3A`), as in `authorization=Bearer%20` and `authorization%3A%20Bearer%20`.
_KEY_SEPARATORS = re.compile(r"""(?:[\s"'=:,\[+]|%20|%3[Aa]|\\+[ntr]?)+""")
# The leading array items a credential field skips before the item it judges
# (`[null, "k1", `) are values, never part of the name: everything from the
# array's `[` through the last `,` goes. No header form has a `,` after its
# `[`, so a header name is untouched.
_SKIPPED_ITEMS = re.compile(r"\[.*,", re.DOTALL)


def assignment_prefix(key_text: str) -> str:
    """The display name of an assignment-shaped match: the text before its
    value group with quotes, backslash escapes (escaped line breaks
    included), operators, list punctuation, the leading array items a
    credential field skips and a bytes-literal `b` dropped, words joined by
    ': ', with a URL-encoded space or colon as a separator too. Every
    quoting of one key shows the same name, so `"api_key": "` and
    `\\"api_key\\":\\"` are both `api_key`, and the
    header is shown as written, with quotes, escapes and operators normalized
    (for example `Authorization: Bearer`, also for `(b'authorization',
    b'Bearer `). Never a byte of the value."""
    words = _KEY_SEPARATORS.split(_SKIPPED_ITEMS.sub("[", key_text))
    return ": ".join(word for word in words if word and word.lower() != "b")


def _floor_prefix(value: str) -> str:
    """The head `min_distinct_chars` strips before counting: everything
    through the last separator in the first 16 characters, or the first 4
    when there is none.

    ponytail: a heuristic, not catalog data, and deliberately not
    `class_prefix`: it may reach into the body, which is harmless for a count
    but not for a display. It yields "sk-proj-", "sk-ant-api03-" and "ghp_"
    for the separator-bearing shapes and a 4-character stub for AKIA/AIza,
    which is every bundled class - PROVIDED the class's literal prefix carries
    a separator within the window; a class with a longer separator-free
    prefix would need a wider window. Also assumes `value` has already
    cleared a length floor: on a very short string this returns the whole
    thing.
    """
    head = value[:_PREFIX_WINDOW]
    cut = max((i for i, ch in enumerate(head) if ch in _SEPARATORS), default=-1)
    return value[: cut + 1] if cut >= 0 else value[:4]


# A run of percent-escapes, decoded as one UTF-8 byte string with invalid
# bytes replaced, exactly as `urllib.parse.unquote` does. Decoded here rather
# than through `urllib`: the audit and status line import the catalog, and
# their import contracts (pyproject.toml) forbid `urllib` as a network module.
_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")


def _percent_decode(value: str) -> str:
    return _PERCENT_RUN.sub(
        lambda run: bytes.fromhex(run.group(0).replace("%", "")).decode("utf-8", "replace"),
        value,
    )


def matched_value(value: str, source: SourceSpec) -> str:
    """The value a match stands for: percent-decoded when the class declares
    `percent_decoded`, else as written. Judge, measure and fingerprint this,
    never the raw match."""
    return _percent_decode(value) if source.percent_decoded else value


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
        suffix = value[len(_floor_prefix(value)) :]
        if len(set(suffix)) < eligibility.min_distinct_chars:
            return False
    return not any(re.fullmatch(p, value) is not None for p in eligibility.reject_patterns)
