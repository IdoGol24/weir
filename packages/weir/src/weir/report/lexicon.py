"""G5 language lint (minimal, inline): the forbidden lexicon check applied
directly to a rendered report. The full `weir validate --templates` linter
(L24, checking all shipped templates generically) is deferred to M2 - this
is just enough to prove L17's own output stays honest (constitution #9)."""

from __future__ import annotations

FORBIDDEN_LEXICON: tuple[str, ...] = (
    "safe",
    "secure",
    "certified",
    "guaranteed",
    "compliant",
    "no vulnerabilities",
)


def find_forbidden_lexicon(html: str) -> list[str]:
    lowered = html.lower()
    return [word for word in FORBIDDEN_LEXICON if word in lowered]
