"""Canary values: the shapes registry and the generator (docs/canary.md,
"Canary values").

A planted value is a provider's documented prefix followed by random
characters from `[A-Za-z0-9]` only, so software that checks a key's prefix
or length accepts it and JSON and URL escaping leave it unchanged. The
prefixes and body lengths here are the ones weir's own catalog judges keys
by (`packages/weir/src/weir/catalog/bundled/catalog.json`, each class's
`eligibility.pattern`), so a canary is a key the pattern scan would also
call a key. `generic` has no prefix: it is the shape for fixtures and tests,
which never carry a real provider prefix.

Values come from a CSPRNG, fresh each run. A seed swaps in a deterministic
HMAC-SHA256 stream for local reproduction only; the `random` module is
banned repo-wide (pyproject.toml, G1).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from collections.abc import Callable, Iterable
from dataclasses import dataclass

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits

# weir's catalog demotes values holding these words (its `reject_patterns`
# are case-insensitive), which would distort a comparison with the pattern
# scan on the same capture. A value never holds one, in any letter case.
BANNED_WORDS = ("FAKE", "TEST", "EXAMPLE", "DEMO", "PLACEHOLDER", "REDACTED")
_BANNED = re.compile("|".join(BANNED_WORDS), re.IGNORECASE)

# Ids are printed in reports, so no id may hold a run of this many
# consecutive characters of any value (docs/canary.md, the ledger).
ID_OVERLAP = 6


@dataclass(frozen=True)
class Shape:
    prefix: str
    body_length: int
    alphabet: str = ALNUM


SHAPES: dict[str, Shape] = {
    "generic": Shape("", 40),
    # catalog openai_api_key: sk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,200}
    "openai": Shape("sk-proj-", 48),
    # catalog anthropic_api_key: sk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{60,200}
    "anthropic": Shape("sk-ant-api03-", 93),
    # catalog github_token: ghp_[A-Za-z0-9]{36}
    "github": Shape("ghp_", 36),
    # catalog google_api_key: AIza[A-Za-z0-9_-]{35}
    "google": Shape("AIza", 35),
    # catalog aws_access_key_id: (AKIA|ASIA)[A-Z0-9]{16}
    "aws-access-key-id": Shape("AKIA", 16, UPPER_DIGITS),
}


class ByteSource:
    """Random bytes: the CSPRNG, or an HMAC-SHA256 counter stream when seeded."""

    def __init__(self, seed: int | None = None) -> None:
        self._key = None if seed is None else str(seed).encode()
        self._counter = 0

    def read(self, n: int) -> bytes:
        if self._key is None:
            return secrets.token_bytes(n)
        out = b""
        while len(out) < n:
            self._counter += 1
            out += hmac.new(self._key, self._counter.to_bytes(8, "big"), hashlib.sha256).digest()
        return out[:n]

    def choose(self, alphabet: str, n: int) -> str:
        """n characters drawn uniformly from alphabet (rejection sampling)."""
        limit = 256 - 256 % len(alphabet)
        chars: list[str] = []
        while len(chars) < n:
            for b in self.read(n - len(chars) + 8):
                if b < limit and len(chars) < n:
                    chars.append(alphabet[b % len(alphabet)])
        return "".join(chars)


def overlaps(value: str, text: str, run: int = ID_OVERLAP) -> bool:
    """Does text hold a run of `run` or more consecutive characters of value?"""
    if len(text) < run or len(value) < run:
        return False
    windows = {value[i : i + run] for i in range(len(value) - run + 1)}
    return any(text[i : i + run] in windows for i in range(len(text) - run + 1))


def acceptable(value: str, taken: Iterable[str], ids: Iterable[str]) -> bool:
    """A value is usable when it holds no banned word, repeats no value and
    shares no run of ID_OVERLAP characters with any id that is or will be
    printed."""
    if _BANNED.search(value):
        return False
    if value in set(taken):
        return False
    return not any(overlaps(value, i) for i in ids)


def generate(
    make: Callable[[], str], taken: Iterable[str], ids: Iterable[str], tries: int = 1000
) -> str:
    """Draw values from `make` until one is acceptable."""
    taken_set, id_list = set(taken), list(ids)
    for _ in range(tries):
        value = make()
        if acceptable(value, taken_set, id_list):
            return value
    raise RuntimeError("could not draw an acceptable canary value")


def shaped(source: ByteSource, shape_name: str) -> Callable[[], str]:
    shape = SHAPES[shape_name]
    return lambda: shape.prefix + source.choose(shape.alphabet, shape.body_length)
