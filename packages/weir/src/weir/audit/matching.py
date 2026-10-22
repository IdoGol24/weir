"""Matching a string against the store (docs/audit.md, "Matching").

The audit holds no value it did not find: it takes candidate strings from
the text it reads, fingerprints each under the inventory's key, and looks
the fingerprint up. A string is searched in every form, the inverse of the
canary judge's encoded forms: the forms give decoded texts, whose candidates
are fingerprinted, or decoded candidates directly.

The candidates of a text are the whole text, each line, each assignment's
value, each quoted run, each PEM private key, each word, and each token
with its sub-spans between cut points. Tokens repeat endlessly in a session file
(the same output read twice, the same path in every record), so a token's
matches are memoised: the memo only ever saves work, it never changes a
result.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator

from weir.audit.inputs import fingerprint
from weir.canary import Form

MAX_CANDIDATE = 65536
# A sub-span runs from a cut point to any of the next CUT_WINDOW cut points.
CUT_WINDOW = 64
# A token this long made only of base64 or hex characters is taken whole:
# a blob is searched through its decodings, not through its raw sub-spans.
_BLOB_TOKEN = 256
_MEMO_LIMIT = 1 << 18
# Whole strings are memoised up to this many characters in all.
_STRING_MEMO_CHARS = 1 << 26

# docs/audit.md, "Candidates": whitespace, control characters, undecodable
# characters (lone surrogates) and a fixed set of punctuation separate
# tokens; inside a token, anything but a word character or `-` is a break.
_SEPARATOR_CLASS = "\\s\\x00-\\x1f\\x7f-\\x9f\\ud800-\\udfff\"'`<>()\\[\\]{},;|\\\\"
_TOKEN = re.compile(f"[^{_SEPARATOR_CLASS}]+")
# A word runs between whitespace, control and undecodable characters only,
# so a value holding a quote or a bracket is still one word.
_WORD = re.compile("[^\\s\\x00-\\x1f\\x7f-\\x9f\\ud800-\\udfff]+")
_SEPARATOR_ENDS = re.compile("^[\"'`<>()\\[\\]{},;|\\\\]+|[\"'`<>()\\[\\]{},;|\\\\]+$")
_PUNCTUATION_ENDS = re.compile(r"^[^\w-]+|[^\w-]+$")
_BREAK = re.compile(r"[^\w-]")
_BLOB = re.compile(r"[A-Za-z0-9+/=_-]+")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# A path is split into segments, and a segment is cut at every character that
# is not a letter or a digit: file names glue words with `-`, `_` and `.`.
_PATH_SEPARATOR = re.compile(r"[\\/]")
_PATH_BREAK = re.compile(r"[\W_]")
_LINE_PREFIX = re.compile(r"^\s*\d+(?:\u2192|\t)")
_ASSIGNMENT = re.compile(
    r"^\s*(?:\d+(?:\u2192|\t))?\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:](.*)$"
)
_QUOTED = re.compile(r"\"([^\"\r\n]*)\"|'([^'\r\n]*)'|`([^`\r\n]*)`")
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

_JSON_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)
_JSON_ESCAPE = re.compile(r"\\(?:([\"\\/bfnrt])|u([0-9A-Fa-f]{4}))")
_SHORT = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_PERCENT_RUN = re.compile(rb"%([0-9A-Fa-f]{2})")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_BASE64URL_RUN = re.compile(r"[A-Za-z0-9_-]{8,}={0,2}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{16,}")


def _utf8(text: str) -> bytes | None:
    """A candidate's bytes: an undecodable character is the byte it stood
    for. A lone surrogate that no byte stands for can match nothing."""
    try:
        return text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return None


def _text(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


# --- candidates ---------------------------------------------------------------


def _unquoted(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def line_candidates(text: str) -> Iterator[str]:
    """Rules 1 to 5: the whole text, lines, assignments, quoted runs and PEM
    keys."""
    yield text.strip()
    for line in _LINE_BREAK.split(text):
        yield line.strip()
        prefix = _LINE_PREFIX.match(line)
        if prefix is not None:
            yield line[prefix.end() :].strip()
        assignment = _ASSIGNMENT.match(line)
        if assignment is not None:
            value = assignment.group(1).strip()
            yield value
            yield _unquoted(value)
        for quoted in _QUOTED.finditer(line):
            yield next(group for group in quoted.groups() if group is not None)
    for pem in _PEM.finditer(text):
        yield pem.group(0)


def word_candidates(word: str) -> Iterator[str]:
    """Rule 6: a word whole and without separators or punctuation at its ends."""
    yield word
    yield _SEPARATOR_ENDS.sub("", word)
    yield _PUNCTUATION_ENDS.sub("", word)


def token_spans(token: str) -> Iterator[str]:
    """Rule 7: a token whole, and its sub-spans between cut points."""
    yield token
    if len(token) >= _BLOB_TOKEN and _BLOB.fullmatch(token):
        return
    cuts = {0, len(token)}
    for found in _BREAK.finditer(token):
        cuts.add(found.start())
        cuts.add(found.end())
    points = sorted(cuts)
    for i, start in enumerate(points):
        for end in points[i + 1 : i + 1 + CUT_WINDOW]:
            if end - start > MAX_CANDIDATE:
                break
            yield token[start:end]


def candidates(text: str) -> Iterator[str]:
    """Every candidate of a text, rules 1 to 7 (duplicates included). A
    token never crosses whitespace, so every token lies inside a word."""
    yield from line_candidates(text)
    for word in _WORD.findall(text):
        yield from word_candidates(word)
        for token in _TOKEN.findall(word):
            yield from token_spans(token)


# --- forms ----------------------------------------------------------------------


def json_unescape(text: str) -> str:
    def one(found: re.Match[str]) -> str:
        short, code = found.group(1), found.group(2)
        return _SHORT[short] if short is not None else chr(int(code, 16))

    unescaped = _JSON_ESCAPE.sub(one, text)
    # `\uD83D\uDE00` decodes to two surrogates: join each pair as one character.
    return unescaped.encode("utf-16", "surrogatepass").decode("utf-16", "surrogatepass")


def json_texts(text: str) -> list[tuple[str, bool]]:
    """The texts the json form unescapes, each with whether it is also a
    candidate whole: the string unescaped, and each JSON string literal whose
    content holds a backslash."""
    out = [(json_unescape(text), False)]
    for literal in _JSON_LITERAL.finditer(text):
        content = literal.group(1)
        if "\\" in content:
            out.append((json_unescape(content), True))
    return out


def _percent_decode(data: bytes) -> bytes:
    return _PERCENT_RUN.sub(lambda found: bytes([int(found.group(1), 16)]), data)


def url_decodings(candidate: str) -> Iterator[str]:
    data = _utf8(candidate)
    if data is None:
        return
    yield _text(_percent_decode(data))
    if b"+" in data:
        yield _text(_percent_decode(data.replace(b"+", b" ")))


def _base64_decodings(text: str, run: re.Pattern[str], urlsafe: bool) -> Iterator[str]:
    altchars = b"-_" if urlsafe else None
    for found in run.finditer(text):
        body = found.group(0).rstrip("=")
        if urlsafe and "-" not in body and "_" not in body:
            continue
        for start in range(4):
            part = body[start:]
            # A last group of 2 or 3 characters is padded; one of 1 holds
            # no whole byte and is dropped.
            rest = len(part) % 4
            part = part[:-1] if rest == 1 else part + "=" * ((4 - rest) % 4)
            if not part:
                continue
            try:
                yield _text(base64.b64decode(part, altchars=altchars, validate=True))
            except (binascii.Error, ValueError):
                continue


def _hex_decodings(text: str) -> Iterator[str]:
    for found in _HEX_RUN.finditer(text):
        run = found.group(0)
        for start in range(2):
            part = run[start:]
            part = part[: len(part) - len(part) % 2]
            yield _text(bytes.fromhex(part))


# --- the matcher ----------------------------------------------------------------


class Matcher:
    """Finds which stored fingerprints a string holds, and in which form.

    Words, tokens and whole strings repeat across a session (the same file
    read twice, the same path in every record), so their results are
    memoised. A memo only ever saves work: what a string holds is a pure
    function of the string, the key and the store."""

    def __init__(self, key: bytes, fingerprints: set[bytes]) -> None:
        self._key = key
        self._fingerprints = fingerprints
        self._words: dict[str, tuple[tuple[bytes, str], ...]] = {}
        self._tokens: dict[str, tuple[tuple[bytes, str], ...]] = {}
        self._strings: dict[str, dict[bytes, Form]] = {}
        self._strings_size = 0
        # Values found, kept in memory only, so the printing rule can
        # withhold any output that holds a fragment of one.
        self.found: set[str] = set()

    def _check(self, candidate: str, out: dict[bytes, str]) -> None:
        if not candidate or len(candidate) > MAX_CANDIDATE:
            return
        data = _utf8(candidate)
        if data is None:
            return
        fp = fingerprint(self._key, data)
        if fp in self._fingerprints:
            out[fp] = candidate

    @staticmethod
    def _remember(
        memo: dict[str, tuple[tuple[bytes, str], ...]], key: str, out: dict[bytes, str]
    ) -> tuple[tuple[bytes, str], ...]:
        result = tuple(out.items())
        if len(memo) >= _MEMO_LIMIT:
            memo.clear()
        memo[key] = result
        return result

    def _token(self, token: str) -> tuple[tuple[bytes, str], ...]:
        memo = self._tokens.get(token)
        if memo is not None:
            return memo
        out: dict[bytes, str] = {}
        for span in set(token_spans(token)):
            self._check(span, out)
        return self._remember(self._tokens, token, out)

    def _word(self, word: str) -> tuple[tuple[bytes, str], ...]:
        memo = self._words.get(word)
        if memo is not None:
            return memo
        out: dict[bytes, str] = {}
        for candidate in set(word_candidates(word)):
            self._check(candidate, out)
        for token in set(_TOKEN.findall(word)):
            out.update(self._token(token))
        return self._remember(self._words, word, out)

    def text(self, text: str, *, whole: bool = False) -> dict[bytes, str]:
        """The fingerprints among a text's candidates (and the text itself,
        unstripped, when `whole`)."""
        out: dict[bytes, str] = {}
        if whole:
            self._check(text, out)
        for candidate in set(line_candidates(text)):
            self._check(candidate, out)
        for word in set(_WORD.findall(text)):
            out.update(self._word(word))
        return out

    def path_holds_value(self, path: str) -> bool:
        """Does a path hold a stored credential? (docs/audit.md, "Printing").
        Every rule a string has, plus each span of a path segment between
        characters that are not letters or digits. A value found here is
        remembered like any other, so the printing rule withholds it."""
        held = bool(self.find(path))
        out: dict[bytes, str] = {}
        for segment in _PATH_SEPARATOR.split(path):
            cuts = {0, len(segment)}
            for found in _PATH_BREAK.finditer(segment):
                cuts.add(found.start())
                cuts.add(found.end())
            points = sorted(cuts)
            for i, start in enumerate(points):
                for end in points[i + 1 : i + 1 + CUT_WINDOW]:
                    self._check(segment[start:end], out)
        self.found.update(out.values())
        return held or bool(out)

    def find(self, string: str) -> dict[bytes, Form]:
        """Every stored fingerprint the string holds, under the first form
        (docs/audit.md, "Forms") that holds it."""
        memo = self._strings.get(string)
        if memo is not None:
            return memo
        found = self._find(string)
        self._strings_size += len(string)
        if self._strings_size > _STRING_MEMO_CHARS:
            self._strings.clear()
            self._strings_size = len(string)
        self._strings[string] = found
        return found

    def _find(self, string: str) -> dict[bytes, Form]:
        found: dict[bytes, Form] = {}

        def take(form: Form, matched: dict[bytes, str]) -> None:
            for fp, value in matched.items():
                found.setdefault(fp, form)
                self.found.add(value)

        take(Form.RAW, self.text(string))
        if "\\" in string:
            once = json_texts(string)
            for text, whole in once:
                take(Form.JSON, self.text(text, whole=whole))
            for text, _ in once:
                if "\\" in text:
                    for inner, whole in json_texts(text):
                        take(Form.JSON2, self.text(inner, whole=whole))
        if "+" in string or _PERCENT.search(string):
            for decoded in url_decodings(string):
                take(Form.URL, self.text(decoded))
            for candidate in set(candidates(string)):
                if "+" in candidate or _PERCENT.search(candidate):
                    for decoded in url_decodings(candidate):
                        out: dict[bytes, str] = {}
                        self._check(decoded, out)
                        take(Form.URL, out)
        for decoded in _base64_decodings(string, _BASE64_RUN, urlsafe=False):
            take(Form.BASE64, self.text(decoded))
        for decoded in _base64_decodings(string, _BASE64URL_RUN, urlsafe=True):
            take(Form.BASE64URL, self.text(decoded))
        for decoded in _hex_decodings(string):
            take(Form.HEX, self.text(decoded))
        return found


# docs/audit.md, "References by name": a shell variable name, and the
# expansions a tool's shell performs on it. A `$` after a `\` or another `$`
# is not an expansion of the name that follows.
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_EXPANSION = r"(?<![\\$])\$(?:\{{|env:)?({names})(?![A-Za-z0-9_])"


class References:
    """The environment credentials a tool call names: `$NAME`, `${NAME}`
    (with any modifier after the name) or PowerShell's `$env:NAME`. A pure
    function of the string and the names."""

    def __init__(self, names: dict[str, tuple[str, ...]]) -> None:
        self._ids = {name: ids for name, ids in names.items() if _ENV_NAME.fullmatch(name)}
        alternatives = "|".join(re.escape(n) for n in sorted(self._ids, key=lambda n: -len(n)))
        self._pattern = re.compile(_EXPANSION.format(names=alternatives)) if self._ids else None

    def find(self, string: str) -> set[str]:
        """The credential ids whose names the string expands."""
        if self._pattern is None or "$" not in string:
            return set()
        return {cid for found in self._pattern.finditer(string) for cid in self._ids[found[1]]}
