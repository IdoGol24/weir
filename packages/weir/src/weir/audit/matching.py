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

The matcher also tells where each value sits in a string (`Matcher.spans`),
so the redaction hook can replace it, still from fingerprints only.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import re
from collections.abc import Callable, Iterable, Iterator

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


def _unescape_one(found: re.Match[str]) -> str:
    short, code = found.group(1), found.group(2)
    return _SHORT[short] if short is not None else chr(int(code, 16))


def json_unescape(text: str) -> str:
    unescaped = _JSON_ESCAPE.sub(_unescape_one, text)
    # `\uD83D\uDE00` decodes to two surrogates: join each pair as one character.
    return unescaped.encode("utf-16", "surrogatepass").decode("utf-16", "surrogatepass")


def _json_regions(text: str) -> list[tuple[int, int, bool]]:
    """Where the texts the json form unescapes sit, each with whether it is
    also a candidate whole: the whole string, and the content of each JSON
    string literal that holds a backslash."""
    out = [(0, len(text), False)]
    at = text.find('"')
    while at >= 0:
        literal = _JSON_LITERAL.match(text, at)
        if literal is None:
            # No unescaped quote after this one: every later quote fails the
            # same way, so the scan stops here rather than trying each one.
            break
        if "\\" in literal.group(1):
            out.append((literal.start(1), literal.end(1), True))
        at = text.find('"', literal.end())
    return out


def json_texts(text: str) -> list[tuple[str, bool]]:
    """The texts the json form unescapes, each with whether it is also a
    candidate whole: the string unescaped, and each JSON string literal whose
    content holds a backslash."""
    return [(json_unescape(text[start:end]), whole) for start, end, whole in _json_regions(text)]


def _percent_decode(data: bytes) -> bytes:
    return _PERCENT_RUN.sub(lambda found: bytes([int(found.group(1), 16)]), data)


def url_decodings(candidate: str) -> Iterator[str]:
    data = _utf8(candidate)
    if data is None:
        return
    yield _text(_percent_decode(data))
    if b"+" in data:
        yield _text(_percent_decode(data.replace(b"+", b" ")))


def _base64_decodings(
    text: str, run: re.Pattern[str], urlsafe: bool
) -> Iterator[tuple[str, tuple[int, int]]]:
    """Each decoding, with the run it was decoded from."""
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
                yield _text(base64.b64decode(part, altchars=altchars, validate=True)), found.span()
            except (binascii.Error, ValueError):
                continue


def _hex_decodings(text: str) -> Iterator[tuple[str, tuple[int, int]]]:
    """Each decoding, with the run it was decoded from."""
    for found in _HEX_RUN.finditer(text):
        run = found.group(0)
        for start in range(2):
            part = run[start:]
            part = part[: len(part) - len(part) % 2]
            yield _text(bytes.fromhex(part)), found.span()


# --- where a match sits ---------------------------------------------------------

_Span = tuple[int, int]


class _Decoded:
    """Where each character of a decoded text came from: every decoded part
    (an escape, a `%XX`) as (from, to, start, end), [from, to) in the
    encoded text and [start, end) in the decoded one, in order. Between
    parts, the text was copied as it was."""

    def __init__(self, parts: list[tuple[int, int, int, int]]) -> None:
        self._parts = parts
        self._starts = [part[2] for part in parts]

    def start(self, at: int) -> int:
        i = bisect.bisect_right(self._starts, at) - 1
        if i < 0:
            return at
        start_from, to, _, end = self._parts[i]
        return start_from if at < end else to + at - end

    def end(self, at: int) -> int:
        """A part is one unit long, so the last part before `at` ends at
        or before it."""
        i = bisect.bisect_left(self._starts, at) - 1
        return at if i < 0 else self._parts[i][1] + at - self._parts[i][3]


def _decoded[T: (str, bytes)](
    text: T, escape: re.Pattern[T], one: Callable[[re.Match[T]], T]
) -> tuple[T, _Decoded]:
    """`text` with each `escape` replaced by its one-unit decoding, and
    where each unit came from."""
    parts: list[tuple[int, int, int, int]] = []
    shrunk = 0
    for found in escape.finditer(text):
        at = found.start() - shrunk
        parts.append((found.start(), found.end(), at, at + 1))
        shrunk += found.end() - found.start() - 1
    return escape.sub(one, text), _Decoded(parts)


def _occurrences[T: (str, bytes)](text: T, part: T) -> Iterator[_Span]:
    at = text.find(part)
    while at >= 0:
        yield at, at + len(part)
        at = text.find(part, at + 1)


def _escaped_spans(text: str, candidate: str, depth: int) -> Iterator[_Span]:
    """Where `candidate` sits in `text` once its JSON escapes are undone
    `depth` times: the exact run that unescapes to it. Surrogate pairs are
    not joined here, so a value holding one is not placed by this form."""
    for start, end, _ in _json_regions(text):
        decoded, where = _decoded(text[start:end], _JSON_ESCAPE, _unescape_one)
        inner = (
            _occurrences(decoded, candidate) if depth == 1
            else _escaped_spans(decoded, candidate, depth - 1)
        )
        for a, b in inner:
            yield start + where.start(a), start + where.end(b)


def _percent_spans(string: str, candidate: str) -> Iterator[_Span]:
    """Where `candidate` sits in `string` once its `%XX` are decoded, `+`
    kept and `+` read as a space: the exact run that decodes to it."""
    data, value = _utf8(string), _utf8(candidate)
    if data is None or value is None:
        return
    for variant in {data, data.replace(b"+", b" ")}:
        decoded, where = _decoded(
            variant, _PERCENT_RUN, lambda found: bytes([int(found.group(1), 16)])
        )
        for a, b in _occurrences(decoded, value):
            yield len(_text(data[: where.start(a)])), len(_text(data[: where.end(b)]))


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
        for form, matched, _ in self._forms(string):
            for fp, value in matched.items():
                found.setdefault(fp, form)
                self.found.add(value)
        return found

    def spans(self, string: str) -> list[tuple[int, int, bytes]]:
        """Where each stored value the string holds sits in it, in every
        form `find` searches: a raw value, and a JSON-escaped or URL-encoded
        one, at the exact run that gives it; a base64 or hex one at the
        whole run it was decoded from, whose edge characters mix bits of
        the value with bits of its neighbours. A value found whose place no
        form can tell spans the whole string. Overlapping spans are kept."""
        out: set[tuple[int, int, bytes]] = set()
        found: set[bytes] = set()
        for _, matched, where in self._forms(string):
            for fp, value in matched.items():
                found.add(fp)
                out |= {(a, b, fp) for a, b in where(value)}
        out |= {(0, len(string), fp) for fp in found - {fp for _, _, fp in out}}
        return sorted(out)

    def _forms(
        self, string: str
    ) -> Iterator[tuple[Form, dict[bytes, str], Callable[[str], Iterable[_Span]]]]:
        """Each form's matches, in the order of docs/audit.md, "Forms", and
        where a matched candidate sits in `string`."""
        yield Form.RAW, self.text(string), lambda value: _occurrences(string, value)
        if "\\" in string:
            once = json_texts(string)
            for text, whole in once:
                yield Form.JSON, self.text(text, whole=whole), (
                    lambda value: _escaped_spans(string, value, 1)
                )
            for text, _ in once:
                if "\\" in text:
                    for inner, whole in json_texts(text):
                        yield Form.JSON2, self.text(inner, whole=whole), (
                            lambda value: _escaped_spans(string, value, 2)
                        )
        if "+" in string or _PERCENT.search(string):
            for decoded in url_decodings(string):
                yield Form.URL, self.text(decoded), (
                    lambda value: _percent_spans(string, value)
                )
            for candidate in set(candidates(string)):
                if "+" in candidate or _PERCENT.search(candidate):
                    for decoded in url_decodings(candidate):
                        out: dict[bytes, str] = {}
                        self._check(decoded, out)
                        yield Form.URL, out, (
                            lambda _, encoded=candidate: _occurrences(string, encoded)
                        )
        runs = (
            (Form.BASE64, _base64_decodings(string, _BASE64_RUN, urlsafe=False)),
            (Form.BASE64URL, _base64_decodings(string, _BASE64URL_RUN, urlsafe=True)),
            (Form.HEX, _hex_decodings(string)),
        )
        for form, decodings in runs:
            for decoded, run in decodings:
                yield form, self.text(decoded), lambda _, run=run: (run,)
