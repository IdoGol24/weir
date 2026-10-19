"""Is this name or value a secret? Local, deterministic checks only.

The environment-variable rule (design brief, "Component specs: Inventory"):
a variable is a secret if its name suggests one or a local check of its
value's shape says so; a value that is a number, a boolean, a path or a plain
hostname is not a secret; anything else is unknown. Precedence, in order:

1. the value has a credential shape (catalog key shapes, a JWT, a URL with a
   password, a PEM private key)  -> secret, reason "shape"
2. the value is empty, a number, a boolean, a path or a plain hostname
                                                    -> not a secret
3. the name suggests a secret                       -> secret, reason "name"
4. anything else                                    -> unknown

Step 2 before step 3 is deliberate: `GOOGLE_APPLICATION_CREDENTIALS` holds a
path and `TOKEN_TTL` a number, and neither value is the credential. The path
check refuses a value with a high-entropy segment, or whose segments read as
key material once the separators are removed, so an AWS secret key that
happens to start with "/" is not waved through as a path. High entropy is
mixed case and digits that do not read as CamelCase or digit words, so
`C:\\Users\\Dev\\AppData\\Local\\Programs\\Python\\Python312` is still a path.
"""

from __future__ import annotations

import enum
import re

from weir.catalog import DEFAULT_CATALOG, Catalog, is_verbatim_eligible


class EnvVerdict(enum.StrEnum):
    SECRET = "secret"
    NOT_SECRET = "not_secret"
    UNKNOWN = "unknown"


# Words that mark a name as a secret on their own.
_SECRET_WORDS = frozenset({
    "SECRET", "SECRETS", "TOKEN", "TOKENS", "PASSWORD", "PASSWORDS", "PASSWD", "PASS",
    "PWD", "PASSPHRASE", "CREDENTIAL", "CREDENTIALS", "CREDS", "APIKEY", "APIKEYS",
    "AUTHTOKEN", "JWT", "BEARER", "COOKIE", "DSN", "PRIVATEKEY",
})
# KEY is a secret word after one of these qualifiers, wherever it sits
# (`client-key-data`, `PRIVATE_KEY_ID`), and as the LAST word of a name
# (`STRIPE_KEY`) unless the qualifier says it is public.
_KEY_QUALIFIERS = frozenset({
    "API", "ACCESS", "SECRET", "PRIVATE", "CLIENT", "SIGNING", "ENCRYPTION", "MASTER",
    "SESSION", "AUTH", "LICENSE", "DEPLOY", "SERVICE", "ACCOUNT", "APP", "WEBHOOK", "HMAC",
    "ADMIN", "SSH", "ENCRYPT", "DECRYPT", "SIGN",
})
_PUBLIC_QUALIFIERS = frozenset({"PUBLIC", "PUBLISHABLE", "PUB"})
_KEY_WORDS = frozenset({"KEY", "KEYS"})

_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def name_words(name: str) -> list[str]:
    """`ACME_API_KEY` -> [ACME, API, KEY]; `clientSecret` -> [CLIENT, SECRET];
    `_authToken` -> [AUTH, TOKEN]."""
    words: list[str] = []
    for chunk in _WORD_SPLIT.split(name):
        words.extend(part.upper() for part in _CAMEL.findall(chunk))
    return words


def name_suggests_secret(name: str) -> bool:
    words = name_words(name)
    if any(word in _SECRET_WORDS for word in words):
        return True
    significant = [w for w in words if not w.isdigit()]
    for i, word in enumerate(significant):
        if word not in _KEY_WORDS:
            continue
        before = significant[i - 1] if i > 0 else None
        if before in _KEY_QUALIFIERS:
            return True
        if i == len(significant) - 1 and before not in _PUBLIC_QUALIFIERS:
            return True
    return False


_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_URL_WITH_PASSWORD = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]*:[^\s/@'\"]+@[^\s'\"]+")
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


def value_shape(value: str, catalog: Catalog = DEFAULT_CATALOG) -> str | None:
    """The credential shape the WHOLE value has, or None. Catalog key shapes
    are judged by their eligibility pattern (fullmatch), so a documented
    placeholder such as AWS's example key is not a shape match."""
    for spec in catalog.sources:
        if spec.exposure and spec.eligibility.pattern is not None:
            if is_verbatim_eligible(value, spec):
                return spec.name
    if _JWT.fullmatch(value):
        return "jwt"
    if _URL_WITH_PASSWORD.fullmatch(value):
        return "url_with_password"
    if _PEM_PRIVATE_KEY.fullmatch(value.strip()):
        return "private_key"
    return None


_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_BOOLEANS = frozenset({"true", "false", "yes", "no", "on", "off"})
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(
    rf"(?:localhost|(?:{_HOST_LABEL}\.)+[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9]\.?"
    r"|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?"
)
_PATH_ANCHOR = re.compile(r"(?:~|\.{1,2}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[A-Za-z]:)?[\\/]")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._@~+, -]*|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
_VAR_ONLY = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")


_WORD_TOKEN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def _high_entropy(segment: str) -> bool:
    """A long run of mixed case and digits with no separator that does not
    read as CamelCase or digit words reads as key material, not a directory
    name: `Python312` splits into words of 6 and 3 characters, a random key
    into words of about 2."""
    if not (
        len(segment) >= 20
        and not any(ch in "._- " for ch in segment)
        and any(ch.isupper() for ch in segment)
        and any(ch.islower() for ch in segment)
        and any(ch.isdigit() for ch in segment)
    ):
        return False
    words = _WORD_TOKEN.findall(segment)
    return sum(len(w) for w in words) < 3 * len(words)


def _is_single_path(value: str) -> bool:
    if value in ("~", ".", ".."):
        return True
    if not _PATH_ANCHOR.match(value):
        return False
    segments = re.split(r"[\\/]", re.sub(r"^[A-Za-z]:", "", value))
    if _high_entropy("".join(segments)):
        return False
    return all(
        _PATH_SEGMENT.fullmatch(seg) is not None and not _high_entropy(seg) for seg in segments
    )


def is_path(value: str) -> bool:
    """One path, or a PATH-style list where every element is a path or a
    variable reference (`$HOME/bin:$PATH`)."""
    if _is_single_path(value):
        return True
    for sep in (":", ";"):
        parts = [p for p in value.split(sep) if p]
        if len(parts) > 1 and all(_is_single_path(p) or _VAR_ONLY.fullmatch(p) for p in parts):
            return True
    return False


def not_secret_kind(value: str) -> str | None:
    """`empty`, `number`, `boolean`, `path` or `hostname`, or None."""
    stripped = value.strip()
    if not stripped:
        return "empty"
    if _NUMBER.fullmatch(stripped):
        return "number"
    if stripped.lower() in _BOOLEANS:
        return "boolean"
    if is_path(stripped):
        return "path"
    if _HOSTNAME.fullmatch(stripped):
        return "hostname"
    return None


_DYNAMIC = re.compile(r"\$[A-Za-z_{(]|`")
_ENV_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def is_env_reference(value: str) -> bool:
    """The whole value is one braced environment variable reference,
    `${NAME}`, as npm and yarn expand it (`_authToken=${NPM_TOKEN}`)."""
    return _ENV_REFERENCE.fullmatch(value.strip()) is not None


def is_dynamic(value: str) -> bool:
    """A shell expansion or command substitution, not a literal value."""
    return _DYNAMIC.search(value) is not None


def classify_env(name: str, value: str | None) -> tuple[EnvVerdict, str | None]:
    """(verdict, why). `why` is the shape class for a shape match, "name"
    for a name match, the not-secret kind for a not-secret value. `value`
    None means the value is not literal (a shell expansion): name only."""
    if value is not None:
        shape = value_shape(value.strip())
        if shape is not None:
            return EnvVerdict.SECRET, shape
        kind = not_secret_kind(value)
        if kind is not None:
            return EnvVerdict.NOT_SECRET, kind
    if name_suggests_secret(name):
        return EnvVerdict.SECRET, "name"
    return EnvVerdict.UNKNOWN, None


_CATALOG_KEY_PATTERNS = tuple(
    re.compile(spec.content_pattern)
    for spec in DEFAULT_CATALOG.sources
    if spec.exposure and spec.eligibility.pattern is not None
)


def looks_secret_shaped(text: str) -> bool:
    """Would printing `text` as a NAME risk printing a credential? A key or
    a scope parsed out of a file is untrusted: a config keyed by its own
    token must not put the token on screen, nor may a line of a multi-line
    key read as a name. Deliberately loose - the catalog's content patterns,
    not its eligibility, and any high-entropy run - since a false positive
    here only withholds a name."""
    if value_shape(text) is not None or _high_entropy(text):
        return True
    return any(
        pattern.search(text) is not None
        for pattern in (_JWT, _URL_WITH_PASSWORD, _PEM_PRIVATE_KEY, *_CATALOG_KEY_PATTERNS)
    )
