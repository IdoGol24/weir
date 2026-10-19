"""Source 2, Weir's half: the catalog and the assignment detector over the
project tree. (The other half, imported gitleaks and trufflehog results, is
`weir.inventory.scanners`.)

Detectors, all over the decoded text of one file:

- the catalog's key-shaped classes (`github_token`, `openai_api_key`, ...),
  judged by each class's eligibility, so a documented placeholder such as
  AWS's example key is not a credential;
- the catalog's `credential_field` assignment class, including the 0.4.1
  escape-boundary fix, so a value after a JSON `\\n` escape is found;
- an assignment detector for `key = value`, `key: value` and JSON
  `"key": "value"` whose key name suggests a secret, which reaches the
  quoted-key forms `credential_field` cannot;
- standalone shapes: a JWT, a URL with a password, a PEM private key.

Hits that cover the same bytes merge into one credential; the same value
found twice in one file is one credential with two offsets.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from weir.catalog import DEFAULT_CATALOG, Catalog, is_verbatim_eligible
from weir.inventory._scan import Hit, line_of
from weir.inventory._types import NotScannedReason, Reason
from weir.inventory.classify import (
    is_dynamic,
    name_suggests_secret,
    not_secret_kind,
)
from weir.inventory.gitignore import base_rules

MAX_PROJECT_FILE_BYTES = 2 * 1024 * 1024

# Never descended into. `.git` is git's own store; `.weir` holds the map,
# which is source 4, not a project file.
_SKIP_DIRS = frozenset({".git", ".weir"})
# Dependency and build directories: skipped whole and REPORTED as not
# scanned, never silently.
VENDORED_DIRS = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".gradle", "vendor", "target", "dist", "build", ".next",
})

# Files where an unquoted right-hand side is code (an identifier, a call),
# not a value: `password = get_password()` is not a credential.
_CODE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java", ".kt", ".kts",
    ".scala", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".swift", ".m", ".dart",
    ".lua", ".pl", ".r", ".groovy", ".vue", ".svelte",
})

_MIN_VALUE_LEN = 8  # the same floor as the catalog's credential_field class


@dataclass
class ProjectFile:
    path: Path
    rel: str  # project-relative, forward slashes
    git_ignored: bool


@dataclass
class Skipped:
    path: Path
    reason: NotScannedReason


def walk_project(home: Path, project: Path) -> tuple[list[ProjectFile], list[Skipped]]:
    """Every regular file under the project, sorted, with its gitignore state."""
    ignore, project_ignored = base_rules(home, project)
    files: list[ProjectFile] = []
    skipped: list[Skipped] = []
    # (directory, its project-relative path, whether it is ignored)
    stack: list[tuple[Path, str, bool]] = [(project, "", project_ignored)]
    while stack:
        directory, rel_dir, dir_ignored = stack.pop()
        if not dir_ignored:
            gitignore = directory / ".gitignore"
            try:
                ignore.add(rel_dir, gitignore.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            skipped.append(Skipped(directory, NotScannedReason.UNREADABLE))
            continue
        subdirs: list[tuple[Path, str, bool]] = []
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            path = Path(entry.path)
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                # A symlinked FILE is followed: `.env -> ~/secrets/app.env`
                # is a credential the agent reaches through the project.
                is_file = entry.is_file()
                is_dir_link = entry.is_symlink() and entry.is_dir()
            except OSError:
                skipped.append(Skipped(path, NotScannedReason.UNREADABLE))
                continue
            if is_dir_link:
                skipped.append(Skipped(path, NotScannedReason.SYMLINKED_DIR))
                continue
            ignored = dir_ignored or ignore.ignored(rel, is_dir=is_dir)
            if is_dir:
                if entry.name in _SKIP_DIRS:
                    continue
                if entry.name in VENDORED_DIRS:
                    skipped.append(Skipped(path, NotScannedReason.VENDORED_DIR))
                    continue
                subdirs.append((path, rel, ignored))
            elif is_file:
                files.append(ProjectFile(path, rel, ignored))
        stack.extend(reversed(subdirs))
    files.sort(key=lambda f: f.rel)
    return files, skipped


# --- detectors -------------------------------------------------------------

_KEY = r"[A-Za-z_][A-Za-z0-9_.\-]*"
_ASSIGNMENT = re.compile(
    rf"""(?:^|(?<=[\s{{,;(\[])|(?<=\\[ntr]))   # start, a delimiter, or a JSON escape
        (?P<kq>["']?)(?P<key>{_KEY})(?P=kq)    # key, optionally quoted
        [ \t]*(?::=|=>|=|:)[ \t]*              # operator, on the same line
        (?P<val>"(?:[^"\\\n]|\\.)*"            # double-quoted value
            |'[^'\n]*'                         # single-quoted value
            |(?:(?!\\[ntr])[^\s,;'"\]}})])+)   # bare value, stopping at a JSON escape
    """,
    re.X | re.M,
)
_PLACEHOLDER = re.compile(
    r"""(?x)
    \$\{?[A-Za-z_][A-Za-z0-9_]*\}?.*   # $VAR / ${VAR} reference
    | \{\{.*\}\}                        # template
    | <[^>]*>                           # <your-token-here>
    | %\(.*\)s | %[sd]                  # format strings
    | [*xX#.\-_]+                       # masked or filler
    | (?i:none|null|nil|undefined|redacted|changeme|example|placeholder|true|false)
    """
)
_IDENTIFIER_EXPR = re.compile(r"[A-Za-z_$][\w$]*(?:\s*(?:\.|::|->)\s*[A-Za-z_$][\w$]*)*")

_STANDALONE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(
        r"(?:\b|(?<=\\[ntr]))eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    )),
    ("url_with_password", re.compile(
        r"(?:\b|(?<=\\[ntr]))[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"\\]*:[^\s/@'\"\\]+@[^\s'\"\\<>]+"
    )),
    ("private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    )),
)


def _unquote(raw: str) -> tuple[str, int, bool]:
    """(value, offset of the value inside raw, was quoted)."""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1], 1, True
    return raw, 0, False


def _catalog_near_miss(value: str, catalog: Catalog) -> bool:
    """Has the value a catalog class's loose shape but fails its
    eligibility? Then it is that class's placeholder or a masked key
    (`sk-proj-REDACTED...`, AWS's documented example), not a credential."""
    return any(
        spec.exposure
        and spec.eligibility.pattern is not None
        and re.fullmatch(spec.content_pattern, value) is not None
        and not is_verbatim_eligible(value, spec)
        for spec in catalog.sources
    )


def _acceptable(value: str, *, quoted: bool, code: bool) -> bool:
    """Is a value assigned to a secret-named key plausibly the secret?"""
    if len(value) < _MIN_VALUE_LEN or _PLACEHOLDER.fullmatch(value):
        return False
    if _catalog_near_miss(value, DEFAULT_CATALOG):
        return False
    if not_secret_kind(value) is not None:
        return False
    if not quoted and (is_dynamic(value) or value.endswith(("(", "{", "["))):
        return False
    if code and not quoted and (
        _IDENTIFIER_EXPR.fullmatch(value) or "(" in value or "[" in value
    ):
        return False
    return True


def _catalog_hits(text: str, catalog: Catalog, *, code: bool) -> Iterator[Hit]:
    for spec in catalog.sources:
        if not spec.exposure:
            continue
        pattern = re.compile(spec.content_pattern)
        for match in pattern.finditer(text):
            if pattern.groups:
                # credential_field: an assignment, the value in group 1. It
                # has no eligibility floor (triage only), so the inventory
                # applies the assignment detector's value checks instead.
                value = match.group(1) or ""
                if any(re.fullmatch(p, value) for p in spec.eligibility.reject_patterns):
                    continue
                quoted = match.start(1) > 0 and text[match.start(1) - 1] in "'\""
                if not _acceptable(value, quoted=quoted, code=code):
                    continue
                key = match.group(0)[: match.start(1) - match.start(0)].rstrip("'\"=: \t\r\n")
                yield Hit(
                    name=key.split()[-1] if key.split() else spec.name, reason=Reason.NAME,
                    detectors={f"catalog:{spec.name}"}, value=value, spans=[match.span(1)],
                    line=line_of(text, match.start(1)), name_rank=20,
                )
            elif is_verbatim_eligible(match.group(0), spec):
                yield Hit(
                    name=spec.name, reason=Reason.SHAPE, detectors={f"catalog:{spec.name}"},
                    value=match.group(0), spans=[match.span()],
                    line=line_of(text, match.start()), name_rank=30,
                )


def _assignment_hits(text: str, *, code: bool) -> Iterator[Hit]:
    for match in _ASSIGNMENT.finditer(text):
        key = match.group("key")
        if not name_suggests_secret(key):
            continue
        value, inner, quoted = _unquote(match.group("val"))
        if not _acceptable(value, quoted=quoted, code=code):
            continue
        start = match.start("val") + inner
        yield Hit(
            name=key, reason=Reason.NAME, detectors={"assignment"}, value=value,
            spans=[(start, start + len(value))], line=line_of(text, start), name_rank=10,
        )


def _standalone_hits(text: str) -> Iterator[Hit]:
    for name, pattern in _STANDALONE:
        for match in pattern.finditer(text):
            yield Hit(
                name=name, reason=Reason.SHAPE, detectors={f"shape:{name}"},
                value=match.group(0), spans=[match.span()], line=line_of(text, match.start()),
                name_rank=40,
            )


def assignment_values(text: str, key: str) -> list[Hit]:
    """Every non-empty value assigned to exactly this key, whatever its
    name suggests: the map's `field`, which a person approved."""
    hits: list[Hit] = []
    for match in _ASSIGNMENT.finditer(text):
        if match.group("key") != key:
            continue
        value, inner, _ = _unquote(match.group("val"))
        if value:
            start = match.start("val") + inner
            hits.append(Hit(
                name=key, reason=Reason.MAP, detectors={"map"}, value=value,
                spans=[(start, start + len(value))], line=line_of(text, start),
            ))
    return hits


def merge_hits(hits: list[Hit]) -> list[Hit]:
    """Hits whose spans overlap are one credential: the value comes from the
    hit with the widest span among the shape detectors, else the first; the
    name from the best-ranked namer. Then equal values merge, keeping every
    span as an offset."""
    groups: list[list[Hit]] = []
    for hit in sorted(hits, key=lambda h: (h.spans[0][0], -h.spans[0][1])):
        span = hit.spans[0]
        if groups and span[0] < max(h.spans[0][1] for h in groups[-1]):
            groups[-1].append(hit)
        else:
            groups.append([hit])

    merged: list[Hit] = []
    for group in groups:
        namer = min(group, key=lambda h: h.name_rank)
        shaped = [h for h in group if h.reason is Reason.SHAPE]
        carrier = max(shaped, key=lambda h: h.spans[0][1] - h.spans[0][0]) if shaped else namer
        detectors = {d for h in group for d in h.detectors}
        merged.append(Hit(
            name=namer.name, reason=carrier.reason if shaped else namer.reason,
            detectors=detectors, value=carrier.value, spans=list(carrier.spans),
            line=carrier.line, name_rank=namer.name_rank,
        ))

    by_value: dict[str | None, Hit] = {}
    for hit in merged:
        existing = by_value.get(hit.value)
        if existing is None:
            by_value[hit.value] = hit
            continue
        existing.spans.extend(hit.spans)
        existing.detectors |= hit.detectors
        if hit.name_rank < existing.name_rank:
            existing.name, existing.name_rank = hit.name, hit.name_rank
    return list(by_value.values())


def scan_shapes(text: str, catalog: Catalog = DEFAULT_CATALOG) -> list[Hit]:
    """Credential shapes only, no assignment parsing: the catalog's
    key-shaped classes and the standalone shapes (JWT, URL with a password,
    PEM private key)."""
    hits = [*_catalog_hits(text, catalog, code=False), *_standalone_hits(text)]
    return merge_hits([h for h in hits if h.reason is Reason.SHAPE])


def scan_text(text: str, *, rel: str, catalog: Catalog = DEFAULT_CATALOG) -> list[Hit]:
    code = Path(rel).suffix.lower() in _CODE_SUFFIXES
    hits = [
        *_catalog_hits(text, catalog, code=code),
        *_assignment_hits(text, code=code),
        *_standalone_hits(text),
    ]
    return merge_hits(hits)


__all__ = [
    "MAX_PROJECT_FILE_BYTES",
    "VENDORED_DIRS",
    "assignment_values",
    "ProjectFile",
    "Skipped",
    "merge_hits",
    "scan_shapes",
    "scan_text",
    "walk_project",
]
