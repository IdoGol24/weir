"""Which project files a .gitignore covers, computed locally (no git process).

Claude Code's Grep tool skips gitignored files when it searches a directory,
so an ignored credential file is hidden from that one route and from nothing
else: Read, cat and grep -r still reach it. The inventory therefore scans
ignored files like any other and reports the per-route effect.

Semantics follow gitignore(5): `#` comments, `!` negation, a trailing `/`
for directories only, a pattern with a slash anchored to its .gitignore's
directory, `**` across directories, last match wins, deeper files override
shallower ones, and a file under an ignored directory cannot be re-included.
Sources, lowest precedence first: the global excludes file (core.excludesFile
in <home>/.gitconfig, else <home>/.config/git/ignore), the repository's
.git/info/exclude, then every .gitignore from the repository root down. The
repository root is the nearest directory at or above the project holding
`.git`, so a project that is a subdirectory of a repository gets the rules
above it too, and is wholly ignored when a directory above it is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from weir.inventory._types import Route, RouteStatus


@dataclass(frozen=True)
class _Rule:
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


def _translate(glob: str) -> str:
    """One gitignore glob (no leading/trailing slash) as a regex body."""
    out: list[str] = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("/.*")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            end = glob.find("]", i + 2 if glob[i + 1:i + 2] in ("!", "^") else i + 1)
            if end == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                body = glob[i + 1:end]
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end + 1
        elif ch == "\\" and i + 1 < len(glob):
            out.append(re.escape(glob[i + 1]))
            i += 2
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


def parse_rules(text: str) -> list[_Rule]:
    rules: list[_Rule] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        # Trailing spaces are ignored unless escaped with a backslash.
        while line.endswith(" ") and not line.endswith("\\ "):
            line = line[:-1]
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        if negate:
            line = line[1:]
        elif line.startswith("\\"):
            line = line[1:] if line[1:2] in ("#", "!") else line
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            continue
        anchored = "/" in line
        line = line.lstrip("/")
        body = _translate(line)
        prefix = "" if anchored or line.startswith("**/") else "(?:.*/)?"
        rules.append(_Rule(re.compile(f"{prefix}{body}"), negate, dir_only))
    return rules


@dataclass
class GitIgnore:
    """Rules keyed by the directory (relative to the repository root, "" for
    the root) of the file they came from, kept in precedence order. `prefix`
    is the project's path from the repository root ("" when they are the
    same); `add` and `ignored` take project-relative paths."""

    prefix: str = ""
    _layers: list[tuple[str, list[_Rule]]] = field(default_factory=list[tuple[str, list[_Rule]]])

    def _rooted(self, rel: str) -> str:
        return "/".join(part for part in (self.prefix, rel) if part)

    def add(self, base: str, text: str) -> None:
        self._add_rooted(self._rooted(base), text)

    def _add_rooted(self, base: str, text: str) -> None:
        rules = parse_rules(text)
        if rules:
            self._layers.append((base, rules))

    def ignored(self, rel: str, *, is_dir: bool) -> bool:
        """Is this project-relative path (forward slashes) ignored by the
        rules that apply to it? Does NOT look at its parents: the walker
        stops descending into an ignored directory and marks everything
        below it ignored."""
        return self._ignored_rooted(self._rooted(rel), is_dir=is_dir)

    def _ignored_rooted(self, rel: str, *, is_dir: bool) -> bool:
        verdict = False
        for base, rules in self._layers:
            if base:
                if not rel.startswith(base + "/"):
                    continue
                local = rel[len(base) + 1:]
            else:
                local = rel
            for rule in rules:
                if rule.dir_only and not is_dir:
                    continue
                if rule.regex.fullmatch(local):
                    verdict = not rule.negate
        return verdict


def _excludes_file(home: Path) -> Path:
    try:
        text = (home / ".gitconfig").read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]").strip().lower()
        elif section == "core" and "=" in stripped:
            key, value = stripped.split("=", 1)
            if key.strip().lower() == "excludesfile":
                value = value.strip().strip('"')
                if value.startswith("~/"):
                    return home / value[2:]
                return Path(value)
    return home / ".config" / "git" / "ignore"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def base_rules(home: Path, project: Path) -> tuple[GitIgnore, bool]:
    """The rules that apply before the project's own .gitignore files, and
    whether the project itself sits in an ignored directory."""
    root = next((d for d in (project, *project.parents) if (d / ".git").exists()), project)
    parts = project.relative_to(root).parts
    ignore = GitIgnore(prefix="/".join(parts))
    ignore._add_rooted("", _read(_excludes_file(home)))
    ignore._add_rooted("", _read(root / ".git" / "info" / "exclude"))
    for depth in range(len(parts)):
        above = parts[:depth]
        ignore._add_rooted("/".join(above), _read(root.joinpath(*above, ".gitignore")))
        if ignore._ignored_rooted("/".join(parts[:depth + 1]), is_dir=True):
            return ignore, True
    return ignore, False


# Claude Code tools reference: "Grep respects .gitignore, so gitignored files
# are skipped. To search a gitignored file, Claude passes its path directly."
# No document gives .gitignore any effect on Read or on shell commands.
IGNORED_ROUTES: tuple[Route, ...] = (
    Route(
        route="grep_tool", status=RouteStatus.HIDDEN,
        note="skipped when Grep searches a directory; Grep given the file's path still reads it",
    ),
    Route(route="read_tool", status=RouteStatus.REACHABLE, note=".gitignore has no effect on Read"),
    Route(route="cat", status=RouteStatus.REACHABLE, note="shell commands ignore .gitignore"),
    Route(route="grep_r", status=RouteStatus.REACHABLE, note="grep -r ignores .gitignore"),
)
