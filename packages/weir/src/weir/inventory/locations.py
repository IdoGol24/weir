"""Source 1: the fixed, versioned list of standard credential locations.

Bump LOCATION_LIST_VERSION whenever an entry, a path, a format or a field
list changes: the inventory report carries it, so a consumer can tell which
list produced a "nothing found".

Paths are relative to the home directory the caller passes, never the real
home of the process. An entry may also name environment variables that move
the file (`AWS_SHARED_CREDENTIALS_FILE`, `DOCKER_CONFIG`, `KUBECONFIG`); they
are read from the launch environment being inventoried, and the default path
is checked as well, because a file the SDK no longer reads is still a file
the agent can read.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import msgspec

from weir.inventory._scan import Hit, absolute, find_encoded, line_of
from weir.inventory._types import Reason, ValueState
from weir.inventory.classify import (
    is_env_reference,
    name_suggests_secret,
    not_secret_kind,
    value_shape,
)

LOCATION_LIST_VERSION = 2


@dataclass(frozen=True)
class StandardLocation:
    id: str
    # Home-relative, forward slashes; `*` globs one path segment.
    paths: tuple[str, ...]
    format: str
    # Lowercased field names that ARE the credential in this format. Any
    # other field still counts when its name or its value's shape says so.
    fields: frozenset[str] = frozenset()
    # Lowercased field names known NOT to be secret although the name may
    # suggest one (Google's `token_uri`): judged by their value's shape only.
    plain_fields: frozenset[str] = frozenset()
    # Variables naming the file itself.
    env_files: tuple[str, ...] = ()
    # (variable naming a directory, path of the file inside it).
    env_dirs: tuple[tuple[str, str], ...] = ()
    # Variables holding an os.pathsep-separated list of files (KUBECONFIG).
    env_path_lists: tuple[str, ...] = ()


_AWS_FIELDS = frozenset({
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_security_token",
})
_GOOGLE_FIELDS = frozenset({"client_secret", "refresh_token", "private_key", "private_key_id"})
# The endpoint and type fields of Google credential files (authorized user,
# service account, external account): URLs and labels, never secrets.
_GOOGLE_PLAIN_FIELDS = frozenset({
    "token_uri", "token_url", "token_info_url", "auth_uri", "auth_provider_x509_cert_url",
    "client_x509_cert_url", "service_account_impersonation_url", "subject_token_type",
    "universe_domain", "type",
})
_GCLOUD_DIRS = (".config/gcloud", "AppData/Roaming/gcloud")

STANDARD_LOCATIONS: tuple[StandardLocation, ...] = (
    StandardLocation(
        "aws_credentials", (".aws/credentials",), "ini", _AWS_FIELDS,
        env_files=("AWS_SHARED_CREDENTIALS_FILE",),
    ),
    StandardLocation(
        "aws_config", (".aws/config",), "ini", _AWS_FIELDS, env_files=("AWS_CONFIG_FILE",),
    ),
    StandardLocation(
        "aws_sso_cache", (".aws/sso/cache/*.json",), "json",
        frozenset({"accesstoken", "refreshtoken", "clientsecret"}),
    ),
    StandardLocation(
        "aws_cli_cache", (".aws/cli/cache/*.json",), "json",
        frozenset({"accesskeyid", "secretaccesskey", "sessiontoken"}),
    ),
    StandardLocation(
        "google_application_default_credentials",
        tuple(f"{d}/application_default_credentials.json" for d in _GCLOUD_DIRS),
        "json", _GOOGLE_FIELDS, _GOOGLE_PLAIN_FIELDS,
        env_files=("GOOGLE_APPLICATION_CREDENTIALS",),
        env_dirs=(("CLOUDSDK_CONFIG", "application_default_credentials.json"),),
    ),
    StandardLocation(
        "gcloud_legacy_credentials",
        tuple(f"{d}/legacy_credentials/*/adc.json" for d in _GCLOUD_DIRS),
        "json", _GOOGLE_FIELDS, _GOOGLE_PLAIN_FIELDS,
        env_dirs=(("CLOUDSDK_CONFIG", "legacy_credentials/*/adc.json"),),
    ),
    StandardLocation(
        "gcloud_token_databases",
        tuple(f"{d}/{db}" for d in _GCLOUD_DIRS for db in ("credentials.db", "access_tokens.db")),
        "opaque",
        env_dirs=(("CLOUDSDK_CONFIG", "credentials.db"), ("CLOUDSDK_CONFIG", "access_tokens.db")),
    ),
    StandardLocation(
        "npmrc", (".npmrc",), "npmrc",
        frozenset({"_authtoken", "_auth", "_password", "password"}),
        env_files=("NPM_CONFIG_USERCONFIG", "npm_config_userconfig"),
    ),
    StandardLocation(
        "yarnrc", (".yarnrc.yml",), "yaml", frozenset({"npmauthtoken", "npmauthident"}),
    ),
    StandardLocation(
        "kube_config", (".kube/config",), "yaml",
        frozenset({
            "token", "client-key-data", "password", "id-token", "refresh-token",
            "client-secret", "access-token",
        }),
        env_path_lists=("KUBECONFIG",),
    ),
    StandardLocation(
        "docker_config", (".docker/config.json",), "json",
        frozenset({"auth", "identitytoken", "registrytoken", "password"}),
        env_dirs=(("DOCKER_CONFIG", "config.json"),),
    ),
    StandardLocation(
        "netrc", (".netrc", "_netrc"), "netrc", frozenset({"password", "account"}),
        env_files=("NETRC",),
    ),
    StandardLocation(
        "git_credentials", (".git-credentials", ".config/git/credentials"), "git_credentials",
        env_dirs=(("XDG_CONFIG_HOME", "git/credentials"),),
    ),
    StandardLocation(
        "gh_hosts", (".config/gh/hosts.yml", "AppData/Roaming/GitHub CLI/hosts.yml"), "yaml",
        frozenset({"oauth_token"}),
        env_dirs=(("GH_CONFIG_DIR", "hosts.yml"), ("XDG_CONFIG_HOME", "gh/hosts.yml")),
    ),
    StandardLocation("hub", (".config/hub",), "yaml", frozenset({"oauth_token"})),
    StandardLocation(
        "ssh_private_keys",
        tuple(f".ssh/{k}" for k in (
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
        )),
        "private_key",
    ),
    StandardLocation("pypirc", (".pypirc",), "ini", frozenset({"password"})),
    StandardLocation(
        "cargo_credentials", (".cargo/credentials.toml", ".cargo/credentials"), "toml",
        frozenset({"token"}),
        env_dirs=(("CARGO_HOME", "credentials.toml"), ("CARGO_HOME", "credentials")),
    ),
    StandardLocation(
        "gem_credentials", (".gem/credentials", ".local/share/gem/credentials"), "yaml",
    ),
    StandardLocation(
        "terraform_credentials", (".terraform.d/credentials.tfrc.json",), "json",
        frozenset({"token"}),
    ),
    StandardLocation("pgpass", (".pgpass",), "pgpass", env_files=("PGPASSFILE",)),
    StandardLocation("mysql_options", (".my.cnf",), "ini", frozenset({"password"})),
    StandardLocation("vault_token", (".vault-token",), "token_file"),
    StandardLocation(
        "huggingface_token", (".cache/huggingface/token", ".huggingface/token"), "token_file",
        env_dirs=(("HF_HOME", "token"),),
    ),
    StandardLocation("claude_json", (".claude.json",), "json"),
    StandardLocation(
        "claude_credentials", (".claude/.credentials.json",), "json",
        frozenset({"accesstoken", "refreshtoken"}),
    ),
    StandardLocation(
        "azure_tokens",
        (".azure/msal_token_cache.json", ".azure/accessTokens.json",
         ".azure/service_principal_entries.json"),
        "json", frozenset({"secret", "accesstoken", "refreshtoken", "client_secret"}),
    ),
)


# Shell startup files that can export a variable into the agent's launch
# environment. Home-relative, and part of the versioned list.
STARTUP_FILES: tuple[str, ...] = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin",
    ".config/fish/config.fish", ".cshrc", ".tcshrc",
)


def _expand(raw: str, home: Path) -> Path | None:
    """An override path from the inventoried environment, resolved against
    the GIVEN home. Relative overrides are ignored: they depend on a working
    directory the agent's process may not share."""
    raw = raw.strip()
    if not raw:
        return None
    if raw == "~" or raw.startswith(("~/", "~\\")):
        return home / raw[2:]
    for var in ("$HOME", "${HOME}"):
        if raw.startswith(var + "/"):
            return home / raw[len(var) + 1:]
    path = Path(raw)
    return path if path.is_absolute() else None


def _glob(base: Path, pattern: str) -> list[Path]:
    if "*" not in pattern:
        return [base / pattern]
    return sorted(p for p in base.glob(pattern) if p.is_file())


def candidate_paths(
    location: StandardLocation, home: Path, env: Mapping[str, str]
) -> list[Path]:
    """Every path this entry names, default paths first, normalized and
    deduplicated."""
    found: list[Path] = []
    for rel in location.paths:
        found.extend(_glob(home, rel))
    for var in location.env_files:
        if var in env and (path := _expand(env[var], home)) is not None:
            found.append(path)
    for var, inner in location.env_dirs:
        if var in env and (base := _expand(env[var], home)) is not None:
            found.extend(_glob(base, inner))
    for var in location.env_path_lists:
        for part in env.get(var, "").split(os.pathsep):
            if (path := _expand(part, home)) is not None:
                found.append(path)
    return list(dict.fromkeys(absolute(p) for p in found))


# --- format parsers --------------------------------------------------------
#
# Each parser takes the file text and yields Hits with character spans into
# that text. A parser raises ValueError when the format does not parse; the
# core then reports the file as a whole-file credential AND as undecodable.


_PLAIN_WORD = re.compile(r"[a-z][a-z-]*")


def _judge(location: StandardLocation, field_name: str, value: str) -> Reason | None:
    """Is this field of a standard credential file a credential? A value
    that is wholly an environment reference (`${NPM_TOKEN}`) never is: the
    tool expands it from the environment, where the variable is judged. A
    field the entry names otherwise always is. Any other field needs a
    credential-shaped value, or a secret-suggesting name with a value that is
    not a short or plain word: docker's `credsStore: desktop` names a helper,
    not a secret. A field the entry names as plain is judged by shape only.
    Only an unnamed field is dropped for a number, boolean, path or hostname
    value."""
    if not value.strip() or is_env_reference(value):
        return None
    name = field_name.lower()
    if name in location.fields:
        return Reason.LOCATION
    if not_secret_kind(value) is not None:
        return None
    if value_shape(value.strip()) is not None:
        return Reason.SHAPE
    if (
        name not in location.plain_fields
        and name_suggests_secret(field_name)
        and len(value) >= 8
        and not _PLAIN_WORD.fullmatch(value)
    ):
        return Reason.NAME
    return None


def _hit(
    location: StandardLocation, name: str, value: str, spans: list[tuple[int, int]],
    text: str, reason: Reason, scope: str | None,
) -> Hit:
    return Hit(
        name=name, reason=reason, detectors={f"location:{location.id}"}, value=value,
        spans=spans, line=line_of(text, spans[0][0]) if spans else None, scope=scope,
    )


_INI_SECTION = re.compile(r"^\s*\[([^\]]*)\]")
_INI_PAIR = re.compile(r"^\s*([^=:#;\s][^=:]*?)\s*[=:]\s*(.*?)\s*$")
# npmrc keys carry colons (`//registry.npmjs.org/:_authToken`); only `=` splits.
_NPMRC_PAIR = re.compile(r"^\s*([^=#;\s][^=]*?)\s*=\s*(.*?)\s*$")


def _strip_quotes(value: str, start: int) -> tuple[str, int]:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1], start + 1
    return value, start


def _parse_ini(location: StandardLocation, text: str) -> Iterator[Hit]:
    section: str | None = None
    offset = 0
    pair_pattern = _NPMRC_PAIR if location.format == "npmrc" else _INI_PAIR
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if (sec := _INI_SECTION.match(line)) is not None:
            section = sec.group(1).strip()
        elif (pair := pair_pattern.match(line)) is not None and not line.lstrip().startswith(
            ("#", ";")
        ):
            key = pair.group(1)
            value, vstart = _strip_quotes(pair.group(2), pair.start(2))
            scope = section
            if location.format == "npmrc" and key.startswith("//") and ":" in key:
                # `//registry.npmjs.org/:_authToken` - the registry is the scope
                scope, key = key.rsplit(":", 1)
            reason = _judge(location, key, value)
            if reason is not None and value:
                span = (offset + vstart, offset + vstart + len(value))
                yield _hit(location, key, value, [span], text, reason, scope)
        offset += len(raw_line)


def _item_label(index: int, item: object) -> str:
    """A list item's path segment: its `name` when it has one (kube config
    users, contexts), else its index."""
    if isinstance(item, dict):
        name = cast(dict[object, object], item).get("name")
        if isinstance(name, str):
            return f"[{name}]"
    return f"[{index}]"


def _walk(
    location: StandardLocation, node: object, text: str, path: list[str]
) -> Iterator[Hit]:
    if isinstance(node, dict):
        for key, child in cast(dict[object, object], node).items():
            yield from _walk(location, child, text, [*path, str(key)])
    elif isinstance(node, list):
        for index, child in enumerate(cast(list[object], node)):
            yield from _walk(location, child, text, [*path, _item_label(index, child)])
    elif isinstance(node, str) and path:
        name = path[-1]
        reason = _judge(location, name, node)
        if reason is not None:
            scope = ".".join(path[:-1]) or None
            yield _hit(location, name, node, find_encoded(text, node), text, reason, scope)
    elif node is not None and path and path[-1].lower() in location.fields:
        # A named field the format typed as a number, boolean or date is still
        # the credential, but its source bytes need not be `str(node)` (YAML
        # reads `on` as True): name it, value unread.
        yield Hit(
            name=path[-1], reason=Reason.LOCATION, detectors={f"location:{location.id}"},
            value=None, spans=[], line=None, scope=".".join(path[:-1]) or None,
            missing=ValueState.TYPED_SCALAR,
        )


def _parse_structured(location: StandardLocation, text: str) -> Iterator[Hit]:
    data: object
    try:
        if location.format == "json":
            data = msgspec.json.decode(text.encode("utf-8", "surrogateescape"))
        elif location.format == "yaml":
            data = msgspec.yaml.decode(text.encode("utf-8", "surrogateescape"))
        else:
            data = cast(object, tomllib.loads(text))
    except (msgspec.DecodeError, tomllib.TOMLDecodeError, UnicodeError) as exc:
        raise ValueError(str(exc)) from exc
    yield from _walk(location, data, text, [])


_NETRC_TOKEN = re.compile(r"\S+")


def _parse_netrc(location: StandardLocation, text: str) -> Iterator[Hit]:
    tokens = list(_NETRC_TOKEN.finditer(text))
    machine: str | None = None
    i = 0
    while i < len(tokens):
        word = tokens[i].group(0)
        if word == "machine" and i + 1 < len(tokens):
            machine = tokens[i + 1].group(0)
            i += 2
        elif word == "default":
            machine = "default"
            i += 1
        elif word in ("password", "account") and i + 1 < len(tokens):
            tok = tokens[i + 1]
            yield _hit(
                location, word, tok.group(0), [tok.span()], text, Reason.LOCATION, machine
            )
            i += 2
        elif word == "macdef":
            # A macro runs to the next blank line; its body is not tokens.
            end = text.find("\n\n", tokens[i].end())
            i = next(
                (j for j, t in enumerate(tokens) if end != -1 and t.start() > end), len(tokens)
            )
        else:
            i += 1


_CREDENTIAL_URL = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9+.-]*://)([^:@/\s]*):([^@\s]+)@([^/\s]+)", re.M
)


def _parse_git_credentials(location: StandardLocation, text: str) -> Iterator[Hit]:
    for match in _CREDENTIAL_URL.finditer(text):
        yield _hit(
            location, "password", match.group(3), [match.span(3)], text, Reason.LOCATION,
            match.group(4),
        )


def _parse_pgpass(location: StandardLocation, text: str) -> Iterator[Hit]:
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if line and not line.startswith("#"):
            # host:port:database:user:password, with \: escaping a colon
            fields = re.split(r"(?<!\\):", line, maxsplit=4)
            if len(fields) == 5 and fields[4]:
                start = offset + len(line) - len(fields[4])
                yield _hit(
                    location, "password", fields[4], [(start, start + len(fields[4]))], text,
                    Reason.LOCATION, fields[0],
                )
        offset += len(raw_line)


_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


def _parse_whole_file(location: StandardLocation, text: str) -> Iterator[Hit]:
    if location.format == "private_key":
        blocks = list(_PEM_BLOCK.finditer(text))
        if blocks:
            for block in blocks:
                yield _hit(
                    location, "private_key", block.group(0), [block.span()], text,
                    Reason.LOCATION, None,
                )
            return
    value = text.strip()
    if value:
        start = text.index(value)
        name = "private_key" if location.format == "private_key" else "token"
        yield _hit(
            location, name, value, [(start, start + len(value))], text, Reason.LOCATION, None
        )


def parse_location(location: StandardLocation, text: str) -> list[Hit]:
    parsers = {
        "ini": _parse_ini,
        "npmrc": _parse_ini,
        "json": _parse_structured,
        "yaml": _parse_structured,
        "toml": _parse_structured,
        "netrc": _parse_netrc,
        "git_credentials": _parse_git_credentials,
        "pgpass": _parse_pgpass,
        "token_file": _parse_whole_file,
        "private_key": _parse_whole_file,
    }
    return list(parsers[location.format](location, text))


def render_locations_doc() -> str:
    """The standard location list as markdown, generated so the committed
    doc (docs/inventory-locations.md) cannot drift from the list."""
    lines = [
        f"# Standard credential locations (list v{LOCATION_LIST_VERSION})",
        "",
        "Generated from `weir.inventory.locations.STANDARD_LOCATIONS`; do not edit by hand.",
        "Paths are relative to the home directory given to `weir inventory --home`.",
        "Variables are read from the launch environment being inventoried; the default",
        "paths are checked as well.",
        "",
        "| id | paths | format | credential fields | plain fields | moved by |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for loc in STANDARD_LOCATIONS:
        paths = "<br>".join(f"`~/{p}`" for p in loc.paths)
        fields = ", ".join(f"`{f}`" for f in sorted(loc.fields)) or "-"
        plain = ", ".join(f"`{f}`" for f in sorted(loc.plain_fields)) or "-"
        moved = [f"`{v}`" for v in loc.env_files]
        moved += [f"`{v}`/`{inner}`" for v, inner in loc.env_dirs]
        moved += [f"`{v}` (list)" for v in loc.env_path_lists]
        lines.append(
            f"| {loc.id} | {paths} | {loc.format} | {fields} | {plain} "
            f"| {', '.join(moved) or '-'} |"
        )
    lines += [
        "",
        "Any other field of these files also counts when its name suggests a secret or",
        "its value has a credential shape (docs/inventory.md, \"Classification\"). A plain",
        "field counts only for its value's shape. A value that is wholly an environment",
        "reference (`${NAME}`, `$NAME`) is never a credential at the file: the variable",
        "is judged in the launch environment.",
        "",
        "## Shell startup files",
        "",
        "Read for exported assignments that put a variable into the agent's launch",
        "environment:",
        "",
        ", ".join(f"`~/{f}`" for f in STARTUP_FILES),
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "LOCATION_LIST_VERSION",
    "STANDARD_LOCATIONS",
    "STARTUP_FILES",
    "StandardLocation",
    "candidate_paths",
    "parse_location",
    "render_locations_doc",
]
