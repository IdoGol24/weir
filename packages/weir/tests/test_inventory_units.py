"""Unit behaviour of the inventory's pieces. Credential-shaped values come
from the fake-home fixture module only (the leak test holds every other
inventory test file to that)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import inventory_fakehome as fx
import msgspec
import pytest

from weir._text_safety import plural
from weir.inventory import (
    Credential,
    Inventory,
    InventoryInputError,
    InventoryInputs,
    LocationKind,
    Source,
    ValueState,
    take_inventory,
)
from weir.inventory.classify import (
    EnvVerdict,
    classify_env,
    is_path,
    looks_secret_shaped,
    name_suggests_secret,
    not_secret_kind,
    value_shape,
)
from weir.inventory.environment import judge, parse_env_file, parse_startup_file
from weir.inventory.fingerprint import FingerprintKeyError, fingerprint, load_or_create_key
from weir.inventory.gitignore import GitIgnore
from weir.inventory.locations import STANDARD_LOCATIONS, parse_location
from weir.inventory.project import scan_text
from weir.inventory.scanners import ScannerReportError, load_gitleaks, load_trufflehog
from weir.inventory.text import inventory_lines

# --- classification -------------------------------------------------------


@pytest.mark.parametrize("name", [
    "ACME_API_KEY", "clientSecret", "_authToken", "DB_PASSWORD", "MYSQL_PWD", "STRIPE_KEY",
    "client-key-data", "PRIVATE_KEY_ID", "AWS_ACCESS_KEY_ID", "GH_TOKEN", "SENTRY_DSN",
    "unsealKey", "db_pass", "SESSION_COOKIE", "ssh_passphrase",
])
def test_names_that_suggest_a_secret(name: str) -> None:
    assert name_suggests_secret(name)


@pytest.mark.parametrize("name", [
    "LOG_LEVEL", "PUBLIC_KEY", "STRIPE_PUBLISHABLE_KEY", "KEYBOARD_LAYOUT", "MONKEY_COUNT",
    "HOME", "PATH", "API_HOST", "PASSTHROUGH", "TOKENIZER_MODEL", "author",
])
def test_names_that_do_not(name: str) -> None:
    assert not name_suggests_secret(name)


@pytest.mark.parametrize(("value", "kind"), [
    ("", "empty"), ("  ", "empty"), ("8080", "number"), ("-1.5e3", "number"),
    ("true", "boolean"), ("OFF", "boolean"), ("/usr/local/bin", "path"),
    ("~/keys/adc.json", "path"), ("./build", "path"), ("C:\\Users\\dev", "path"),
    ("$HOME/bin:$PATH", "path"), ("/usr/bin:/bin", "path"),
    ("api.acme.example", "hostname"), ("localhost:5432", "hostname"), ("10.0.0.1", "hostname"),
])
def test_values_that_are_not_secrets(value: str, kind: str) -> None:
    assert not_secret_kind(value) == kind


_WINDOWS_PYTHON = "C:\\Users\\Dev\\AppData\\Local\\Programs\\Python\\Python312"
_XCODE = "/Applications/Xcode15/Contents/Developer"


@pytest.mark.parametrize("value", [
    _WINDOWS_PYTHON, _XCODE, f"/usr/bin:{_XCODE}:/bin", f"C:\\Windows;{_WINDOWS_PYTHON}",
])
def test_mixed_case_paths_with_digits_are_paths(value: str) -> None:
    assert is_path(value)
    assert classify_env("PATH", value) == (EnvVerdict.NOT_SECRET, "path")


@pytest.mark.parametrize(
    "value", [fx.AWS_SECRET_S02_ROTATED, fx.AWS_SECRET_S02_SPLIT], ids=["rotated", "split"]
)
def test_a_key_that_starts_with_a_slash_is_not_a_path(value: str) -> None:
    assert value.startswith("/")
    assert not is_path(value)
    assert classify_env("AWS_SECRET_ACCESS_KEY", value) == (EnvVerdict.SECRET, "name")


# Ids name the shape, never the value: a test id lands in logs and reports.
@pytest.mark.parametrize(("value", "shape"), [
    pytest.param(value, shape, id=shape) for value, shape in [
        (fx.GITHUB_S04, "github_token"), (fx.OPENAI_S07, "openai_api_key"),
        (fx.ANTHROPIC_S10, "anthropic_api_key"), (fx.AWS_ID_S01, "aws_access_key_id"),
        (fx.JWT_S16, "jwt"), (fx.DATABASE_URL_S13, "url_with_password"),
        (fx.SSH_KEY, "private_key"),
    ]
])
def test_value_shapes(value: str, shape: str) -> None:
    assert value_shape(value) == shape


def test_documented_placeholders_have_no_shape() -> None:
    assert value_shape(fx.PLACEHOLDER_AWS_EXAMPLE) is None
    assert value_shape(fx.PLACEHOLDER_OPENAI_REDACTED) is None


def test_env_precedence_shape_then_not_secret_then_name() -> None:
    assert classify_env("ACME_UPLINK", fx.OPENAI_S09) == (EnvVerdict.SECRET, "openai_api_key")
    assert classify_env("TOKEN_TTL", "3600") == (EnvVerdict.NOT_SECRET, "number")
    assert classify_env("GOOGLE_APPLICATION_CREDENTIALS", "/k/adc.json")[0] is (
        EnvVerdict.NOT_SECRET
    )
    assert classify_env("ACME_DEPLOY_TOKEN", fx.MARKER_USERMCP) == (EnvVerdict.SECRET, "name")
    assert classify_env("BUILD_FLAVOR", fx.MARKER_DOTENVLOCAL) == (EnvVerdict.UNKNOWN, None)
    assert classify_env("OPENAI_API_KEY", None) == (EnvVerdict.SECRET, "name")


def test_credential_shaped_names_are_withheld() -> None:
    assert looks_secret_shaped(fx.GITHUB_S05)
    assert looks_secret_shaped(f"prefix-{fx.AWS_ID_S02}")
    assert not looks_secret_shaped("ACME_API_KEY")


def test_a_credential_shaped_key_is_never_printed(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / ".config/gh/hosts.yml").write_text(
        f"github.com:\n    {fx.GITHUB_S06}: {fx.GITHUB_S04}\n"
    )
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    gh = [c for c in report.credentials if c.location.display == "~/.config/gh/hosts.yml"]
    assert [c.name for c in gh] == ["[withheld: credential-shaped]"]


# --- gitignore -------------------------------------------------------------


def _ignore(rules: str, base: str = "") -> GitIgnore:
    ignore = GitIgnore()
    ignore.add(base, rules)
    return ignore


@pytest.mark.parametrize(("rules", "path", "is_dir", "ignored"), [
    (".env*\n", ".env", False, True),
    (".env*\n", "deep/.env.local", False, True),
    (".env*\n!.env.example\n", ".env.example", False, False),
    ("config/prod/\n", "config/prod", True, True),
    ("config/prod/\n", "config/prod", False, False),
    ("/build\n", "build", True, True),
    ("/build\n", "src/build", True, False),
    ("docs/*.md\n", "docs/a.md", False, True),
    ("docs/*.md\n", "docs/x/a.md", False, False),
    ("**/secrets.yaml\n", "a/b/secrets.yaml", False, True),
    ("logs/**\n", "logs/x/y.log", False, True),
    ("a/**/z\n", "a/b/c/z", False, True),
    ("\\#notes\n", "#notes", False, True),
    ("# comment\n", "# comment", False, False),
    ("*.ke[yz]\n", "id.key", False, True),
    ("*.ke[!yz]\n", "id.key", False, False),
])
def test_gitignore_semantics(rules: str, path: str, is_dir: bool, ignored: bool) -> None:
    assert _ignore(rules).ignored(path, is_dir=is_dir) is ignored


def test_nested_gitignore_applies_below_its_directory_only() -> None:
    ignore = _ignore("*.cfg\n", base="sub")
    assert ignore.ignored("sub/a.cfg", is_dir=False)
    assert not ignore.ignored("a.cfg", is_dir=False)
    assert not ignore.ignored("subway/a.cfg", is_dir=False)


def test_an_ignored_directory_hides_a_reincluded_file(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    gitignore = fake.project / ".gitignore"
    gitignore.write_text(gitignore.read_text() + "!config/prod/secrets.yaml\n")
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    assert "./config/prod/secrets.yaml" in {g.display for g in report.git_ignored}


def test_global_excludes_file_from_gitconfig(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / ".gitconfig").write_text("[core]\n\texcludesFile = ~/.gitignore_global\n")
    (fake.home / ".gitignore_global").write_text("*.cfg\n")
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    assert "./src/legacy.cfg" not in {g.display for g in report.git_ignored}  # no credential
    vault = [c for c in report.credentials if c.location.display == "./src/vault.go"]
    assert vault and not any(c.git_ignored for c in vault)
    (fake.project / "src/legacy.cfg").write_text(f"api_key = {fx.MARKER_DOTENV}\n")
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    assert "./src/legacy.cfg" in {g.display for g in report.git_ignored}


# --- environment ------------------------------------------------------------


def test_env_file_forms() -> None:
    text = (
        "# comment\n"
        f"export ACME_DEPLOY_TOKEN='{fx.MARKER_USERMCP}'\n"
        f'ACME_UPLINK="{fx.OPENAI_S09}"\n'
        "EMPTY=\n"
        "not a line\n"
    )
    entries = parse_env_file(text)
    assert [(e.name, e.line) for e in entries] == [
        ("ACME_DEPLOY_TOKEN", 2), ("ACME_UPLINK", 3), ("EMPTY", 4),
    ]
    same = [e.value for e in entries] == [fx.MARKER_USERMCP, fx.OPENAI_S09, ""]
    assert same
    for entry in entries[:2]:
        assert entry.span is not None and entry.value is not None
        assert text[entry.span[0]:entry.span[1]] == entry.value


def test_env_file_quoted_value_across_lines() -> None:
    text = f'APP_PRIVATE_KEY="{fx.SA_PRIVATE_KEY}"\nLOG_LEVEL=info\n'
    key, level = parse_env_file(text)
    whole = key.value == fx.SA_PRIVATE_KEY
    assert (key.name, whole, key.line) == ("APP_PRIVATE_KEY", True, 1)
    assert key.span is not None and text[key.span[0]:key.span[1]] == key.value
    assert (level.name, level.line) == ("LOG_LEVEL", fx.SA_PRIVATE_KEY.count("\n") + 2)


def test_env_file_unquoted_value_ends_before_a_comment() -> None:
    text = (
        f"A_TOKEN={fx.MARKER_USERMCP}   # rotated\n"
        "PORT=3000 # dev\n"
        "B_MODE=x#y\n"
        f'C_TOKEN="{fx.MARKER_PROJMCP} # kept"\n'
        "D_MODE=v  \n"
    )
    entries = {e.name: e for e in parse_env_file(text)}
    exact = entries["A_TOKEN"].value == fx.MARKER_USERMCP
    kept = entries["C_TOKEN"].value == f"{fx.MARKER_PROJMCP} # kept"
    assert exact and kept
    assert [entries[n].value for n in ("PORT", "B_MODE", "D_MODE")] == ["3000", "x#y", "v"]
    for entry in entries.values():
        assert entry.span is not None and text[entry.span[0]:entry.span[1]] == entry.value


def test_env_file_pem_block_runs_to_its_end_line() -> None:
    text = f"APP_PRIVATE_KEY={fx.SA_PRIVATE_KEY}SIGNING_KEY={fx.SSH_KEY}\nLOG_LEVEL=info\n"
    entries = parse_env_file(text)
    assert [(e.name, e.line) for e in entries] == [
        ("APP_PRIVATE_KEY", 1), ("SIGNING_KEY", 4), ("LOG_LEVEL", 7),
    ]
    whole = [e.value for e in entries[:2]] == [fx.SA_PRIVATE_KEY.rstrip(), fx.SSH_KEY]
    assert whole
    for entry in entries:
        assert entry.span is not None and text[entry.span[0]:entry.span[1]] == entry.value


def test_an_unclosed_pem_block_is_the_rest_of_the_file_and_a_secret() -> None:
    head, body, _ = fx.SA_PRIVATE_KEY.splitlines()
    text = f"APP_PEM={head}\n{body}\nLOG_LEVEL=info\n"
    [entry] = parse_env_file(text)
    assert entry.name == "APP_PEM" and entry.span is not None
    rest = entry.value == text[entry.span[0]:].rstrip()
    assert rest
    assert judge(entry).verdict is EnvVerdict.SECRET


def test_env_file_nul_separated() -> None:
    text = f"ACME_DEPLOY_TOKEN={fx.MARKER_USERMCP}\0MULTI=a\nb\0"
    entries = parse_env_file(text)
    assert [e.name for e in entries] == ["ACME_DEPLOY_TOKEN", "MULTI"]
    assert entries[1].value == "a\nb"


def test_startup_file_forms() -> None:
    text = (
        f"export A_TOKEN={fx.MARKER_USERMCP} B_SECRET='{fx.MARKER_PROJMCP}'\n"
        f"declare -x C_PASSWORD=\"{fx.MARKER_DOTENV}\"\n"
        f"setenv D_TOKEN {fx.MARKER_PRODYAML}\n"
        f"set -gx E_TOKEN {fx.MARKER_AWSCREDS}\n"
        f"set -g F_TOKEN {fx.MARKER_AWSCREDS}\n"
        f"G_TOKEN={fx.MARKER_DOTENVLOCAL}; export G_TOKEN\n"
        'export H_TOKEN="$(pass show h)"\n'
        "export I_DIR=\"$HOME/x\"\n"
        f"J_TOKEN={fx.MARKER_DOTENVLOCAL}\n"
    )
    entries = {e.name: e for e in parse_startup_file(text)}
    assert set(entries) == {
        "A_TOKEN", "B_SECRET", "C_PASSWORD", "D_TOKEN", "E_TOKEN", "G_TOKEN", "H_TOKEN",
        "I_DIR", "J_TOKEN", "F_TOKEN",
    }
    assert entries["H_TOKEN"].value is None
    assert entries["I_DIR"].value is None and entries["I_DIR"].expansion == "$HOME/x"
    assert entries["G_TOKEN"].exported and not entries["J_TOKEN"].exported
    # fish `set -g` without -x is a shell variable, not an export.
    assert not entries["F_TOKEN"].exported
    for entry in entries.values():
        if entry.value is not None and entry.span is not None:
            assert text[entry.span[0]:entry.span[1]] == entry.value, entry.name


def test_startup_file_commands_after_a_separator() -> None:
    text = (
        f'[ -n "$PS1" ] && export A_TOKEN={fx.MARKER_USERMCP}\n'
        f"cd ~; export B_TOKEN={fx.MARKER_PROJMCP}\n"
        f"export C_MODE=1; export D_TOKEN={fx.MARKER_DOTENV} || true\n"
        f"if true; then export E_TOKEN={fx.MARKER_PRODYAML}; fi\n"
        f"true && F_TOKEN={fx.MARKER_AWSCREDS}; true && export F_TOKEN\n"
        f"echo 'x; export G_TOKEN={fx.MARKER_DOTENVLOCAL}' # ; export H_TOKEN=1\n"
    )
    entries = {e.name: e for e in parse_startup_file(text)}
    assert set(entries) == {"A_TOKEN", "B_TOKEN", "C_MODE", "D_TOKEN", "E_TOKEN", "F_TOKEN"}
    assert all(e.exported for e in entries.values())
    assert [entries[n].line for n in sorted(entries)] == [1, 2, 3, 3, 4, 5]
    for entry in entries.values():
        assert entry.span is not None and entry.value is not None
        assert text[entry.span[0]:entry.span[1]] == entry.value, entry.name


def test_an_export_after_a_separator_is_an_environment_credential(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / ".bash_profile").write_text(
        f'[ -n "$PS1" ] && export LATE_TOKEN={fx.MARKER_DOTENV}\n'
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    [cred] = [c for c in result.report.credentials if c.location.display == "~/.bash_profile"]
    assert (cred.name, cred.source, cred.location.line) == ("LATE_TOKEN", "environment", 1)
    [record] = [r for r in result.store.records if r.credential_id == cred.id]
    data = (fake.home / ".bash_profile").read_bytes()
    assert [data[s:e] for s, e in record.offsets] == [fx.MARKER_DOTENV.encode()]


def test_a_quoted_startup_file_value_runs_across_lines() -> None:
    cert = "\n".join(
        ["-----BEGIN CERTIFICATE-----", fx.SSH_KEY.splitlines()[1], "-----END CERTIFICATE-----"]
    )
    text = (
        "# don't read this apostrophe as a quote\n"
        f'export CA_CERT="{cert}"\n'
        f"export SIGNING_KEY='{fx.SSH_KEY}'\n"
        "export LOG_LEVEL=info\n"
    )
    entries = parse_startup_file(text)
    assert [(e.name, e.line) for e in entries] == [
        ("CA_CERT", 2), ("SIGNING_KEY", 5), ("LOG_LEVEL", 8),
    ]
    whole = [e.value for e in entries[:2]] == [cert, fx.SSH_KEY]
    assert whole
    for entry in entries:
        assert entry.span is not None and text[entry.span[0]:entry.span[1]] == entry.value
    assert judge(entries[0]).verdict is EnvVerdict.UNKNOWN
    assert judge(entries[1]).verdict is EnvVerdict.SECRET


def test_a_mixed_quote_word_never_gets_a_wrong_offset() -> None:
    text = 'export A_TOKEN=abc"defghij"\nexport B_TOKEN="abc"\n'
    first, second = parse_startup_file(text)
    assert (first.value, first.span) == ("abcdefghij", None)
    assert second.span is not None and text[second.span[0]:second.span[1]] == "abc"


def test_unexported_secret_in_a_startup_file_is_a_credential(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / ".bash_profile").write_text(
        f"LOCAL_TOKEN={fx.MARKER_DOTENV}\nLOCAL_NOTE={fx.MARKER_PRODYAML}\n"
    )
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    names = {c.name for c in report.credentials if c.location.display == "~/.bash_profile"}
    assert names == {"LOCAL_TOKEN"}
    # An unexported unknown is not an environment variable at all.
    assert "LOCAL_NOTE" not in {e.name for e in report.env_unknown}


def _launch_env_records(report: Inventory) -> list[Credential]:
    return [c for c in report.credentials if c.location.kind is LocationKind.LAUNCH_ENV]


def test_an_env_file_inside_the_project_is_a_project_file_and_the_launch_env(
    tmp_path: Path,
) -> None:
    fake = fx.build(tmp_path)
    dotenv = fake.project / ".env"
    with dotenv.open("a") as handle:
        # under the project floor, a secret by name; the comment is not the value
        handle.write("SHORT_TOKEN=abc12x  # rotated\n")
    plain = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    launched = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key, env_file=dotenv,
    ))

    def unlinked(creds: list[Credential]) -> list[Credential]:
        return [msgspec.structs.replace(c, same_value_as=[]) for c in creds]

    launch = _launch_env_records(launched.report)
    rest = [c for c in launched.report.credentials if c not in launch]
    assert unlinked(rest) == unlinked(plain.report.credentials)
    assert {c.name for c in launch} == {"ACME_API_KEY", "OPENAI_API_KEY", "SHORT_TOKEN"}
    assert all(
        c.source is Source.ENVIRONMENT and c.location.path == dotenv.as_posix() for c in launch
    )
    at_env = {c.name: c for c in rest if c.location.display == "./.env"}
    assert at_env and all(c.git_ignored for c in at_env.values())
    linked = [c for c in launch if c.name in at_env]
    assert {c.name for c in linked} == {"ACME_API_KEY", "OPENAI_API_KEY"}
    for cred in linked:
        assert at_env[cred.name].id in cred.same_value_as
        assert cred.id in at_env[cred.name].same_value_as
    [short] = [c for c in launch if c.name == "SHORT_TOKEN"]
    assert short.same_value_as == []
    data = dotenv.read_bytes()
    [record] = [r for r in launched.store.records if r.credential_id == short.id]
    assert [data[s:e] for s, e in record.offsets] == [b"abc12x"]
    assert launched.report.counts.distinct_values == plain.report.counts.distinct_values + 1
    assert launched.report.git_ignored == plain.report.git_ignored
    plain_records = {r.credential_id: r for r in plain.store.records}
    assert {
        r.credential_id: r for r in launched.store.records if r.credential_id in plain_records
    } == plain_records
    [acme] = [c for c in linked if c.name == "ACME_API_KEY"]
    [row] = [r for r in _screen_rows(launched.report, "launch env") if "ACME_API_KEY" in r]
    assert row.endswith(f"(same value as {plural(len(acme.same_value_as), 'other')})")


def test_a_multi_line_quoted_key_in_a_project_env_file_is_recorded_whole(
    tmp_path: Path,
) -> None:
    key = fx.SA_PRIVATE_KEY.rstrip()
    fake = fx.build(tmp_path)
    dotenv = fake.project / ".env"
    dotenv.write_text(f'APP_PRIVATE_KEY="{key}"\nLOG_LEVEL=info\n')
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key, env_file=dotenv,
    ))
    [launch] = _launch_env_records(result.report)
    assert (launch.name, launch.location.line) == ("APP_PRIVATE_KEY", 1)
    [pem] = [
        c for c in result.report.credentials
        if c.location.display == "./.env" and "shape:private_key" in c.detectors
    ]
    assert launch.same_value_as == [pem.id] and pem.same_value_as == [launch.id]
    data = dotenv.read_bytes()
    for cred in (launch, pem):
        [record] = [r for r in result.store.records if r.credential_id == cred.id]
        whole = [data[s:e] for s, e in record.offsets] == [key.encode()]
        assert whole, cred.source
    launch_unknown = [
        e.name for e in result.report.env_unknown if e.location.kind is LocationKind.LAUNCH_ENV
    ]
    assert launch_unknown == ["LOG_LEVEL"]


def test_two_variables_holding_one_value_in_a_project_env_file_stay_two_records(
    tmp_path: Path,
) -> None:
    fake = fx.build(tmp_path)
    dotenv = fake.project / ".env"
    dotenv.write_text(
        f"DATABASE_URL={fx.DATABASE_URL_S14}\nDIRECT_URL={fx.DATABASE_URL_S14}\n"
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key, env_file=dotenv,
    ))
    launch = _launch_env_records(result.report)
    assert [(c.name, c.location.line) for c in launch] == [("DATABASE_URL", 1), ("DIRECT_URL", 2)]
    [project] = [c for c in result.report.credentials if c.location.display == "./.env"]
    linked = [*launch, project]
    ids = {c.id for c in linked}
    for cred in linked:
        assert cred.same_value_as == sorted(ids - {cred.id})

    data = dotenv.read_bytes()
    records = {r.credential_id: r for r in result.store.records if r.credential_id in ids}
    assert len({r.fingerprint for r in records.values()}) == 1
    for cred in launch:
        offsets = records[cred.id].offsets
        assert [data[s:e] for s, e in offsets] == [fx.DATABASE_URL_S14.encode()]
        assert data.count(b"\n", 0, offsets[0][0]) + 1 == cred.location.line


# --- standard formats -------------------------------------------------------


def _location(location_id: str):
    return next(loc for loc in STANDARD_LOCATIONS if loc.id == location_id)


def test_netrc_with_a_macro() -> None:
    text = (
        "machine a.example login u password "
        f"{fx.MARKER_DOTENV}\n"
        "macdef init\npassword not-this-one\n\n"
        f"default login x password {fx.MARKER_PROJMCP}\n"
    )
    hits = parse_location(_location("netrc"), text)
    assert [(h.scope, h.name) for h in hits] == [("a.example", "password"), ("default", "password")]


def test_pgpass_and_cargo_and_token_file() -> None:
    pg = parse_location(_location("pgpass"), f"db.example:5432:*:app:{fx.MARKER_DOTENV}\n")
    assert [(h.scope, h.value == fx.MARKER_DOTENV) for h in pg] == [("db.example", True)]
    cargo = parse_location(
        _location("cargo_credentials"), f'[registry]\ntoken = "{fx.GITHUB_S04}"\n'
    )
    assert [(h.scope, h.name) for h in cargo] == [("registry", "token")]
    token = parse_location(_location("vault_token"), f"\n{fx.GITHUB_S19}\n\n")
    assert [h.line for h in token] == [2]


def test_a_field_the_location_names_is_a_credential_whatever_its_value() -> None:
    value = fx.MARKER_DOTENV_DECIMAL
    assert not_secret_kind(value) == "number"
    hits = parse_location(
        _location("aws_credentials"), f"[default]\naws_secret_access_key = {value}\n"
    )
    assert [(h.scope, h.name, h.value == value) for h in hits] == [
        ("default", "aws_secret_access_key", True)
    ]


def _screen_rows(report: Inventory, display: str) -> list[str]:
    """The credential rows (indented four spaces) at this location."""
    return [
        line for line in inventory_lines(report, unknown_list_path=None)
        if line.startswith("    ") and f" {display}" in line
    ]


@pytest.mark.parametrize("value", [fx.MARKER_DOTENV_DECIMAL, "on", "no", "true", "2024-05-01"])
def test_a_named_field_with_a_typed_scalar_is_a_credential_without_a_value(
    tmp_path: Path, value: str,
) -> None:
    text = f"users:\n- name: ci\n  user:\n    password: {value}\n"
    hits = parse_location(_location("kube_config"), text)
    assert [(h.scope, h.name, h.value) for h in hits] == [("users.[ci].user", "password", None)]
    fake = fx.build(tmp_path)
    (fake.home / ".kube/config").write_text(text)
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    kube = [c for c in report.credentials if c.location.display == "~/.kube/config"]
    assert [(c.name, c.value_state) for c in kube] == [("password", ValueState.TYPED_SCALAR)]
    [row] = _screen_rows(report, "~/.kube/config")
    assert row.endswith("(value typed as a non-string)")


@pytest.mark.parametrize(("location_id", "text"), [
    ("docker_config", '{"auths": {"r.example": {"auth": true}}}'),
    ("docker_config", '{"auths": {"r.example": {"password": 12.5}}}'),
    ("cargo_credentials", "[registry]\ntoken = 2024-05-01\n"),
    ("cargo_credentials", "[registry]\ntoken = false\n"),
])
def test_typed_scalars_of_named_fields_in_json_and_toml(location_id: str, text: str) -> None:
    hits = parse_location(_location(location_id), text)
    assert [(h.value, h.missing) for h in hits] == [(None, ValueState.TYPED_SCALAR)]


def test_a_typed_scalar_of_an_unnamed_field_is_not_a_credential() -> None:
    text = "users:\n- name: ci\n  user:\n    insecure: true\n    retries: 3\n"
    assert parse_location(_location("kube_config"), text) == []


def test_undecodable_standard_file_is_still_reported(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / ".kube/config").write_text("users: [unclosed\n  - token: x\n")
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    kube = [c for c in report.credentials if c.location.display == "~/.kube/config"]
    assert [(c.name, c.value_state.value) for c in kube] == [("config", "absent")]
    [row] = _screen_rows(report, "~/.kube/config")
    assert row.endswith("(whole file)")
    assert ("~/.kube/config", "undecodable") in {
        (n.display, n.reason.value) for n in report.not_scanned
    }


def test_override_variables_move_standard_files(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    moved = fake.home / "alt/docker"
    moved.mkdir(parents=True)
    (moved / "config.json").write_text(json.dumps({"auths": {"r.example": {
        "auth": fx.DOCKER_AUTH,
    }}}))
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
        process_env={"DOCKER_CONFIG": "~/alt/docker"},
    )).report
    assert "~/alt/docker/config.json" in {c.location.display for c in report.credentials}


# --- project detectors --------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_files_are_followed_and_symlinked_dirs_reported(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    (fake.home / "secrets").mkdir()
    (fake.home / "secrets/app.env").write_text(f"APP_TOKEN={fx.MARKER_DOTENV}\n")
    (fake.project / "linked.env").symlink_to(fake.home / "secrets/app.env")
    (fake.project / "linked-dir").symlink_to(fake.home / "secrets", target_is_directory=True)
    report = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    )).report
    linked = [c.name for c in report.credentials if c.location.display == "./linked.env"]
    assert linked == ["APP_TOKEN"]
    assert ("./linked-dir", "symlinked_dir") in {
        (n.display, n.reason.value) for n in report.not_scanned
    }


def test_code_references_are_not_credentials() -> None:
    text = (
        "password = get_password()\n"
        "token = settings.API_TOKEN\n"
        "secret = os.environ['X']\n"
        'api_key: str = ""\n'
    )
    assert scan_text(text, rel="src/app.py") == []


def test_quoted_secret_in_code_is_a_credential() -> None:
    hits = scan_text(f'secret = "{fx.MARKER_DOTENV}"\n', rel="src/app.py")
    assert [h.name for h in hits] == ["secret"]


def test_same_value_twice_is_one_credential_with_two_offsets() -> None:
    text = f"API_TOKEN={fx.MARKER_DOTENV}\nOTHER_TOKEN={fx.MARKER_DOTENV}\n"
    hits = scan_text(text, rel=".env")
    assert len(hits) == 1 and len(hits[0].spans) == 2


# --- scanners -------------------------------------------------------------------


def test_scanner_errors_never_quote_the_report(tmp_path: Path) -> None:
    gitleaks = tmp_path / "g.json"
    gitleaks.write_text(f'[{{"RuleID": "x", "Secret": 5, "Match": "{fx.MARKER_DOTENV}"}}]')
    with pytest.raises(ScannerReportError) as exc:
        load_gitleaks(gitleaks, tmp_path)
    assert fx.MARKER_DOTENV[:6] not in str(exc.value)
    truffle = tmp_path / "t.jsonl"
    truffle.write_text(f'{{"DetectorName": "x"}}\n{{"Raw": "{fx.MARKER_DOTENV}"}}\n')
    with pytest.raises(ScannerReportError) as exc:
        load_trufflehog(truffle, tmp_path)
    assert "line 2" in str(exc.value)
    assert fx.MARKER_DOTENV[6:12] not in str(exc.value)


# --- map ------------------------------------------------------------------------


@pytest.mark.parametrize("body", [
    "version: 2\n",
    "version: 1\ncredentials:\n  - path: a\n    feild: x\n",
    "version: 1\nenv:\n  fine: BUILD\n",
    "version: [1\n",
])
def test_an_invalid_map_is_an_input_error(tmp_path: Path, body: str) -> None:
    fake = fx.build(tmp_path)
    (fake.project / ".weir/reach.yml").write_text(body)
    with pytest.raises(InventoryInputError):
        take_inventory(InventoryInputs(home=fake.home, project=fake.project, key_path=fake.key))


# --- key and values -------------------------------------------------------------


def test_key_is_created_private_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "state" / "fingerprint.key"
    first = load_or_create_key(path)
    assert len(first) == 32 and load_or_create_key(path) == first
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    assert fingerprint(first, "a") != fingerprint(bytes(32), "a")


@pytest.mark.parametrize("content", ["not hex\n", "abcd\n"])
def test_a_bad_key_is_an_error_and_never_replaced(tmp_path: Path, content: str) -> None:
    path = tmp_path / "k"
    path.write_text(content)
    with pytest.raises(FingerprintKeyError):
        load_or_create_key(path)
    assert path.read_text() == content


def test_inputs_must_exist(tmp_path: Path) -> None:
    with pytest.raises(InventoryInputError):
        take_inventory(InventoryInputs(
            home=tmp_path / "absent", project=tmp_path, key_path=tmp_path / "k",
        ))
    with pytest.raises(InventoryInputError):
        take_inventory(InventoryInputs(
            home=tmp_path, project=tmp_path, key_path=tmp_path / "k",
            env_file=tmp_path / "e", process_env={},
        ))
