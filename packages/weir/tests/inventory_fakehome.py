"""A fake home, project, launch environment and scanner reports for the
inventory tests, built into a temporary directory. Nothing here touches a
real home: every path is under the `root` the caller passes.

FAKE DATA ONLY. Every credential-shaped value below already existed before
this file: the fake credentials of the weir v14 redaction bench
(~/bench/weir-redact/cases/inventory.json, itself drawn from the
weir-transcripts corpus) and the FAKE-EXPOSURE markers of the weir v9
exposure audit (~/bench/weir-exposure-audit/fixture/markers.json). Encoded
or relocated copies (base64, a rotation that starts a key with "/") are
marked as such. No new credential-shaped value was made.

This module is the only test file that holds values. Every other test reads
them from here, and the leak tests scan everything the suite writes for any
6-character fragment of anything in `ALL_VALUES`.

`PLANTS` is the fixture's contract: one entry per credential planted, by
(source, displayed location, name). The tests derive their expectations from
it and from the files this module writes, never from the inventory's output.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, replace
from pathlib import Path


def _v(fragments: str) -> str:
    """A fake value written as space-separated short fragments, so no
    committed literal has a credential's shape for a secret scanner to match.
    The tests see only the joined value, unchanged from its source."""
    return fragments.replace(" ", "")


# --- fake values (copied, never invented) ---------------------------------
# weir-redact inventory.json
AWS_ID_S01 = _v("AKIAAVIG 3PZX5QFV SXQE")
AWS_SECRET_S01 = _v("XcOLH52V nAnRuIVg heptaR3H e9ng7x9m fEFwLHb5")
AWS_ID_S02 = _v("AKIA5CH4 PKB2RBHY RPCN")
AWS_SECRET_S02 = _v("IvCccTbt nS3oJcPi 2HApnEof DmPQsj80 mzd1/eEv")
AWS_ID_S03 = _v("AKIA32OD QJL3IKIT VSYM")
AWS_SECRET_S03 = _v("J4Mox+BU LvuO/Ff5 xx+rdhe3 bQUhnKEe N1VG67f5")
AWS_ID_S20 = _v("AKIAVE7D FKZDNHFN 64CK")
AWS_SECRET_S20 = _v("yZkbrCJt UlWJRmqb uE1eR8pD YUWDiJxq UttilDdK")
DATABASE_URL_S13 = _v(
    "postgres ://app_r xmg:pmLQ y0NOompY JNB5cDLA 8o1V@db- o2j5xb.i nternal: 5432/ord ers"
)
DATABASE_URL_S14 = _v(
    "postgres ://app_a huh:CxDR v92v6h0L VwgGd5HD s3FB@db- a8gxd3.i nternal: 5432/ord ers"
)
DATABASE_URL_S15 = _v(
    "postgres ://app_y moq:WWxS T6uehQ5x B7rseSzs uMOh@db- xufa1m.i nternal: 5432/ord ers"
)
DECOY_D1 = "FAKE-DECOY-D1-d7b4be0068b64623389774d0f29af8ca"
DECOY_D2 = "FAKE-DECOY-D2-cffbe6032630dd21a963777a6061564b"
DECOY_D3 = "FAKE-DECOY-D3-da3c683921b1e2518e7078009d0ec44b"
DECOY_D4 = "FAKE-DECOY-D4-3a719627c38d6af4c831d16e131b697b"
GITHUB_S04 = _v("ghp_xwIf 51Dvtnpw FOrYAvY1 BJtfvN6W seeBplEO")
GITHUB_S05 = _v("ghp_dHQJ rbDMiFJm Sc985zgk UOlr6hCz IGbrCST8")
GITHUB_S06 = _v("ghp_CMRu rcnyLDvO o6PGL20k 47MHk6R2 8h0RFHfI")
GITHUB_S19 = _v("ghp_7WVY Ff5s8veC 0mXfX3mB FQspMaAp Y10z80cM")
OPENAI_S07 = _v(
    "sk-proj- U3swGdlI QypecfL2 Nd0UE-iq Khni7rx8 dGynaQiL mHaTOzWR os5Nijht nTT6UccL YeGS-WSg"
    "OBT3Blbk FJvm8uS7 d8WJNP-q QZhTzJiH cYn9NiwU Aal7Rhnh vKE01-n0 9-gXJxYS Q3c5pOjw 2I6s5vdA"
    "cdU4"
)
OPENAI_S08 = _v(
    "sk-proj- lMoShaGy ReJYKdrs lAk7J3On 8dgz7cS6 DC-23vMM 3Hqbu9o_ tbgpHn8y Gnk-pFhC 6dIJ-LfO"
    "zbT3Blbk FJmZWmYT 3uFgI64p Rsz0_0Xr qYhjlJ9h TDqi9IIv rVrGHIFj rrEzC-v6 hbIxLAaK n2ThNF8I"
    "VBmj"
)
OPENAI_S09 = _v(
    "sk-proj- ZqkGUxwV qCk3-M7W kjjF5ybX PESxFlDd pxgENW-V IgSlcTqm c6d-m8kQ -jBfkGBM WoFUgV78"
    "40T3Blbk FJpvwm-A MBGQ97-9 1i84TBRM 2I1t35E6 qnihlCDO FdfD3ReG 32RzGmtq O1x-ZE10 MfO9Xq1Y"
    "gjBU"
)
ANTHROPIC_S10 = _v(
    "sk-ant-a pi03-USf YMvpZqRH AG-mP6or 7trxhBcF DeTkgRH5 3CCYSvlb bueuxUat E5T5e2Me 6Zx5kLlV"
    "JV8NlK2k 4Y3VH5Fj puy3RuRo u2AA"
)
ANTHROPIC_S11 = _v(
    "sk-ant-a pi03-fDU 9GqtgqUl jXPPzliR KB6xtn5t HmNqLisq Iid_HuoW aBrOdnPq 56PchUCN H6R4Tn8H"
    "KqqY-lyX 9BAEMwsM mlQOzIp5 8vAA"
)
ANTHROPIC_S12 = _v(
    "sk-ant-a pi03-gsl PNAGSMWM pc5mlGLW Ve4QYkwi rrrIodLu ZQCgUetV GJjHi6rA ayFu-rjK CXrUiJvt"
    "X6q4DsDr sqSSzOgf HqaCaWzF 6-AA"
)
JWT_S16 = _v(
    "eyJhbGci OiJIUzI1 NiIsInR5 cCI6IkpX VCJ9.eyJ zdWIiOiI 0MWViZDc yZC05OTh iLTQwYzY tYmQxYi0"
    "3MGEwNmU wYTljZjk iLCJzY29 wZSI6Im9 yZGVyczp 3cml0ZSI sImlhdCI 6MTc5MTg wMDAwMCw iZXhwIjo"
    "xNzkxODg 2NDAwLCJ pc3MiOiJ hdXRoLml udGVybmF sIn0.4bi oLEyPJ0k 2oddepZU adtQ6Zhj tLYWGj73"
    "8SoanG_4"
)
JWT_S17 = _v(
    "eyJhbGci OiJIUzI1 NiIsInR5 cCI6IkpX VCJ9.eyJ zdWIiOiJ iM2Q5Zjk 1My0wZDk 2LTQyN2E tODMyYS0"
    "yNTE3ZTk 0YzkyMjE iLCJzY29 wZSI6Im9 yZGVyczp 3cml0ZSI sImlhdCI 6MTc5MTg wMDAwMCw iZXhwIjo"
    "xNzkxODg 2NDAwLCJ pc3MiOiJ hdXRoLml udGVybmF sIn0.sU6 9AqeCmHf _OmUDPR0 lt-pd52b rhZj8nQ_"
    "4IX4Zjww"
)
JWT_S18 = _v(
    "eyJhbGci OiJIUzI1 NiIsInR5 cCI6IkpX VCJ9.eyJ zdWIiOiJ mYWM4OWF jYi0zZDN kLTQzZjc tYjMxNC1"
    "iZGY2Yzl lODE5Yjk iLCJzY29 wZSI6Im9 yZGVyczp 3cml0ZSI sImlhdCI 6MTc5MTg wMDAwMCw iZXhwIjo"
    "xNzkxODg 2NDAwLCJ pc3MiOiJ hdXRoLml udGVybmF sIn0.03f QKVKQFHv GM-XprdB 74rKHdb5 ECPLEdrw"
    "ihYdB9DU"
)
# weir-exposure-audit markers.json. The markers whose place names are also
# file names this fixture displays (bashrc, npmrc, compose, configjson) are
# not used: "~/.bashrc" on screen would itself be a 6-character fragment of
# the bashrc marker.
MARKER_DOTENV = "FAKE-EXPOSURE-dotenv-fbfb685aa854"
MARKER_DOTENVLOCAL = "FAKE-EXPOSURE-dotenvlocal-9eb91e0a6b30"
MARKER_PRODYAML = "FAKE-EXPOSURE-prodyaml-2f5a71f454d2"
MARKER_PROJMCP = "FAKE-EXPOSURE-projmcp-45e03b5cd243"
MARKER_AWSCREDS = "FAKE-EXPOSURE-awscreds-33a94eb40dac"
MARKER_USERMCP = "FAKE-EXPOSURE-usermcp-163f9cb0dcca"

# Encoded or relocated copies of the values above.
AWS_SECRET_S02_ROTATED = AWS_SECRET_S02[-4:] + AWS_SECRET_S02[:-4]  # starts with "/"
# The rotated key with two more "/" inserted: no segment reaches 20 characters.
AWS_SECRET_S02_SPLIT = "/".join((
    AWS_SECRET_S02_ROTATED[:14], AWS_SECRET_S02_ROTATED[14:28], AWS_SECRET_S02_ROTATED[28:],
))
# The dotenv marker's hex tail in decimal: a password that reads as a number.
MARKER_DOTENV_DECIMAL = str(int(MARKER_DOTENV.rsplit("-", 1)[1], 16))
DOCKER_AUTH = base64.b64encode(f"ci-bot:{MARKER_AWSCREDS}".encode()).decode()
SSH_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    + base64.b64encode(MARKER_PRODYAML.encode()).decode()
    + "\n-----END OPENSSH PRIVATE KEY-----"
)
SA_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    + base64.b64encode(AWS_SECRET_S20.encode()).decode()
    + "\n-----END PRIVATE KEY-----\n"
)
SA_PRIVATE_KEY_ID = DECOY_D1[-32:]

# Documented placeholders and masked keys: credential-SHAPED, never credentials.
PLACEHOLDER_AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"  # AWS's own documented example key
PLACEHOLDER_OPENAI_REDACTED = "sk-proj-REDACTEDREDACTEDREDACTEDREDACTED"  # tests/ fixture

# Non-credential values that are still never printed: unknown variables.
UNKNOWN_EDITOR_THEME = "solarized-dark"

ALL_VALUES: tuple[str, ...] = tuple(sorted({
    AWS_ID_S01, AWS_SECRET_S01, AWS_ID_S02, AWS_SECRET_S02, AWS_ID_S03, AWS_SECRET_S03,
    AWS_ID_S20, AWS_SECRET_S20, DATABASE_URL_S13, DATABASE_URL_S14, DATABASE_URL_S15,
    DECOY_D1, DECOY_D2, DECOY_D3, DECOY_D4, GITHUB_S04, GITHUB_S05, GITHUB_S06, GITHUB_S19,
    OPENAI_S07, OPENAI_S08, OPENAI_S09, ANTHROPIC_S10, ANTHROPIC_S11, ANTHROPIC_S12,
    JWT_S16, JWT_S17, JWT_S18, MARKER_DOTENV, MARKER_DOTENVLOCAL, MARKER_PRODYAML,
    MARKER_PROJMCP, MARKER_AWSCREDS, MARKER_USERMCP, AWS_SECRET_S02_ROTATED,
    AWS_SECRET_S02_SPLIT, MARKER_DOTENV_DECIMAL, DOCKER_AUTH, SSH_KEY, SA_PRIVATE_KEY,
    SA_PRIVATE_KEY_ID, UNKNOWN_EDITOR_THEME,
}))

# A fixed fingerprint key, so a test run's store is byte-identical across
# runs and a leak scan of it cannot pass or fail by chance.
TEST_KEY_HEX = "5e" * 32


@dataclass(frozen=True)
class Plant:
    """One planted credential: what the inventory must report. The value
    is kept out of the repr, so a failing test never prints it."""

    source: str
    display: str  # as Location.display renders it
    name: str
    value: str | None = field(repr=False)  # None: dynamic or whole-file
    # 1-based line of the value's first occurrence. Left None at plant time
    # for a value in a file, it is derived from the written bytes.
    line: int | None = None


@dataclass(frozen=True)
class FakeHome:
    root: Path
    home: Path
    project: Path
    env_file: Path
    gitleaks: Path
    trufflehog: Path
    key: Path
    plants: tuple[Plant, ...] = field(repr=False)
    # Names the inventory must list as unknown, and the one the map marks fine.
    unknown_env: tuple[str, ...]
    fine_env: tuple[str, ...]
    # Project files .gitignore covers that hold a planted credential.
    git_ignored: tuple[str, ...]
    # Displayed paths the inventory must list as not scanned, with reasons.
    not_scanned: tuple[tuple[str, str], ...]


def _write(path: Path, text: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8", newline="\n")


def _js(obj: object) -> str:
    return json.dumps(obj, indent=2) + "\n"


def _derive_line(plant: Plant, home: Path, project: Path) -> Plant:
    """Fill a file plant's line from the bytes actually written: the first
    occurrence of the value, raw or JSON-escaped."""
    if plant.line is not None or plant.value is None:
        return plant
    prefix, base = ("./", project) if plant.display.startswith("./") else ("~/", home)
    text = (base / plant.display.removeprefix(prefix)).read_text(encoding="utf-8")
    for form in (plant.value, json.dumps(plant.value)[1:-1]):
        index = text.find(form)
        if index != -1:
            return replace(plant, line=text.count("\n", 0, index) + 1)
    raise AssertionError(f"plant {plant!r} is not in its file")


STANDARD = "standard_location"
PROJECT = "project_scan"
ENVIRONMENT = "environment"
MAP = "map"


def build(root: Path) -> FakeHome:
    home = root / "fakehome"
    project = home / "work" / "proj"
    plants: list[Plant] = []

    def plant(source: str, display: str, name: str, value: str | None, line: int | None = None):
        plants.append(Plant(source, display, name, value, line))

    # --- source 1: standard locations --------------------------------------
    _write(home / ".aws/credentials", (
        "[default]\n"
        f"aws_access_key_id = {AWS_ID_S01}\n"
        f"aws_secret_access_key = {AWS_SECRET_S01}\n"
        "region = us-east-1\n"
        "\n[work]\n"
        f"aws_access_key_id={AWS_ID_S02}\n"
        f"aws_secret_access_key={AWS_SECRET_S02}\n"
    ))
    plant(STANDARD, "~/.aws/credentials", "aws_access_key_id", AWS_ID_S01, 2)
    plant(STANDARD, "~/.aws/credentials", "aws_secret_access_key", AWS_SECRET_S01, 3)
    plant(STANDARD, "~/.aws/credentials", "aws_access_key_id", AWS_ID_S02, 7)
    plant(STANDARD, "~/.aws/credentials", "aws_secret_access_key", AWS_SECRET_S02, 8)

    _write(home / ".aws/config", (
        "[profile ci]\nregion = eu-west-1\noutput = json\n"
        f"aws_access_key_id = {AWS_ID_S20}\n"
    ))
    plant(STANDARD, "~/.aws/config", "aws_access_key_id", AWS_ID_S20, 4)

    _write(home / ".config/gcloud/application_default_credentials.json", _js({
        "client_id": "fake-client.apps.googleusercontent.com",
        "client_secret": AWS_SECRET_S03,
        "refresh_token": JWT_S17,
        "type": "authorized_user",
    }))
    plant(STANDARD, "~/.config/gcloud/application_default_credentials.json", "client_secret",
          AWS_SECRET_S03)
    plant(STANDARD, "~/.config/gcloud/application_default_credentials.json", "refresh_token",
          JWT_S17)
    # A binary token database: whole-file, value absent.
    _write(home / ".config/gcloud/credentials.db", b"SQLite format 3\x00" + b"\x00" * 64)
    plant(STANDARD, "~/.config/gcloud/credentials.db", "credentials.db", None)
    # A service-account key moved by GOOGLE_APPLICATION_CREDENTIALS (below).
    _write(home / "keys/adc-sa.json", _js({
        "type": "service_account",
        "project_id": "acme-dev",
        "private_key_id": SA_PRIVATE_KEY_ID,
        "private_key": SA_PRIVATE_KEY,
        "client_email": "ci@acme-dev.iam.gserviceaccount.com",
    }))
    plant(STANDARD, "~/keys/adc-sa.json", "private_key_id", SA_PRIVATE_KEY_ID)
    plant(STANDARD, "~/keys/adc-sa.json", "private_key", SA_PRIVATE_KEY)

    _write(home / ".npmrc", (
        "registry=https://registry.npmjs.org/\n"
        f"//registry.npmjs.org/:_authToken={ANTHROPIC_S12}\n"
    ))
    plant(STANDARD, "~/.npmrc", "_authToken", ANTHROPIC_S12, 2)

    _write(home / ".kube/config", (
        "apiVersion: v1\nkind: Config\nclusters:\n- name: dev\n  cluster:\n"
        "    server: https://k8s.acme.example:6443\n"
        "users:\n- name: dev-admin\n  user:\n"
        f"    token: {JWT_S16}\n"
        "contexts:\n- name: dev\n  context:\n    cluster: dev\n    user: dev-admin\n"
        "current-context: dev\n"
    ))
    plant(STANDARD, "~/.kube/config", "token", JWT_S16, 10)

    _write(home / ".docker/config.json", _js({
        "auths": {"registry.acme.example": {"auth": DOCKER_AUTH, "identitytoken": JWT_S18}},
        "credsStore": "desktop",
    }))
    plant(STANDARD, "~/.docker/config.json", "auth", DOCKER_AUTH)
    plant(STANDARD, "~/.docker/config.json", "identitytoken", JWT_S18)

    _write(home / ".netrc", (
        f"machine api.acme.example\n  login dev\n  password {MARKER_AWSCREDS}\n"
    ))
    plant(STANDARD, "~/.netrc", "password", MARKER_AWSCREDS, 3)

    _write(home / ".git-credentials", f"https://dev:{GITHUB_S05}@github.com\n")
    plant(STANDARD, "~/.git-credentials", "password", GITHUB_S05, 1)

    _write(home / ".config/gh/hosts.yml", (
        f"github.com:\n    oauth_token: {GITHUB_S04}\n    user: dev\n    git_protocol: https\n"
    ))
    plant(STANDARD, "~/.config/gh/hosts.yml", "oauth_token", GITHUB_S04, 2)

    _write(home / ".ssh/id_ed25519", SSH_KEY + "\n")
    _write(home / ".ssh/id_ed25519.pub", "ssh-ed25519 AAAA dev@fake\n")
    plant(STANDARD, "~/.ssh/id_ed25519", "private_key", SSH_KEY, 1)

    _write(home / ".vault-token", GITHUB_S19 + "\n")
    plant(STANDARD, "~/.vault-token", "token", GITHUB_S19, 1)

    _write(home / ".claude.json", _js({"mcpServers": {"acme-search": {
        "type": "stdio", "command": "acme-search-mcp",
        "env": {"ACME_SEARCH_TOKEN": MARKER_USERMCP, "ACME_REGION": "eu-west-1"},
    }}}))
    plant(STANDARD, "~/.claude.json", "ACME_SEARCH_TOKEN", MARKER_USERMCP)

    # --- source 3: launch environment and startup files --------------------
    env_file = root / "launch.env"
    launch = [
        ("ACME_DEPLOY_TOKEN", MARKER_USERMCP),
        ("ACME_UPLINK", OPENAI_S09),  # no name signal: secret by shape
        ("ANTHROPIC_API_KEY", ANTHROPIC_S10),
        ("API_HOST", "api.acme.example"),
        ("AWS_SECRET_ACCESS_KEY", AWS_SECRET_S02_ROTATED),  # starts with "/", not a path
        ("BUILD_FLAVOR", MARKER_DOTENVLOCAL),  # unknown
        ("CI", "true"),
        ("DATABASE_URL", DATABASE_URL_S14),
        ("GOOGLE_APPLICATION_CREDENTIALS", "~/keys/adc-sa.json"),  # a path, not a secret
        ("HOME", "/home/dev"),
        ("LOG_LEVEL", "info"),  # unknown
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("PORT", "8080"),
        ("RELEASE_CHANNEL", DECOY_D1),  # unknown, marked fine in the map
        ("TOKEN_TTL", "3600"),  # name suggests a secret, but a number is not one
    ]
    _write(env_file, "".join(f"{k}={v}\n" for k, v in launch))
    line = {k: i + 1 for i, (k, _) in enumerate(launch)}
    for name in ("ACME_DEPLOY_TOKEN", "ACME_UPLINK", "ANTHROPIC_API_KEY",
                 "AWS_SECRET_ACCESS_KEY", "DATABASE_URL"):
        plant(ENVIRONMENT, "launch env", name, dict(launch)[name], line[name])

    _write(home / ".bashrc", (
        "# fake rc\n"
        'export PATH="$HOME/bin:$PATH"\n'
        f"export ACME_DEPLOY_TOKEN={MARKER_USERMCP}\n"
        'export OPENAI_API_KEY="$(pass show openai)"\n'
        f"export EDITOR_THEME={UNKNOWN_EDITOR_THEME}\n"
        "alias ll='ls -l'\n"
    ))
    plant(ENVIRONMENT, "~/.bashrc", "ACME_DEPLOY_TOKEN", MARKER_USERMCP, 3)
    plant(ENVIRONMENT, "~/.bashrc", "OPENAI_API_KEY", None, 4)
    _write(home / ".profile", f"GH_TOKEN='{GITHUB_S05}'\nexport GH_TOKEN\n")
    plant(ENVIRONMENT, "~/.profile", "GH_TOKEN", GITHUB_S05, 1)
    _write(home / ".zshrc", f"export STRIPE_KEY='{OPENAI_S08}'\n")
    plant(ENVIRONMENT, "~/.zshrc", "STRIPE_KEY", OPENAI_S08, 1)
    _write(home / ".config/fish/config.fish", f"set -gx HF_TOKEN {GITHUB_S19}\n")
    plant(ENVIRONMENT, "~/.config/fish/config.fish", "HF_TOKEN", GITHUB_S19, 1)

    # --- source 2: project files --------------------------------------------
    _write(project / ".gitignore", ".env*\n!.env.example\nconfig/prod/\n.mcp.json\n")
    _write(project / ".env", (
        f"ACME_API_KEY={MARKER_DOTENV}\nOPENAI_API_KEY={OPENAI_S07}\nLOG_LEVEL=info\nPORT=8080\n"
    ))
    plant(PROJECT, "./.env", "ACME_API_KEY", MARKER_DOTENV, 1)
    plant(PROJECT, "./.env", "OPENAI_API_KEY", OPENAI_S07, 2)
    # Placeholders and documented examples: none is a credential.
    _write(project / ".env.example", (
        f"OPENAI_API_KEY={PLACEHOLDER_OPENAI_REDACTED}\n"
        "API_TOKEN=<your-token-here>\n"
        f"AWS_ACCESS_KEY_ID={PLACEHOLDER_AWS_EXAMPLE}\n"
        "DB_PASSWORD=changeme\n"
        "SESSION_SECRET=${SESSION_SECRET}\n"
    ))
    _write(project / "config/settings.json", _js({"db": {"host": "localhost", "db_password":
                                                          MARKER_PROJMCP}}))
    plant(PROJECT, "./config/settings.json", "db_password", MARKER_PROJMCP, 4)
    _write(project / "config/prod/secrets.yaml", (
        f"payments:\n  signing_secret: {MARKER_PRODYAML}\n"
    ))
    plant(PROJECT, "./config/prod/secrets.yaml", "signing_secret", MARKER_PRODYAML, 2)
    _write(project / "config/database.yml", f"production:\n  url: {DATABASE_URL_S13}\n")
    plant(PROJECT, "./config/database.yml", "url_with_password", DATABASE_URL_S13, 2)
    _write(project / ".mcp.json", _js({"mcpServers": {"acme-tracker": {
        "command": "acme-mcp", "env": {"ACME_TRACKER_TOKEN": MARKER_AWSCREDS},
    }}}))
    plant(PROJECT, "./.mcp.json", "ACME_TRACKER_TOKEN", MARKER_AWSCREDS, 6)
    _write(project / "src/app.py", (
        f'FALLBACK = "{GITHUB_S06}"\n'
        "password = get_password()\n"
        "token = settings.API_TOKEN\n"
        'api_key: str = ""\n'
    ))
    plant(PROJECT, "./src/app.py", "github_token", GITHUB_S06, 1)
    _write(project / "src/db.ts", f'const pool = connect("{DATABASE_URL_S15}");\n')
    plant(PROJECT, "./src/db.ts", "url_with_password", DATABASE_URL_S15, 1)
    _write(project / "src/vault.go", f'package vault\n\nvar unsealKey = "{AWS_SECRET_S03}"\n')
    plant(PROJECT, "./src/vault.go", "unsealKey", AWS_SECRET_S03, 3)
    # Keys after JSON escapes, the 0.4.1 boundary fix: one after \n, one after \t.
    _write(project / "logs/session.json", json.dumps(
        {"tool_result": f"line one\n{AWS_ID_S03}\t{ANTHROPIC_S11} done"}
    ) + "\n")
    plant(PROJECT, "./logs/session.json", "aws_access_key_id", AWS_ID_S03, 1)
    plant(PROJECT, "./logs/session.json", "anthropic_api_key", ANTHROPIC_S11, 1)
    # Found only by the imported scanners.
    _write(project / "src/legacy.cfg", f"slack_hook = {DECOY_D2}\n")
    plant(PROJECT, "./src/legacy.cfg", "gitleaks:generic-api-key", DECOY_D2, 1)
    _write(project / "notes/handoff.txt", f"handoff notes\nshared: {DECOY_D3}\n")
    plant(PROJECT, "./notes/handoff.txt", "trufflehog:Dockerhub", DECOY_D3, 2)
    plant(PROJECT, "./old/creds.txt", "trufflehog:Github", DECOY_D4, 3)
    _write(project / "assets/blob.bin", b"\x89PNG\r\n\x1a\n\x00\x00binary")
    _write(project / "node_modules/leftpad/index.js", "module.exports = (s) => s;\n")
    _write(project / "README.md", "# demo-proj\n\nRun `python3 app.py`.\n")

    gitleaks = root / "gitleaks.json"
    _write(gitleaks, _js([
        {"RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": 1,
         "EndLine": 1, "StartColumn": 14, "EndColumn": 59, "Match": f"slack_hook = {DECOY_D2}",
         "Secret": DECOY_D2, "File": "src/legacy.cfg", "SymlinkFile": "", "Commit": "",
         "Entropy": 4.1, "Author": "", "Email": "", "Date": "", "Message": "", "Tags": [],
         "Fingerprint": "src/legacy.cfg:generic-api-key:1"},
        # The same token weir's catalog finds: merges into one credential.
        {"RuleID": "github-pat", "Description": "GitHub PAT", "StartLine": 1, "EndLine": 1,
         "StartColumn": 13, "EndColumn": 52, "Match": GITHUB_S06, "Secret": GITHUB_S06,
         "File": str(project / "src/app.py"), "SymlinkFile": "", "Commit": "", "Entropy": 4.5,
         "Author": "", "Email": "", "Date": "", "Message": "", "Tags": [],
         "Fingerprint": "src/app.py:github-pat:1"},
    ]))
    trufflehog = root / "trufflehog.jsonl"
    _write(trufflehog, "".join(json.dumps(r) + "\n" for r in [
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "notes/handoff.txt", "line": 2}}},
         "SourceID": 1, "SourceType": 15, "SourceName": "trufflehog - filesystem",
         "DetectorType": 1, "DetectorName": "Dockerhub", "DecoderName": "PLAIN",
         "Verified": False, "Raw": DECOY_D3, "RawV2": "", "Redacted": "", "ExtraData": None},
        {"SourceMetadata": {"Data": {"Git": {
            "commit": "4f1c2b9e7a0d3c5b8e6f1a2d4c7b9e0f3a5d8c1b", "file": "old/creds.txt",
            "email": "dev <dev@acme.example>", "repository": "", "line": 3}}},
         "SourceID": 2, "SourceType": 16, "SourceName": "trufflehog - git",
         "DetectorType": 8, "DetectorName": "Github", "DecoderName": "PLAIN",
         "Verified": False, "Raw": DECOY_D4, "RawV2": "", "Redacted": "", "ExtraData": None},
    ]))

    # --- source 4: the approved map ------------------------------------------
    _write(home / ".config/acme/session.bin", b"\x00\x01acme-session\x00")
    _write(project / ".weir/reach.yml", (
        "version: 1\n"
        "credentials:\n"
        "  - path: src/vault.go\n    name: VAULT_UNSEAL_KEY\n    field: unsealKey\n"
        "  - path: ~/.config/acme/session.bin\n    name: ACME_SESSION\n"
        "  - path: docs/gone.txt\n"
        "env:\n  fine: [RELEASE_CHANNEL]\n"
    ))
    plant(MAP, "./src/vault.go", "VAULT_UNSEAL_KEY", AWS_SECRET_S03, 3)
    plant(MAP, "~/.config/acme/session.bin", "ACME_SESSION", None)

    key = root / "test.key"
    _write(key, TEST_KEY_HEX + "\n")
    return FakeHome(
        root=root, home=home, project=project, env_file=env_file, gitleaks=gitleaks,
        trufflehog=trufflehog, key=key,
        plants=tuple(_derive_line(p, home, project) for p in plants),
        unknown_env=("BUILD_FLAVOR", "EDITOR_THEME", "LOG_LEVEL"),
        fine_env=("RELEASE_CHANNEL",),
        git_ignored=("./.env", "./.mcp.json", "./config/prod/secrets.yaml"),
        not_scanned=(
            ("./assets/blob.bin", "binary"),
            ("./docs/gone.txt", "missing"),
            ("./node_modules", "vendored_dir"),
        ),
    )
