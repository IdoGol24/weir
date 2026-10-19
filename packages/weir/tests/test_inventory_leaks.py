"""No value, and no fragment of 6 or more characters of one, in anything the
inventory tests produce: screen output, JSON, error messages, the unknown
list, the store, the key directory, reprs, and the test tree itself.

One threshold everywhere: 6 characters. The scan also looks for the base64
(all three alignments), JSON-escaped and URL-encoded forms of every value.
A failure names the blob and offset, never the fragment, so the failure
report cannot itself leak. The positive controls prove the scanner fires.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import urllib.parse
from pathlib import Path

import inventory_fakehome as fx
import pytest
from click.testing import CliRunner

from weir.cli.main import main
from weir.inventory import (
    Inventory,
    InventoryInputError,
    InventoryInputs,
    LocationKind,
    PartlyReadReason,
    ValueState,
    encode_report,
    encode_store,
    take_inventory,
)
from weir.inventory.fingerprint import fingerprint, load_or_create_key
from weir.inventory.text import inventory_lines, unknown_list_lines

THRESHOLD = 6
_TESTS_DIR = Path(__file__).parent


def _secret_parts(value: str) -> list[str]:
    """A PEM block's armor (`-----BEGIN ... PRIVATE KEY-----`) is the same
    in every key and in plenty of prose; its body is the secret."""
    if "-----BEGIN" not in value:
        return [value]
    return [line for line in value.splitlines() if line and not line.startswith("-----")]


def _forms(value: str) -> set[str]:
    forms: set[str] = set()
    for part in _secret_parts(value):
        forms |= _part_forms(part)
    return forms


def _part_forms(value: str) -> set[str]:
    raw = value.encode()
    forms = {value, json.dumps(value)[1:-1], urllib.parse.quote(value, safe="")}
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + raw).decode()
        # Drop the characters that encode the padding bytes and the trailing
        # partial group: they depend on the neighbours, not on the value.
        lead = (shift * 4 + 2) // 3
        forms.add(encoded[lead:len(encoded) - 4])
    return {f for f in forms if len(f) >= THRESHOLD}


def _fragments(values: tuple[str, ...]) -> dict[str, int]:
    """Every THRESHOLD-length window of every form of every value -> index."""
    out: dict[str, int] = {}
    for index, value in enumerate(values):
        for form in _forms(value):
            for i in range(len(form) - THRESHOLD + 1):
                out.setdefault(form[i:i + THRESHOLD], index)
    return out


_FRAGMENTS = _fragments(fx.ALL_VALUES)


def leaks(label: str, blob: str | bytes) -> list[tuple[str, int, int]]:
    """(blob label, offset, value index) per leaked window. Never the text."""
    text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
    found: list[tuple[str, int, int]] = []
    for i in range(len(text) - THRESHOLD + 1):
        index = _FRAGMENTS.get(text[i:i + THRESHOLD])
        if index is not None:
            found.append((label, i, index))
    return found


def _assert_clean(blobs: dict[str, str | bytes]) -> None:
    # Hide this frame: pytest would print `blobs`, i.e. the scanned text.
    __tracebackhide__ = True
    assert blobs, "nothing was collected to scan"
    found = [hit for label, blob in blobs.items() for hit in leaks(label, blob)]
    assert not found, f"value fragments at (blob, offset, value index): {found[:10]}"


# --- positive controls: the scanner must fire ---------------------------------


@pytest.mark.parametrize(
    "value", [fx.DECOY_D2, fx.AWS_SECRET_S01, fx.JWT_S16], ids=["decoy", "aws", "jwt"]
)
def test_control_a_six_character_fragment_is_caught(value: str) -> None:
    middle = len(value) // 2
    assert leaks("control", f"safe text {value[middle:middle + 6]} safe text")


def test_control_a_base64_copy_is_caught() -> None:
    encoded = base64.b64encode(fx.MARKER_DOTENV.encode()).decode()
    assert leaks("control", f"x {encoded} y")


def test_control_five_characters_is_under_the_threshold() -> None:
    sample = fx.AWS_SECRET_S01[10:15]
    assert len(sample) == 5
    assert not leaks("control", f"  {sample}  ")


def test_control_the_fixture_files_themselves_are_caught(tmp_path: Path) -> None:
    fake = fx.build(tmp_path)
    assert leaks("fixture", (fake.home / ".aws/credentials").read_text())


# --- the scan -------------------------------------------------------------


def _collect_files(root: Path, blobs: dict[str, str | bytes], prefix: str) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            blobs[f"{prefix}/{path.relative_to(root).as_posix()}"] = path.read_bytes()


def test_nothing_the_inventory_produces_holds_a_value(tmp_path: Path) -> None:
    fake = fx.build(tmp_path / "fixture")
    out = tmp_path / "out"
    out.mkdir()
    # The default state directory, preloaded with the fixed test key so the
    # key file is scanned too and the scan cannot pass or fail by chance.
    (fake.home / ".weir").mkdir()
    (fake.home / ".weir/fingerprint.key").write_text(fx.TEST_KEY_HEX + "\n")
    blobs: dict[str, str | bytes] = {}
    base = [
        "inventory", "--home", str(fake.home), "--project", str(fake.project),
        "--gitleaks", str(fake.gitleaks), "--trufflehog", str(fake.trufflehog),
    ]
    with_env = [*base, "--env-file", str(fake.env_file)]
    runs = {
        "text": with_env,
        "json": [*with_env, "--json"],
        "strict": [*with_env, "--strict"],
        "store": [*with_env, "--store", str(out / "store.json"), "--key", str(fake.key)],
        "unknown-list": [*with_env, "--unknown-list", str(out / "unknown.txt")],
        "no-env": base,
    }
    for label, args in runs.items():
        result = CliRunner().invoke(main, args)
        assert result.exit_code in (0, 1), label
        blobs[f"cli:{label}:stdout"] = result.stdout
        blobs[f"cli:{label}:stderr"] = result.stderr

    # Error paths: inputs that CONTAIN values must not echo them.
    bad_gitleaks = out / "bad-gitleaks.json"
    bad_gitleaks.write_text(json.dumps([{"RuleID": 7, "Secret": fx.OPENAI_S07}]))
    bad_truffle = out / "bad-trufflehog.jsonl"
    bad_truffle.write_text(f'{{"DetectorName": "x", "Raw": "{fx.GITHUB_S04}"\n')
    bad_key = out / "bad.key"
    bad_key.write_text(fx.AWS_SECRET_S01)
    errors = {
        "gitleaks": [*base, "--gitleaks", str(bad_gitleaks)],
        "trufflehog": [*base, "--trufflehog", str(bad_truffle)],
        "key": [*base, "--key", str(bad_key)],
        "env-file": [*base, "--env-file", str(out / "absent.env")],
    }
    for label, args in errors.items():
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 2, label
        blobs[f"error:{label}:stdout"] = result.stdout
        blobs[f"error:{label}:stderr"] = result.stderr

    reach = fake.project / ".weir/reach.yml"
    good_map = reach.read_text()
    bad_maps = {
        "map-value": f"oops: {fx.ANTHROPIC_S10}\n",
        # PyYAML quotes the offending line; msgspec quotes an unknown key.
        "map-yaml": f"  field: _authToken: {fx.ANTHROPIC_S10}\n",
        "map-key": f"{fx.ANTHROPIC_S10}: x\n",
    }
    for label, extra in bad_maps.items():
        reach.write_text(good_map + extra)
        result = CliRunner().invoke(main, with_env)
        assert result.exit_code == 2, label
        blobs[f"error:{label}:stderr"] = result.stderr
    reach.write_text(good_map)

    # The API surface: reprs, encodings, exception text.
    inputs = InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key, env_file=fake.env_file,
        gitleaks_reports=[fake.gitleaks], trufflehog_reports=[fake.trufflehog],
    )
    api = take_inventory(inputs)
    blobs["api:report-json"] = encode_report(api.report)
    blobs["api:store-json"] = encode_store(api.store)
    blobs["api:report-repr"] = repr(api.report)
    blobs["api:store-repr"] = repr(api.store)
    with pytest.raises(InventoryInputError) as bad:
        take_inventory(InventoryInputs(
            home=fake.home, project=fake.project, key_path=fake.key,
            gitleaks_reports=[bad_gitleaks],
        ))
    blobs["api:input-error"] = str(bad.value)

    proc = subprocess.run(
        [sys.executable, "-m", "weir.cli.main", *base, "--process-env", "--key", str(fake.key),
         "--unknown-list", str(out / "process-unknown.txt")],
        env={"ACME_DEPLOY_TOKEN": fx.MARKER_USERMCP, "PATH": "/usr/bin:/bin",
             **({"SYSTEMROOT": r"C:\Windows"} if sys.platform == "win32" else {})},
        capture_output=True, check=False,
    )
    assert proc.returncode == 0
    blobs["subprocess:stdout"] = proc.stdout
    blobs["subprocess:stderr"] = proc.stderr

    # Every file the runs wrote: the store, the unknown lists, and the
    # default state directory in the fake home (key, unknown list).
    _collect_files(out, blobs, "out")
    _collect_files(fake.home / ".weir", blobs, "home-state")
    for name in ("bad-gitleaks.json", "bad-trufflehog.jsonl", "bad.key"):
        blobs.pop(f"out/{name}")  # inputs this test planted, not outputs
    assert "out/store.json" in blobs and "home-state/unknown-env.txt" in blobs
    _assert_clean(blobs)


def test_multi_line_keys_in_a_plain_env_file_list_no_line_of_them(tmp_path: Path) -> None:
    """`env > file` writes a multi-line value as raw lines. A key's body
    line (`<base64>==`) must never read as `NAME=value`, however short it is:
    a PEM block is one value, from its BEGIN line to its END line."""
    head, body, tail = fx.SA_PRIVATE_KEY.splitlines()
    rewrapped = "\n".join([head, body[:40], body[40:], tail])  # last body line under 20
    fake = fx.build(tmp_path / "fixture")
    env_file = tmp_path / "plain.env"
    env_file.write_text(
        f"APP_PRIVATE_KEY={rewrapped}\nSIGNING_KEY={fx.SSH_KEY}\nLOG_LEVEL=info\n"
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key, env_file=env_file,
    ))
    report = result.report
    app, signing = sorted(
        (c for c in report.credentials if c.location.kind is LocationKind.LAUNCH_ENV),
        key=lambda c: c.name,
    )
    assert (app.name, signing.name) == ("APP_PRIVATE_KEY", "SIGNING_KEY")
    launch_names = [
        e.name for e in [*report.env_unknown, *report.env_fine]
        if e.location.kind is LocationKind.LAUNCH_ENV
    ]
    assert launch_names == ["LOG_LEVEL"]
    assert report.counts.env_withheld == 0
    data = env_file.read_bytes()
    for cred, key in ((app, rewrapped), (signing, fx.SSH_KEY)):
        [record] = [r for r in result.store.records if r.credential_id == cred.id]
        whole = [data[s:e] for s, e in record.offsets] == [key.encode()]
        assert whole, cred.name
    assert app.same_value_as == [] and app.id not in signing.same_value_as
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_a_multi_line_quoted_key_in_a_startup_file_is_one_value(tmp_path: Path) -> None:
    """A quoted value runs to its closing quote across lines, as the shell
    reads it: the key is one record holding the whole key, and no line of
    it is read as a command, however short."""
    head, body, tail = fx.SA_PRIVATE_KEY.splitlines()
    rewrapped = "\n".join([head, body[:40], body[40:], tail])  # last body line under 20
    fake = fx.build(tmp_path / "fixture")
    inputs = InventoryInputs(home=fake.home, project=fake.project, key_path=fake.key)
    before = take_inventory(inputs).report
    bashrc = fake.home / ".bashrc"
    with bashrc.open("a") as handle:
        handle.write(f'export APP_PRIVATE_KEY="{rewrapped}"\n')
    result = take_inventory(inputs)
    report = result.report

    def at_bashrc(inventory: Inventory) -> list[str]:
        return sorted(
            c.name for c in inventory.credentials if c.location.display == "~/.bashrc"
        )

    assert at_bashrc(report) == sorted([*at_bashrc(before), "APP_PRIVATE_KEY"])
    assert [(e.name, e.location.display) for e in report.env_unknown] == [
        (e.name, e.location.display) for e in before.env_unknown
    ]
    assert report.counts.env_withheld == before.counts.env_withheld == 0
    [key] = [
        c for c in report.credentials
        if c.name == "APP_PRIVATE_KEY" and c.location.display == "~/.bashrc"
    ]
    [record] = [r for r in result.store.records if r.credential_id == key.id]
    data = bashrc.read_bytes()
    whole = [data[s:e] for s, e in record.offsets] == [rewrapped.encode()]
    assert whole and key.same_value_as == []
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_a_stray_quote_hides_no_later_line_and_is_reported(tmp_path: Path) -> None:
    """Startup files are read line by line: an apostrophe in a here-document
    or a quote its line leaves open cannot hide a later export, and what is
    not fully read is listed by file and line, never skipped silently."""
    fake = fx.build(tmp_path / "fixture")
    profile = fake.home / ".bash_profile"
    profile.write_text(
        "usage() {\ncat <<EOF\nNOTE=Don't run as root\nEOF\n}\n"  # 1-5
        f"export GH_TOKEN={fx.GITHUB_S05}\n"  # 6
        "export PS1='\\u \\w'\n"  # 7
        f'export DRAFT_TOKEN="{fx.MARKER_DOTENV}\n'  # 8
        'export A_MODE="x y"\n'  # 9
        f"export OPENAI_API_KEY={fx.OPENAI_S08}\n"  # 10
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    report = result.report
    found = [c for c in report.credentials if c.location.display == "~/.bash_profile"]
    assert [(c.name, c.location.line, c.value_state) for c in found] == [
        ("GH_TOKEN", 6, ValueState.LITERAL), ("DRAFT_TOKEN", 8, ValueState.PARTIAL),
        ("OPENAI_API_KEY", 10, ValueState.LITERAL),
    ]
    unknown = [
        (e.name, e.location.line) for e in report.env_unknown
        if e.location.display == "~/.bash_profile"
    ]
    assert unknown == [("A_MODE", 9)]
    assert [(p.display, p.line, p.reason) for p in report.not_fully_read] == [
        ("~/.bash_profile", 2, PartlyReadReason.HEREDOC),
        ("~/.bash_profile", 8, PartlyReadReason.MULTI_LINE_QUOTE),
    ]
    assert report.counts.not_fully_read == 2
    data = profile.read_bytes()
    records = {r.credential_id: r for r in result.store.records}
    assert found[1].id not in records
    for cred, value in ((found[0], fx.GITHUB_S05), (found[2], fx.OPENAI_S08)):
        exact = [data[s:e] for s, e in records[cred.id].offsets] == [value.encode()]
        assert exact, cred.name
    screen = inventory_lines(report, unknown_list_path=None)
    assert "present, not fully read: 2" in screen
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(screen),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_a_key_in_a_here_document_body_is_still_a_credential(tmp_path: Path) -> None:
    """A here-document body is not read as commands, but it is still
    searched for credential shapes: a key there is a credential at its own
    line, and the here-document stays listed as not fully read."""
    fake = fx.build(tmp_path / "fixture")
    profile = fake.home / ".bash_profile"
    profile.write_text(
        "cat > ~/.config/app/env <<EOF\n"  # 1
        f"export ACME_UPLINK={fx.OPENAI_S09}\n"  # 2
        "EOF\n"  # 3
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    report = result.report
    [cred] = [c for c in report.credentials if c.location.display == "~/.bash_profile"]
    assert (cred.source, cred.reason, cred.location.line) == ("environment", "shape", 2)
    assert all(d.startswith(("catalog:", "shape:")) for d in cred.detectors)
    [record] = [r for r in result.store.records if r.credential_id == cred.id]
    exact = [profile.read_bytes()[s:e] for s, e in record.offsets] == [fx.OPENAI_S09.encode()]
    assert exact
    assert [(p.display, p.line, p.reason) for p in report.not_fully_read] == [
        ("~/.bash_profile", 1, PartlyReadReason.HEREDOC),
    ]
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


@pytest.mark.parametrize(("body", "expected"), [
    # A key on a continuation line of a quote its line leaves open: a shape
    # credential at its own line; the variable itself is judged by name.
    (f"export ACME_CONFIG='\ntoken: {fx.OPENAI_S09}\n'\n", (2, ValueState.LITERAL, False)),
    # A key on the open line under a secret name: one record, the name's.
    (f'export GH_TOKEN="{fx.OPENAI_S09}\nmore"\n', (1, ValueState.LITERAL, True)),
], ids=["continuation-line", "open-line"])
def test_a_key_in_a_value_not_fully_read_is_one_credential(
    tmp_path: Path, body: str, expected: tuple[int, ValueState, bool],
) -> None:
    fake = fx.build(tmp_path / "fixture")
    profile = fake.home / ".bash_profile"
    profile.write_text(body)
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    report = result.report
    [cred] = [c for c in report.credentials if c.location.display == "~/.bash_profile"]
    line, state, named = expected
    assert (cred.location.line, cred.value_state, cred.reason) == (line, state, "shape")
    assert (cred.name == "GH_TOKEN") is named
    [record] = [r for r in result.store.records if r.credential_id == cred.id]
    exact = [profile.read_bytes()[s:e] for s, e in record.offsets] == [fx.OPENAI_S09.encode()]
    assert exact
    assert [(p.display, p.line, p.reason) for p in report.not_fully_read] == [
        ("~/.bash_profile", 1, PartlyReadReason.MULTI_LINE_QUOTE),
    ]
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_a_shaped_value_keeps_its_own_bytes_before_the_next_command(tmp_path: Path) -> None:
    """A URL shape runs on past `;`; the assignment's own value is what is
    fingerprinted, so it links to the same value assigned elsewhere."""
    fake = fx.build(tmp_path / "fixture")
    profile = fake.home / ".bash_profile"
    profile.write_text(
        f"export DATABASE_URL={fx.DATABASE_URL_S14}; export X_MODE=1\n"
        f"export DB2_URL={fx.DATABASE_URL_S14}\n"
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    report = result.report
    first, second = [c for c in report.credentials if c.location.display == "~/.bash_profile"]
    assert (first.name, first.location.line, second.name) == ("DATABASE_URL", 1, "DB2_URL")
    records = {r.credential_id: r for r in result.store.records}
    expected = fingerprint(load_or_create_key(fake.key), fx.DATABASE_URL_S14)
    data = profile.read_bytes()
    for cred in (first, second):
        record = records[cred.id]
        exact = [data[s:e] for s, e in record.offsets] == [fx.DATABASE_URL_S14.encode()]
        assert exact and record.fingerprint == expected, cred.name
    assert second.id in first.same_value_as
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_a_record_holds_the_shape_within_its_value(tmp_path: Path) -> None:
    """A token inside a longer value is fingerprinted alone and links to the
    same token elsewhere; a complete private key in a value not fully read
    is kept whole; a PEM block with no END is a name-only record."""
    head, body, tail = fx.SA_PRIVATE_KEY.splitlines()
    key = f"{head}\\n\n{body}\\n\n{tail}"  # literal \n before each line break
    fake = fx.build(tmp_path / "fixture")
    profile = fake.home / ".bash_profile"
    profile.write_text(
        f'export GH_AUTH_HEADER="Authorization: token {fx.GITHUB_S05}"\n'  # 1
        f"export GH_TOKEN={fx.GITHUB_S05}\n"  # 2
        f'export APP_KEY="{key}"\n'  # 3-5: not fully read, complete key
        f'export OLD_KEY="{head}\n'  # 6: no END line
        f'export NEW_KEY="{head}\n'  # 7: no END line
    )
    result = take_inventory(InventoryInputs(
        home=fake.home, project=fake.project, key_path=fake.key,
    ))
    report = result.report
    found = {c.name: c for c in report.credentials if c.location.display == "~/.bash_profile"}
    assert sorted(found) == ["APP_KEY", "GH_AUTH_HEADER", "GH_TOKEN", "NEW_KEY", "OLD_KEY"]
    records = {r.credential_id: r for r in result.store.records}
    data = profile.read_bytes()

    def stored(name: str) -> list[bytes]:
        return [data[s:e] for s, e in records[found[name].id].offsets]

    token = stored("GH_AUTH_HEADER") == [fx.GITHUB_S05.encode()]
    assert token and found["GH_TOKEN"].id in found["GH_AUTH_HEADER"].same_value_as
    whole = stored("APP_KEY") == [key.encode()]
    assert whole and found["APP_KEY"].value_state is ValueState.LITERAL
    for name in ("OLD_KEY", "NEW_KEY"):
        cred = found[name]
        assert cred.value_state is ValueState.PARTIAL and cred.same_value_as == []
        assert cred.id not in records
    assert [(p.line, p.reason) for p in report.not_fully_read] == [
        (3, PartlyReadReason.UNCLOSED_PEM), (6, PartlyReadReason.UNCLOSED_PEM),
        (7, PartlyReadReason.UNCLOSED_PEM),
    ]
    _assert_clean({
        "report": encode_report(report),
        "screen": "\n".join(inventory_lines(report, unknown_list_path=None)),
        "unknown-list": "\n".join(unknown_list_lines([*report.env_unknown, *report.env_fine])),
    })


def test_no_test_file_or_cache_restates_a_value() -> None:
    """Only the fixture module may hold values: no snapshot, expectation or
    other inventory test file restates one. Their compiled caches are scanned
    too, except the fixture module's own bytecode, a copy of its source."""
    blobs: dict[str, str | bytes] = {}
    for path in sorted(_TESTS_DIR.rglob("*")):
        if not path.is_file() or path.name.startswith("inventory_fakehome."):
            continue
        if "inventory" not in path.name:
            continue
        blobs[path.relative_to(_TESTS_DIR).as_posix()] = path.read_bytes()
    _assert_clean(blobs)
