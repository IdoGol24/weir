"""End to end: `weir inventory` over the fake home finds every planted
credential from all four sources, and nothing else.

Expectations come from the fixture's own declaration of what it planted
(`inventory_fakehome.PLANTS`) and from the bytes it wrote, never from the
inventory's output. The mutation tests at the bottom break one source at a
time and show the comparison notices.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import subprocess
import sys
from pathlib import Path

import inventory_fakehome as fx
import msgspec
import pytest
from click.testing import CliRunner

import weir.inventory.core as core
import weir.inventory.locations as locations
from weir.cli.main import main
from weir.inventory import (
    Inventory,
    InventoryInputs,
    InventoryResult,
    Source,
    ValueState,
    encode_report,
    encode_store,
    take_inventory,
)
from weir.inventory.text import inventory_lines


@pytest.fixture
def fake(tmp_path: Path) -> fx.FakeHome:
    return fx.build(tmp_path)


def _inputs(fake: fx.FakeHome, **overrides: object) -> InventoryInputs:
    args: dict[str, object] = {
        "home": fake.home,
        "project": fake.project,
        "key_path": fake.key,
        "env_file": fake.env_file,
        "gitleaks_reports": [fake.gitleaks],
        "trufflehog_reports": [fake.trufflehog],
    }
    args.update(overrides)
    return InventoryInputs(**args)  # type: ignore[arg-type]


def _run(fake: fx.FakeHome) -> InventoryResult:
    return take_inventory(_inputs(fake))


Key = tuple[str, str, str, int | None]


def _key(plant_or_cred: object) -> Key:
    """(source, displayed location, name, line): what a person sees."""
    if isinstance(plant_or_cred, fx.Plant):
        p = plant_or_cred
        return p.source, p.display, p.name, p.line
    c = plant_or_cred
    return c.source.value, c.location.display, c.name, c.location.line  # type: ignore[attr-defined]


def missing_plants(report: Inventory, fake: fx.FakeHome) -> list[Key]:
    found = {_key(c) for c in report.credentials}
    return sorted({_key(p) for p in fake.plants} - found)


def _lacks(missing: list[Key], source: str, display: str, name: str) -> bool:
    return any(k[:3] == (source, display, name) for k in missing)


def test_finds_every_planted_credential_and_nothing_else(fake: fx.FakeHome) -> None:
    report = _run(fake).report
    assert missing_plants(report, fake) == []
    planted = {_key(p) for p in fake.plants}
    extra = sorted({_key(c) for c in report.credentials} - planted)
    assert extra == [], "credentials the fixture did not plant (false positives)"
    # One record per plant: nothing double-counted.
    assert len(report.credentials) == len(fake.plants)


def test_every_source_contributes(fake: fx.FakeHome) -> None:
    report = _run(fake).report
    by_source = {s: {_key(c) for c in report.credentials if c.source is s} for s in Source}
    for source in Source:
        expected = {_key(p) for p in fake.plants if p.source == source.value}
        assert expected and by_source[source] == expected, source


def _keyed(value: str) -> str:
    return hmac.new(bytes.fromhex(fx.TEST_KEY_HEX), value.encode(), hashlib.sha256).hexdigest()


def test_store_holds_keyed_fingerprints_and_true_offsets(fake: fx.FakeHome) -> None:
    """Every planted literal value, and nothing else, is in the store as its
    keyed fingerprint at offsets that hold it. Comparisons are booleans, so
    a failure prints the plant's key and never a value."""
    result = _run(fake)
    by_key = {_key(c): c for c in result.report.credentials}
    records = {r.credential_id: r for r in result.store.records}
    literal: set[str] = set()
    for plant in fake.plants:
        cred = by_key[_key(plant)]
        if plant.value is None:
            assert cred.value_state is not ValueState.LITERAL
            continue
        assert cred.value_state is ValueState.LITERAL
        literal.add(cred.id)
        record = records[cred.id]
        keyed = record.fingerprint == _keyed(plant.value)
        assert keyed, f"fingerprint is not HMAC-SHA256 of the planted value for {_key(plant)}"
        # Keyed, not a plain hash: an unkeyed sha256 would be a dictionary target.
        plain = record.fingerprint == hashlib.sha256(plant.value.encode()).hexdigest()
        assert not plain
        if record.path is None or not record.offsets:
            continue
        data = Path(record.path).read_bytes()
        forms = {plant.value.encode(), json.dumps(plant.value)[1:-1].encode()}
        for start, end in record.offsets:
            located = data[start:end] in forms
            assert located, f"offset {start}:{end} of {_key(plant)} does not hold its value"
    assert set(records) == literal


def test_env_unknown_fine_ignored_and_not_scanned(fake: fx.FakeHome) -> None:
    report = _run(fake).report
    assert sorted({e.name for e in report.env_unknown}) == sorted(fake.unknown_env)
    assert sorted({e.name for e in report.env_fine}) == sorted(fake.fine_env)
    assert [g.display for g in report.git_ignored] == sorted(fake.git_ignored)
    for ignored in report.git_ignored:
        routes = {r.route: r.status.value for r in ignored.routes}
        assert routes == {
            "grep_tool": "hidden", "read_tool": "reachable", "cat": "reachable",
            "grep_r": "reachable",
        }
    flagged = {c.location.display for c in report.credentials if c.git_ignored}
    assert flagged == set(fake.git_ignored)
    assert sorted((n.display, n.reason.value) for n in report.not_scanned) == sorted(
        fake.not_scanned
    )


def test_deterministic_and_the_report_does_not_depend_on_the_key(
    fake: fx.FakeHome, tmp_path: Path
) -> None:
    first, second = _run(fake), _run(fake)
    assert encode_report(first.report) == encode_report(second.report)
    assert encode_store(first.store) == encode_store(second.store)
    other_key = tmp_path / "other.key"
    other = take_inventory(_inputs(fake, key_path=other_key))
    assert encode_report(other.report) == encode_report(first.report)
    assert encode_store(other.store) != encode_store(first.store)


def test_ids_survive_moving_the_home(fake: fx.FakeHome, tmp_path: Path) -> None:
    before = {_key(c): c.id for c in _run(fake).report.credentials}
    moved_root = tmp_path / "elsewhere"
    shutil.copytree(fake.root, moved_root, ignore=shutil.ignore_patterns("elsewhere"))
    moved = fx.FakeHome(**{
        **fake.__dict__,
        "root": moved_root,
        "home": moved_root / "fakehome",
        "project": moved_root / "fakehome/work/proj",
        "env_file": moved_root / "launch.env",
        "gitleaks": moved_root / "gitleaks.json",
        "trufflehog": moved_root / "trufflehog.jsonl",
        "key": moved_root / "test.key",
    })
    after = {_key(c): c.id for c in _run(moved).report.credentials}
    # The gitleaks report names one file by absolute path, so that record
    # moves with it; every other id is unchanged.
    changed = {k[:3] for k in before if before[k] != after.get(k)}
    assert changed <= {("project_scan", "./src/app.py", "github_token")}


def _cli(fake: fx.FakeHome, *extra: str) -> tuple[int, str]:
    args = [
        "inventory", "--home", str(fake.home), "--project", str(fake.project),
        "--env-file", str(fake.env_file), "--gitleaks", str(fake.gitleaks),
        "--trufflehog", str(fake.trufflehog), "--key", str(fake.key), *extra,
    ]
    result = CliRunner().invoke(main, args)
    return result.exit_code, result.output


def test_cli_json_is_the_report(fake: fx.FakeHome) -> None:
    code, out = _cli(fake, "--json")
    assert code == 0
    decoded = msgspec.json.decode(out.encode(), type=Inventory)
    assert decoded == _run(fake).report
    assert missing_plants(decoded, fake) == []


def test_cli_text_lists_every_credential_by_name(fake: fx.FakeHome) -> None:
    code, out = _cli(fake)
    assert code == 0
    for plant in fake.plants:
        assert plant.name in out
        assert plant.display in out
    assert f"unknown environment variables: {len(fake.unknown_env)}" in out


def test_cli_unknown_list_file_and_strict(fake: fx.FakeHome, tmp_path: Path) -> None:
    listing = tmp_path / "out" / "unknown.txt"
    code, out = _cli(fake, "--unknown-list", str(listing))
    assert code == 0
    names = [line.split("\t")[0] for line in listing.read_text().splitlines()]
    assert sorted(names) == sorted(fake.unknown_env)
    assert str(listing.as_posix()) in out
    strict_code, _ = _cli(fake, "--unknown-list", str(listing), "--strict")
    assert strict_code == 1


def test_cli_strict_passes_when_every_unknown_is_marked_fine(fake: fx.FakeHome) -> None:
    reach = fake.project / ".weir/reach.yml"
    text = reach.read_text().replace("mark: review", "mark: fine")
    listed = {line.split("env:", 1)[1] for line in text.splitlines() if "location: env:" in line}
    text += "".join(
        f"  - location: env:{name}\n    evidence:\n      - src/app.py:1\n"
        f"    reason: read by the app\n    mark: fine\n"
        for name in fake.unknown_env if name not in listed
    )
    reach.write_text(text)
    code, _ = _cli(fake, "--strict")
    assert code == 0


def test_cli_store_is_written_private(fake: fx.FakeHome, tmp_path: Path) -> None:
    store = tmp_path / "state" / "store.json"
    code, _ = _cli(fake, "--store", str(store))
    assert code == 0
    assert store.read_bytes() == encode_store(_run(fake).store)
    if sys.platform != "win32":
        assert store.stat().st_mode & 0o777 == 0o600


def test_cli_default_state_lands_in_the_given_home(fake: fx.FakeHome) -> None:
    args = ["inventory", "--home", str(fake.home), "--project", str(fake.project)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0
    assert (fake.home / ".weir/fingerprint.key").is_file()
    assert (fake.home / ".weir/unknown-env.txt").is_file()
    assert "launch env  not given" in result.output


def test_cli_requires_an_explicit_home() -> None:
    result = CliRunner().invoke(main, ["inventory"])
    assert result.exit_code == 2
    assert "--home" in result.output


def test_process_env_is_the_launch_environment(fake: fx.FakeHome, tmp_path: Path) -> None:
    """A real subprocess with a fully specified environment: nothing of the
    test runner's own environment reaches the inventory."""
    env = {"ACME_DEPLOY_TOKEN": fx.MARKER_USERMCP, "PATH": "/usr/bin:/bin", "CI": "true"}
    if sys.platform == "win32":
        env["SYSTEMROOT"] = r"C:\Windows"
    proc = subprocess.run(
        [sys.executable, "-m", "weir.cli.main", "inventory", "--home", str(fake.home),
         "--project", str(fake.project), "--key", str(fake.key), "--process-env", "--json",
         "--unknown-list", str(tmp_path / "u.txt")],
        env=env, capture_output=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")[-200:]
    report = msgspec.json.decode(proc.stdout, type=Inventory)
    launch = {c.name for c in report.credentials if c.location.display == "launch env"}
    assert "ACME_DEPLOY_TOKEN" in launch
    assert report.inputs.env_source.value == "process"


def test_api_process_env_mapping(fake: fx.FakeHome) -> None:
    result = take_inventory(_inputs(
        fake, env_file=None, process_env={"ACME_DEPLOY_TOKEN": fx.MARKER_USERMCP}
    ))
    launch = [c for c in result.report.credentials if c.location.display == "launch env"]
    assert [c.name for c in launch] == ["ACME_DEPLOY_TOKEN"]
    assert launch[0].location.path is None
    [record] = [r for r in result.store.records if r.credential_id == launch[0].id]
    keyed = record.fingerprint == _keyed(fx.MARKER_USERMCP)
    assert keyed and record.path is None and record.offsets == []


def test_paths_named_through_dot_dot_give_the_same_inventory(fake: fx.FakeHome) -> None:
    """The gitleaks report names src/app.py by its normalized absolute path:
    it merges with weir's own hit only if the walk normalizes the project."""
    dotted = take_inventory(_inputs(
        fake, home=fake.home / "work" / "..", project=fake.project / ".." / "proj",
        env_file=fake.home / ".." / fake.env_file.name,
    ))
    first = _run(fake)
    assert encode_report(dotted.report) == encode_report(first.report)
    assert encode_store(dotted.store) == encode_store(first.store)


def _project_plants(fake: fx.FakeHome) -> set[str]:
    """Displays of the plants in project files that exist."""
    return {
        p.display for p in fake.plants
        if p.display.startswith("./") and (fake.project / p.display[2:]).is_file()
    }


def test_ignore_rules_above_a_project_inside_a_repository_apply(fake: fx.FakeHome) -> None:
    repo = fake.project.parent
    (repo / ".git/info").mkdir(parents=True)
    (repo / ".git/info/exclude").write_text("/proj/src/vault.go\n")
    (repo / ".gitignore").write_text("logs/\n")
    above = {"./src/vault.go", "./logs/session.json"}
    assert above <= _project_plants(fake) and not above & set(fake.git_ignored)
    report = _run(fake).report
    assert [g.display for g in report.git_ignored] == sorted({*fake.git_ignored, *above})


def test_a_project_in_an_ignored_directory_is_wholly_ignored(fake: fx.FakeHome) -> None:
    repo = fake.project.parent
    (repo / ".git").mkdir()
    (repo / ".gitignore").write_text(f"{fake.project.name}/\n")
    report = _run(fake).report
    assert {g.display for g in report.git_ignored} == _project_plants(fake)


@pytest.mark.parametrize("form", ["redact", "redact-percent", "not-in-the-file"])
def test_a_scanner_value_its_file_does_not_hold_is_never_fingerprinted(
    fake: fx.FakeHome, tmp_path: Path, form: str
) -> None:
    findings = json.loads(fake.gitleaks.read_text())
    for finding in findings:
        finding["Secret"] = {
            "redact": "REDACTED", "redact-percent": finding["Secret"][:4] + "...",
            "not-in-the-file": fx.DECOY_D1,
        }[form]
        finding["Match"] = "REDACTED"
    report_path = tmp_path / "gitleaks-redacted.json"
    report_path.write_text(json.dumps(findings))
    result = take_inventory(_inputs(fake, gitleaks_reports=[report_path]))
    [plant] = [p for p in fake.plants if p.display == "./src/legacy.cfg"]
    legacy = [c for c in result.report.credentials if c.location.display == plant.display]
    assert [(c.name, c.location.line, c.value_state) for c in legacy] == [
        (plant.name, plant.line, ValueState.NOT_IN_FILE)
    ]
    assert legacy[0].id not in {r.credential_id for r in result.store.records}
    [row] = [
        line for line in inventory_lines(result.report, unknown_list_path=None)
        if f"{plant.display}:{plant.line}" in line
    ]
    assert row.endswith("(value not in the file)")


@pytest.mark.parametrize("option", ["--store", "--unknown-list", "--key"])
def test_an_output_that_cannot_be_written_exits_2(
    fake: fx.FakeHome, tmp_path: Path, option: str
) -> None:
    if option == "--key":
        if sys.platform == "win32":
            pytest.skip("symlinks need privileges on Windows")
        # Absent, so the key is created; its directory cannot be.
        blocker = tmp_path / "dangling"
        blocker.symlink_to(tmp_path / "absent")
    else:
        blocker = tmp_path / "a-file"
        blocker.write_text("")
    target = blocker / "out"
    args = [
        "inventory", "--home", str(fake.home), "--project", str(fake.project),
        "--key", str(fake.key), option, str(target),
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "error: cannot" in result.stderr and str(target) in result.stderr


# --- mutations: each comparison above must notice a broken source ----------


def test_mutation_dropping_a_standard_location_is_noticed(
    fake: fx.FakeHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    kept = tuple(loc for loc in locations.STANDARD_LOCATIONS if loc.id != "docker_config")
    monkeypatch.setattr(core, "STANDARD_LOCATIONS", kept)
    missing = missing_plants(_run(fake).report, fake)
    assert _lacks(missing, "standard_location", "~/.docker/config.json", "auth")


def test_mutation_a_blind_name_rule_is_noticed(
    fake: fx.FakeHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    import weir.inventory.classify as classify
    import weir.inventory.project as project

    monkeypatch.setattr(classify, "name_suggests_secret", lambda name: False)
    monkeypatch.setattr(project, "name_suggests_secret", lambda name: False)
    missing = missing_plants(_run(fake).report, fake)
    assert _lacks(missing, "environment", "launch env", "ACME_DEPLOY_TOKEN")
    assert _lacks(missing, "project_scan", "./config/settings.json", "db_password")


def test_mutation_ignoring_scanner_reports_is_noticed(fake: fx.FakeHome) -> None:
    report = take_inventory(_inputs(fake, gitleaks_reports=[], trufflehog_reports=[])).report
    missing = missing_plants(report, fake)
    assert _lacks(missing, "project_scan", "./src/legacy.cfg", "gitleaks:generic-api-key")
    assert _lacks(missing, "project_scan", "./notes/handoff.txt", "trufflehog:Dockerhub")


def test_mutation_skipping_startup_files_is_noticed(
    fake: fx.FakeHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(core, "STARTUP_FILES", ())
    missing = missing_plants(_run(fake).report, fake)
    assert _lacks(missing, "environment", "~/.bashrc", "ACME_DEPLOY_TOKEN")


def test_mutation_losing_the_map_is_noticed(fake: fx.FakeHome) -> None:
    (fake.project / ".weir/reach.yml").unlink()
    report = _run(fake).report
    missing = missing_plants(report, fake)
    assert _lacks(missing, "map", "~/.config/acme/session.bin", "session.bin")
    assert sorted(fake.fine_env) != sorted(e.name for e in report.env_fine)


def test_mutation_a_gitignore_that_ignores_nothing_is_noticed(
    fake: fx.FakeHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    import weir.inventory.gitignore as gitignore

    monkeypatch.setattr(gitignore.GitIgnore, "ignored", lambda self, rel, *, is_dir: False)
    report = _run(fake).report
    assert [g.display for g in report.git_ignored] != sorted(fake.git_ignored)
