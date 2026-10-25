"""`weir statusline setup` with no flags (docs/statusline.md, "Setup and
undo"), written before the implementation.

FAKE DATA ONLY. Every run uses a fake home under the temporary directory, a
fake Claude config directory inside it and a launch environment of fake
values only: the process environment is cleared for the run and holds
nothing but HOME, CLAUDE_CONFIG_DIR and the fake credentials, so no real
environment, home or setting is read.

1. Two commands are enough: setup with no flags inventories the home and
   this shell's environment into ~/.weir, and the status line it installs
   counts what a real `weir audit` of the session counts. It walks the
   current folder as the project only on an exact `yes` to its offer, and
   never offers the home or a folder that holds it.
2. The preview lists the inventory as `weir inventory` lists it, names
   only: never a value or a 6-character run of one.
3. Nothing is written before the exact `yes`: not the key, the store, the
   inventory report or the settings.
4. An inventory already at the default path is used, not taken again.
5. The flags keep working and each overrides its default; a store or key
   left to its default must exist when --inventory is given.
6. A key file others can read is refused, as `weir inventory` refuses it.
7. Setup then undo leaves the settings byte-identical and ~/.weir in place.
8. An interrupted setup leaves a state that a re-run finishes.
10. The current folder is offered before a first inventory: the preview
    and the refresh command show the choice.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx
from click.testing import CliRunner

import weir.cli.main as cli
from weir.cli.main import main
from weir.statusline import setup as statusline_setup

pytestmark = sx.posix_shell

SESSION_ID = fx.SESSION_ID
ACME, GH, AWS_SECRET = "ACME_API_TOKEN", "GH_TOKEN", "aws_secret_access_key"
OFFER = "Type yes to include: "
NO_FOLDER = "  No project folder is included: project files are not scanned"


class Home:
    """A fake home: a fake ~/.aws/credentials, a fake project to run setup
    from, an empty Claude config directory, and a fake launch environment."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "home"
        self.project = self.home / "work" / "proj"
        self.project.mkdir(parents=True)
        self.config = self.home / ".claude"
        (self.config / "projects" / sx.PROJECT).mkdir(parents=True)
        self.values = {
            ACME: cfx.fake_value("default-setup-acme"),
            GH: cfx.fake_value("default-setup-gh"),
            AWS_SECRET: cfx.fake_value("default-setup-aws", 40),
        }
        (self.home / ".aws").mkdir()
        cfx.write(
            self.home / ".aws" / "credentials",
            f"[default]\n{AWS_SECRET} = {self.values[AWS_SECRET]}\n",
        )
        # One variable the inventory cannot judge: the count shows it. A
        # UTF-8 locale, or a Python started without one sets LC_CTYPE in its
        # own environment (PEP 538) and sees one variable more.
        self.env = {
            "HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.config), "LANG": "C.UTF-8",
            ACME: self.values[ACME], GH: self.values[GH], "WIDGET_FLAVOUR": "plum-crumble",
        }

    @property
    def weir(self) -> Path:
        return self.home / ".weir"

    @property
    def report(self) -> Path:
        return self.weir / "inventory.json"

    @property
    def store(self) -> Path:
        return self.weir / "store.json"

    @property
    def key(self) -> Path:
        return self.weir / "fingerprint.key"

    @property
    def settings(self) -> Path:
        return self.config / "settings.json"

    def transcript(self) -> Path:
        return self.config / "projects" / sx.PROJECT / f"{SESSION_ID}.jsonl"

    def snapshot(self) -> dict[str, bytes]:
        """Every file under the temporary directory, and every directory."""
        return {
            str(p.relative_to(self.root)): p.read_bytes() if p.is_file() else b"<dir>"
            for p in sorted(self.root.rglob("*"))
        }

    def invoke(
        self, monkeypatch: pytest.MonkeyPatch, args: list[str], stdin: str | None = None,
        cwd: Path | None = None,
    ) -> sx.Run:
        """weir in this process, its environment only the fake one, run
        from `cwd`, else the fake project."""
        with monkeypatch.context() as m:
            for name in list(os.environ):
                m.delenv(name)
            for name, value in self.env.items():
                m.setenv(name, value)
            m.chdir(cwd or self.project)
            result = CliRunner().invoke(main, args, input=stdin, catch_exceptions=False)
        return sx.Run(result.exit_code, result.stdout, result.stderr)

    def process(self, args: list[str], stdin: str = "") -> sx.Run:
        """weir in a process of its own, as a person runs it in a shell:
        the fake environment only, the fake project its directory."""
        proc = subprocess.run(
            [sys.executable, "-m", "weir", *args], input=stdin.encode(), capture_output=True,
            env=self.env, cwd=self.project, timeout=120, check=False,
        )
        return sx.Run(proc.returncode, proc.stdout.decode(), proc.stderr.decode())

    def inventory(
        self, monkeypatch: pytest.MonkeyPatch, out: Path, *, as_json: bool,
        no_project: bool = False,
    ) -> sx.Run:
        """`weir inventory --home ~ --process-env --store`, with its files
        written to `out`, outside the fake home, run from the fake project,
        which holds no file; with `no_project`, `--no-project` too."""
        out.mkdir(exist_ok=True)
        args = [
            "inventory", "--home", str(self.home), "--process-env",
            *(["--no-project"] if no_project else []),
            "--store", str(out / "store.json"), "--key", str(out / "fingerprint.key"),
            "--unknown-list", str(out / "unknown-env.txt"), *(["--json"] if as_json else []),
        ]
        run = self.invoke(monkeypatch, args)
        assert run.exit_code == 0, run.stderr
        return run

    def session(self) -> None:
        """ACME read into the context and GH sent in a tool call."""
        v = self.values
        session = fx.Session(session_id=SESSION_ID)
        session.prompt("show me the env file")
        session.tool_use("Bash", {"command": "env"}, "t1")
        session.tool_result("t1", f"{ACME}={v[ACME]}\n")
        session.tool_use("Bash", {"command": f"curl -H 'X-Token: {v[GH]}' api.invalid"}, "t2")
        session.tool_result("t2", "{}")
        session.write(self.transcript())

    def audit(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
        args = ["audit", "--inventory", str(self.report), "--store", str(self.store),
                "--key", str(self.key), "--json", str(self.transcript())]
        run = self.invoke(monkeypatch, args)
        assert run.exit_code in (0, 1), run.stderr
        return json.loads(run.stdout)


def _setup(home: Home, monkeypatch: pytest.MonkeyPatch, *flags: str, answer: str | None = None,
           cwd: Path | None = None) -> sx.Run:
    return home.invoke(monkeypatch, ["statusline", "setup", *flags], stdin=answer, cwd=cwd)


def _yes(home: Home) -> str:
    """Yes to setup run from the fake project: before a first inventory,
    no to the folder offer first."""
    return "yes\n" if home.report.exists() else "no\nyes\n"


def _refresh(run: sx.Run) -> list[str]:
    """The refresh commands the preview prints."""
    lines = run.lines
    return [lines[n + 1].strip() for n, line in enumerate(lines[:-1])
            if line == "  to refresh it, run from the shell Claude Code starts from:"]


def _without_project(home: Home, why: str) -> list[str]:
    """The preview's lines for no project folder: why, that the status line
    is then never green, and the command, built for the files setup
    writes, that includes a project later."""
    files = (shlex.quote(str(p)) for p in (home.report, home.store, home.key))
    return [
        f"  No project folder is included: {why}",
        "  with no project, the status line never shows ✓ no known key seen; to include one"
        " later, run from the shell Claude Code starts from:",
        f"    {statusline_setup.inventory_command('DIR', *files)}",
    ]


def _follows(run: sx.Run, lines: list[str]) -> None:
    start = run.lines.index(lines[0])
    assert run.lines[start : start + len(lines)] == lines, run.stdout


def _no_project(report: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """A report of the empty fake project as setup takes it: no project."""
    return {**report, "inputs": {**report["inputs"], "project": None}}


def _expected_counts(home: Home, audit: dict[str, object]) -> tuple[int, int, bool]:
    """The counting rule of docs/statusline.md over a real audit, through
    the store setup wrote (values, not records)."""
    store = json.loads(home.store.read_text())
    group = {r["credential_id"]: r["fingerprint"] for r in store["records"]}
    context = {group.get(h["credential"], h["credential"]) for h in audit["hits"]  # type: ignore[union-attr]
               if h["kind"] in ("context", "tool_call")}
    sent = {group.get(h["credential"], h["credential"]) for h in audit["hits"]  # type: ignore[union-attr]
            if h["kind"] == "tool_call"}
    return len(context), len(sent), bool(audit["unknown"])


# --- 1. two commands --------------------------------------------------------------


def test_setup_with_no_flags_inventories_the_home_and_installs_a_working_status_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    expected_report = home.inventory(monkeypatch, tmp_path / "independent", as_json=True).stdout
    home.session()

    run = home.process(["statusline", "setup"], stdin="no\nyes\n")

    assert run.exit_code == 0, run.stderr
    # The inventory is the one `weir inventory --home ~ --process-env` takes
    # from an empty project, but for the project it names: none.
    assert json.loads(home.report.read_text()) == _no_project(json.loads(expected_report))
    for private in (home.key, home.store, home.report):
        assert stat.S_IMODE(private.stat().st_mode) == 0o600, private
    names = {c["name"] for c in json.loads(expected_report)["credentials"]}
    assert set(home.values) <= names
    # The status line it installed reads those files and counts what the
    # audit counts.
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    for path in (home.report, home.store, home.key):
        assert str(path) in command
    payload = sx.status_json(home.transcript(), SESSION_ID, str(home.project))
    shown = sx.run_shell(command, payload, home.env)
    expected = _expected_counts(home, home.audit(monkeypatch))
    assert expected[:2] == (2, 1)
    assert shown.stdout == sx.segment_for(expected, colour=True) + "\n"
    cfx.assert_value_free(run.stdout + run.stderr, home.values.values())


# --- 2. the preview ---------------------------------------------------------------


def test_the_preview_lists_the_inventory_by_name_and_never_a_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    listing = home.inventory(
        monkeypatch, tmp_path / "independent", as_json=False, no_project=True).lines
    report = json.loads(home.inventory(monkeypatch, tmp_path / "again", as_json=True).stdout)

    run = _setup(home, monkeypatch, "--dry-run")

    assert run.exit_code == 0, run.stderr
    shown = run.lines
    # Every line `weir inventory --no-project` prints, but the file it wrote
    # the unknown names to, which setup writes on yes.
    unknown = f"unknown environment variables: {report['counts']['env_unknown']}"
    for line in listing:
        if line.startswith("unknown environment variables: "):
            line = f"{unknown} (names in {home.weir / 'unknown-env.txt'})"
        assert ("  " + line if line else "") in shown, line
    assert report["counts"]["env_unknown"] >= 1
    for credential in report["credentials"]:
        assert any(credential["name"] in s and credential["location"]["display"] in s
                   for s in shown), credential["name"]
    assert "this shell's environment" in run.stdout
    assert "Claude Code starts with" in run.stdout
    assert NO_FOLDER in shown
    cfx.assert_value_free(run.stdout + run.stderr, home.values.values())


def test_a_first_setup_run_from_the_home_walks_no_project_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run from the home itself: a file under a cache directory and a past
    Claude Code transcript, each holding a fake credential, are neither
    read nor listed. `weir inventory` run from there lists both."""
    home = Home(tmp_path)
    planted = {
        "cache": cfx.fake_value("default-setup-cache"),
        "transcript": cfx.fake_value("default-setup-transcript"),
    }
    cache = home.home / ".cache" / "some-tool" / "settings.env"
    cache.parent.mkdir(parents=True)
    cfx.write(cache, f"PLANTED_API_TOKEN={planted['cache']}\n")
    session = fx.Session(session_id="11111111-2222-4333-8444-555555555555")
    session.tool_use("Bash", {"command": "env"}, "t1")
    session.tool_result("t1", f"OLD_API_TOKEN={planted['transcript']}\n")
    transcript = home.config / "projects" / sx.PROJECT / "old-session.jsonl"
    session.write(transcript)
    walked = home.invoke(
        monkeypatch, ["inventory", "--home", str(home.home), "--process-env", "--json",
                      "--store", str(tmp_path / "walked.json"),
                      "--key", str(tmp_path / "walked.key")], cwd=home.home,
    )
    walked_displays = {c["location"]["display"] for c in json.loads(walked.stdout)["credentials"]}
    assert {"./.cache/some-tool/settings.env", "./.claude/projects/" + sx.PROJECT
            + "/old-session.jsonl"} <= walked_displays
    read: list[Path] = []
    real_read_bytes, real_open = Path.read_bytes, Path.open

    def read_bytes(self: Path) -> bytes:
        read.append(self.absolute())
        return real_read_bytes(self)

    def open_(self: Path, *args: object, **kwargs: object) -> object:
        read.append(self.absolute())
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    with monkeypatch.context() as m:
        m.setattr(Path, "read_bytes", read_bytes)
        m.setattr(Path, "open", open_)
        run = _setup(home, monkeypatch, answer="yes\n", cwd=home.home)

    assert run.exit_code == 0, run.stderr
    assert OFFER not in run.stdout
    assert cache not in read and transcript not in read
    report = json.loads(home.report.read_text())
    assert report["inputs"]["project"] is None
    for text in (run.stdout, home.report.read_text(), home.store.read_text()):
        assert "settings.env" not in text and "old-session" not in text
    assert "PLANTED_API_TOKEN" not in run.stdout and "OLD_API_TOKEN" not in run.stdout
    cfx.assert_value_free(run.stdout + run.stderr, [*home.values.values(), *planted.values()])


@pytest.mark.parametrize("folder", ["no", "yes"])
def test_the_printed_refresh_command_reproduces_the_first_inventory(
    tmp_path: Path, folder: str,
) -> None:
    """Setup, then the refresh command its preview prints, each run by a
    shell with the fake home and the same fake environment: the second
    report and store are the first, byte for byte, with the project folder
    or without it as chosen."""
    home = Home(tmp_path)
    cfx.write(home.project / ".env", f"PROJECT_API_TOKEN={cfx.fake_value('default-setup-proj')}\n")
    env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", **home.env}

    def shell(command: str, stdin: str = "") -> sx.Run:
        proc = subprocess.run(
            ["sh", "-c", command], input=stdin.encode(), capture_output=True, env=env,
            cwd=home.project, timeout=120, check=False,
        )
        return sx.Run(proc.returncode, proc.stdout.decode(), proc.stderr.decode())

    setup = shell("weir statusline setup", f"{folder}\nyes\n")
    assert setup.exit_code == 0, setup.stderr
    first = {p: p.read_bytes() for p in (home.report, home.store, home.key)}
    printed = _refresh(setup)
    assert len(printed) == 1, setup.stdout
    home.report.unlink()
    home.store.unlink()

    refresh = shell(printed[0])

    assert refresh.exit_code == 0, refresh.stderr
    assert {p: p.read_bytes() for p in first} == first
    report = json.loads(first[home.report])
    assert report["inputs"]["project"] == (str(home.project) if folder == "yes" else None)
    names = {c["name"] for c in report["credentials"]}
    assert ("PROJECT_API_TOKEN" in names) is (folder == "yes")


@sx.posix_shell
def test_switching_the_project_as_the_preview_says_never_leaves_the_earlier_one_green(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup with the current folder as the project, then the refresh
    command switched to another project as the preview says: the earlier
    project's key stops being counted, and a session there is never green."""
    home = Home(tmp_path)
    token = cfx.fake_value("default-setup-proj")
    cfx.write(home.project / ".env", f"PROJECT_API_TOKEN={token}\n")
    other = home.home / "work" / "other"
    other.mkdir()
    env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", **home.env}

    def shell(command: str, stdin: str = "") -> sx.Run:
        return sx.run_shell(command, stdin, env, str(home.project))

    setup = shell("weir statusline setup", "yes\nyes\n")
    assert setup.exit_code == 0, setup.stderr
    assert "to switch the project" in setup.stdout
    assert "the earlier project's keys then stop being counted" in setup.stdout
    session = fx.Session(session_id=SESSION_ID)
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "t1")
    session.tool_result("t1", f"PROJECT_API_TOKEN={token}\n")
    session.write(home.transcript())
    status = json.loads(home.settings.read_text())["statusLine"]["command"]

    def line(folder: Path) -> str:
        return shell(status, sx.status_json(home.transcript(), SESSION_ID, str(folder))).stdout

    before = _expected_counts(home, home.audit(monkeypatch))
    assert before[:2] == (1, 0)
    assert line(home.project) == sx.segment_for(before, colour=True) + "\n"
    (printed,) = _refresh(setup)
    given = f"--project {shlex.quote(str(home.project))}"
    assert given in printed
    switched = shell(printed.replace(given, f"--project {shlex.quote(str(other))}"))
    assert switched.exit_code == 0, switched.stderr
    assert json.loads(home.report.read_text())["inputs"]["project"] == str(other)

    after = _expected_counts(home, home.audit(monkeypatch))
    assert after == (0, 0, False)
    assert line(home.project) == sx.segment_for(after, colour=True, inside=False) + "\n"
    assert line(other) == sx.segment_for(after, colour=True) + "\n"


@pytest.mark.parametrize("flag", ["--project", "--gitleaks", "--trufflehog"])
def test_no_project_is_refused_with_a_project_or_a_scanner_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str,
) -> None:
    home = Home(tmp_path)
    given = home.project if flag == "--project" else home.project / "scanner.json"
    if flag != "--project":
        given.write_text("[]" if flag == "--gitleaks" else "")
    before = home.snapshot()

    run = home.invoke(monkeypatch, [
        "inventory", "--home", str(home.home), "--no-project", flag, str(given),
        "--process-env", "--json", "--store", str(home.store),
    ])

    assert run.exit_code == 2
    assert "--no-project" in run.stderr
    assert run.stdout == ""
    assert home.snapshot() == before


# --- 3. nothing before yes --------------------------------------------------------


@pytest.mark.parametrize(
    "flags, answer",
    [(["--dry-run"], None), (["--dry-run"], "yes\nyes\n"), ([], "no\nno\n"), ([], ""),
     ([], "no\n"), ([], "yes\n"), ([], "yes\nno\n"), ([], "no\ny\n"), ([], "no\nYES\n"),
     ([], "no\n yes\n"), ([], "no\nyes please\n")],
    ids=["dry run", "dry run, folder", "no", "nothing", "folder no only", "folder yes only",
         "folder, no", "y", "YES", "space yes", "yes please"],
)
def test_nothing_is_written_before_the_exact_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str], answer: str | None,
) -> None:
    home = Home(tmp_path)
    home.settings.write_bytes(b'{"theme": "dark"}')
    before = home.snapshot()

    run = _setup(home, monkeypatch, *flags, answer=answer)

    assert run.exit_code == 0, run.stderr
    assert home.snapshot() == before
    assert not home.weir.exists()
    cfx.assert_value_free(run.stdout + run.stderr, home.values.values())


# --- 4. an existing inventory ------------------------------------------------------


@pytest.mark.parametrize("no_project", [False, True], ids=["project", "no project"])
def test_an_inventory_at_the_default_path_is_used_and_not_taken_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_project: bool,
) -> None:
    """No folder is offered, and the refresh command is the one a first
    setup prints for that inventory's project choice."""
    home = Home(tmp_path)
    first = home.inventory(monkeypatch, home.weir, as_json=True, no_project=no_project).stdout
    cfx.write(home.report, first)
    home.report.chmod(0o600)
    kept = {p: p.read_bytes() for p in (home.report, home.store, home.key)}
    # A variable added since: a new inventory would list it.
    home.env["LATE_API_TOKEN"] = cfx.fake_value("default-setup-late")
    count = len(json.loads(first)["credentials"])

    run = _setup(home, monkeypatch, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    assert f"inventory: {home.report} (existing, {count} credentials)" in run.lines
    assert OFFER not in run.stdout
    first_setup = _setup(Home(tmp_path / "other"), monkeypatch, "--dry-run",
                         answer="no\n" if no_project else "yes\n", cwd=home.project)
    assert _refresh(run) == _refresh(first_setup) != []
    assert "--project DIR" in run.stdout
    assert "LATE_API_TOKEN" not in run.stdout
    assert {p: p.read_bytes() for p in kept} == kept
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    for path in kept:
        assert str(path) in command


def test_an_inventory_without_its_store_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    cfx.write(home.report, home.inventory(monkeypatch, home.weir, as_json=True).stdout)
    home.store.unlink()
    before = home.snapshot()

    run = _setup(home, monkeypatch, answer=_yes(home))

    assert run.exit_code == 2
    assert str(home.store) in run.stderr
    assert home.snapshot() == before


# --- 5. the flags ---------------------------------------------------------------


def test_explicit_inventory_flags_take_no_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    out = tmp_path / "elsewhere"
    cfx.write(out / "inventory.json", home.inventory(monkeypatch, out, as_json=True).stdout)
    flags = ["--inventory", str(out / "inventory.json"), "--store", str(out / "store.json"),
             "--key", str(out / "fingerprint.key")]

    run = _setup(home, monkeypatch, *flags, answer="yes\n")

    assert run.exit_code == 0, run.stderr
    assert "weir inventory (names only" not in run.stdout
    assert not home.report.exists() and not home.store.exists() and not home.key.exists()
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    for path in ("inventory.json", "store.json", "fingerprint.key"):
        assert str(out / path) in command


def test_an_inventory_flag_without_its_store_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """docs/audit.md's inventory, then setup given only its report: the
    store is not at the default path, so every status line run would fail."""
    home = Home(tmp_path)
    taken = home.invoke(
        monkeypatch, ["inventory", "--home", str(home.home), "--json", "--store", "store.json"],
    )
    assert taken.exit_code == 0, taken.stderr
    cfx.write(home.project / "inventory.json", taken.stdout)
    assert home.key.is_file() and not home.store.exists()
    before = home.snapshot()

    runs = [_setup(home, monkeypatch, "--inventory", "inventory.json", "--dry-run"),
            _setup(home, monkeypatch, "--inventory", "inventory.json", answer="yes\n")]

    for run in runs:
        assert run.exit_code == 2
        assert str(home.store) in run.stderr and "nothing changed" in run.stderr
    assert home.snapshot() == before


def test_store_and_key_flags_place_a_first_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    out = tmp_path / "keys"
    flags = ["--store", str(out / "store.json"), "--key", str(out / "fingerprint.key")]

    run = _setup(home, monkeypatch, *flags, answer=_yes(home))

    assert run.exit_code == 0, run.stderr
    assert home.report.is_file()
    assert (out / "store.json").is_file() and (out / "fingerprint.key").is_file()
    assert not home.store.exists() and not home.key.exists()
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    for path in (home.report, out / "store.json", out / "fingerprint.key"):
        assert str(path) in command


# --- 6. the key ------------------------------------------------------------------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_key_file_others_can_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int,
) -> None:
    home = Home(tmp_path)
    home.weir.mkdir(mode=0o700)
    home.key.write_text("ab" * 32 + "\n")
    home.key.chmod(mode)
    before = home.snapshot()

    runs = [_setup(home, monkeypatch, "--dry-run"), _setup(home, monkeypatch, answer=_yes(home))]

    for run in runs:
        assert run.exit_code == 2
        assert str(home.key) in run.stderr
    assert home.snapshot() == before
    assert stat.S_IMODE(home.key.stat().st_mode) == mode  # refused, never repaired


def test_an_existing_private_key_is_used_and_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    home.weir.mkdir(mode=0o700)
    home.key.write_text("ab" * 32 + "\n")
    home.key.chmod(0o600)

    run = _setup(home, monkeypatch, answer=_yes(home))

    assert run.exit_code == 0, run.stderr
    assert home.key.read_text() == "ab" * 32 + "\n"
    home.session()
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    payload = sx.status_json(home.transcript(), SESSION_ID, str(home.project))
    shown = sx.run_shell(command, payload, home.env)
    assert shown.stdout == sx.segment_for(
        _expected_counts(home, home.audit(monkeypatch)), colour=True) + "\n"


# --- 7. undo ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "original", [None, b'{\n    "theme": "dark"\n}'], ids=["no settings", "settings"],
)
def test_setup_then_undo_leaves_the_settings_as_they_were_and_weir_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, original: bytes | None,
) -> None:
    home = Home(tmp_path)
    if original is not None:
        home.settings.write_bytes(original)

    setup = _setup(home, monkeypatch, answer=_yes(home))
    undo = home.invoke(monkeypatch, ["statusline", "undo"], stdin="yes\n")

    assert setup.exit_code == 0, setup.stderr
    assert undo.exit_code == 0, undo.stderr
    assert (home.settings.read_bytes() if home.settings.exists() else None) == original
    assert not (home.config / "commands" / "weir.md").exists()
    for kept in (home.report, home.store, home.key):
        assert kept.is_file(), kept


# --- 8. an interrupted setup -------------------------------------------------------


class Stopped(Exception):
    pass


@pytest.mark.parametrize("writes", [1, 2, 3, 4, 5])
def test_an_interrupted_first_setup_is_finished_by_a_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writes: int,
) -> None:
    """Stopped after the key, the store, the unknown names, the report, or
    the backup: running setup again, and undo after it, finish the job."""
    home = Home(tmp_path)
    home.settings.write_bytes(b'{"theme": "dark"}')
    home.session()
    done = 0

    def counted[F](real: F) -> F:
        def wrapper(*args: object, **kwargs: object) -> object:
            nonlocal done
            if done == writes:
                raise Stopped
            done += 1
            return real(*args, **kwargs)  # type: ignore[operator]
        return wrapper  # type: ignore[return-value]

    with monkeypatch.context() as m:
        m.setattr(cli, "write_private", counted(cli.write_private))
        m.setattr(cli, "write_new_key", counted(cli.write_new_key))  # pyright: ignore[reportAttributeAccessIssue]
        m.setattr(statusline_setup, "write_atomic", counted(statusline_setup.write_atomic))
        with pytest.raises(Stopped):
            _setup(home, monkeypatch, answer=_yes(home))

    rerun = _setup(home, monkeypatch, answer=_yes(home))
    if rerun.exit_code == 1:  # the backup was written: undo, then set up again
        assert "already set up" in rerun.stderr
        assert home.invoke(monkeypatch, ["statusline", "undo"], stdin="yes\n").exit_code == 0
        assert home.settings.read_bytes() == b'{"theme": "dark"}'
        rerun = _setup(home, monkeypatch, answer=_yes(home))

    assert rerun.exit_code == 0, rerun.stderr
    command = json.loads(home.settings.read_text())["statusLine"]["command"]
    payload = sx.status_json(home.transcript(), SESSION_ID, str(home.project))
    shown = sx.run_shell(command, payload, home.env)
    assert shown.stdout == sx.segment_for(
        _expected_counts(home, home.audit(monkeypatch)), colour=True) + "\n"


# --- 9. a directory setup or undo cannot write ---------------------------------------

needs_modes = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="owner mode bits do not bind root"
)


def _refused_plainly(run: sx.Run, path: Path, then: str) -> None:
    """Exit 2, no traceback, the real file named, and how to finish."""
    assert run.exit_code == 2, run.stdout + run.stderr
    assert "Traceback" not in run.stdout + run.stderr
    assert str(path) in run.stderr, run.stderr
    assert then in run.stderr, run.stderr


@needs_modes
def test_setup_refuses_plainly_when_the_command_directory_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    original = b'{\n    "theme": "dark"\n}'
    home.settings.write_bytes(original)
    commands = home.config / "commands"
    commands.mkdir(mode=0o500)
    try:
        run = _setup(home, monkeypatch, answer=_yes(home))
    finally:
        commands.chmod(0o700)

    # The backup was written first, so undo finishes it.
    _refused_plainly(run, commands / "weir.md", "weir statusline undo")
    assert home.settings.read_bytes() == original
    assert home.invoke(monkeypatch, ["statusline", "undo"], stdin="yes\n").exit_code == 0
    assert home.settings.read_bytes() == original
    assert _setup(home, monkeypatch, answer=_yes(home)).exit_code == 0


@needs_modes
def test_setup_refuses_plainly_when_the_claude_directory_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    original = b'{"theme": "dark"}'
    home.settings.write_bytes(original)
    home.config.chmod(0o500)
    try:
        run = _setup(home, monkeypatch, answer=_yes(home))
    finally:
        home.config.chmod(0o700)

    _refused_plainly(run, Path(str(home.settings) + ".weir-backup"), "weir statusline setup again")
    assert home.settings.read_bytes() == original
    # The inventory was written before the settings: a re-run uses it.
    rerun = _setup(home, monkeypatch, answer=_yes(home))
    assert rerun.exit_code == 0, rerun.stderr
    assert f"inventory: {home.report} (existing," in rerun.stdout


@needs_modes
def test_undo_refuses_plainly_when_the_claude_directory_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    original = b'{"theme": "dark"}'
    home.settings.write_bytes(original)
    assert _setup(home, monkeypatch, answer=_yes(home)).exit_code == 0
    set_up = home.settings.read_bytes()
    home.config.chmod(0o500)
    try:
        run = home.invoke(monkeypatch, ["statusline", "undo"], stdin="yes\n")
    finally:
        home.config.chmod(0o700)

    _refused_plainly(run, home.settings, "weir statusline undo again")
    assert home.settings.read_bytes() == set_up
    assert home.invoke(monkeypatch, ["statusline", "undo"], stdin="yes\n").exit_code == 0
    assert home.settings.read_bytes() == original


@needs_modes
def test_a_first_inventory_write_that_fails_names_the_real_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An existing key in a ~/.weir that cannot be written: the store is
    the first file written, and the message names it, not a temporary file."""
    home = Home(tmp_path)
    home.weir.mkdir(mode=0o700)
    home.key.write_text("ab" * 32 + "\n")
    home.key.chmod(0o600)
    home.settings.write_bytes(b'{"theme": "dark"}')
    home.weir.chmod(0o500)
    try:
        run = _setup(home, monkeypatch, answer=_yes(home))
    finally:
        home.weir.chmod(0o700)

    _refused_plainly(run, home.store, "weir statusline setup again")
    assert f".{home.store.name}." not in run.stderr
    assert home.settings.read_bytes() == b'{"theme": "dark"}'
    assert sorted(p.name for p in home.weir.iterdir()) == ["fingerprint.key"]


def test_an_inventory_flag_naming_a_missing_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    out = tmp_path / "elsewhere"
    home.inventory(monkeypatch, out, as_json=True)
    missing = out / "inventory.json"
    assert not missing.exists()
    flags = ["--inventory", str(missing), "--store", str(out / "store.json"),
             "--key", str(out / "fingerprint.key")]
    before = home.snapshot()

    runs = [_setup(home, monkeypatch, *flags, "--dry-run"),
            _setup(home, monkeypatch, *flags, answer="yes\n")]

    for run in runs:
        assert run.exit_code == 2
        assert str(missing) in run.stderr and "nothing changed" in run.stderr
    assert home.snapshot() == before


def test_with_no_project_the_listing_says_the_map_was_not_looked_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A map lives in a project, so with no project there is none to find."""
    home = Home(tmp_path)
    listing = home.invoke(monkeypatch, [
        "inventory", "--home", str(home.home), "--no-project",
        "--key", str(tmp_path / "k"), "--unknown-list", str(tmp_path / "u"),
    ])
    walked = home.invoke(monkeypatch, [
        "inventory", "--home", str(home.home),
        "--key", str(tmp_path / "k"), "--unknown-list", str(tmp_path / "u"),
    ])
    preview = _setup(home, monkeypatch, "--dry-run")

    assert "  map         none (no project)" in listing.lines
    assert "    map         none (no project)" in preview.lines
    assert "  map         none (.weir/reach.yml not found)" in walked.lines


# --- 10. the project folder --------------------------------------------------------


@pytest.mark.parametrize(
    "folder", ["yes", "no", "", "y", "YES", " yes", "yes please"],
    ids=["yes", "no", "empty", "y", "YES", "space yes", "yes please"],
)
def test_the_current_folder_is_included_only_on_the_exact_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder: str,
) -> None:
    """The offer names the folder before the inventory is taken; the
    preview, the report and the refresh command follow the answer."""
    home = Home(tmp_path)
    cfx.write(home.project / ".env", f"PROJECT_API_TOKEN={cfx.fake_value('default-setup-proj')}\n")
    included = folder == "yes"

    run = _setup(home, monkeypatch, answer=f"{folder}\nyes\n")

    assert run.exit_code == 0, run.stderr
    offer = run.stdout.split("weir statusline setup will make this change:")[0]
    assert str(home.project) in offer and OFFER in offer
    assert (f"  Project folder: {home.project}" in run.lines) is included
    assert (NO_FOLDER in run.lines) is not included
    report = json.loads(home.report.read_text())
    assert report["inputs"]["project"] == (str(home.project) if included else None)
    assert ("PROJECT_API_TOKEN" in {c["name"] for c in report["credentials"]}) is included
    flag = f"--project {shlex.quote(str(home.project))}" if included else "--no-project"
    assert [f" {flag} " in line for line in _refresh(run)] == [True]
    cfx.assert_value_free(run.stdout + run.stderr, home.values.values())


def test_at_the_end_of_input_the_folder_is_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)

    run = _setup(home, monkeypatch, "--dry-run")

    assert run.exit_code == 0, run.stderr
    assert OFFER in run.stdout
    _follows(run, _without_project(home, "project files are not scanned"))
    assert [" --no-project " in line for line in _refresh(run)] == [True]


@pytest.mark.parametrize("where", ["home", "above home"])
def test_the_home_or_a_folder_that_holds_it_is_never_offered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str,
) -> None:
    home = Home(tmp_path)
    cwd = home.home if where == "home" else home.home.parent

    run = _setup(home, monkeypatch, answer="yes\n", cwd=cwd)

    assert run.exit_code == 0, run.stderr
    assert OFFER not in run.stdout
    skipped = [line for line in run.lines if line.startswith("  No project folder is included: ")]
    assert len(skipped) == 1, run.stdout
    _follows(run, _without_project(home, f"{cwd} is or holds your home, and walking it would"
                                         " read the whole home, so the project walk is skipped"))
    assert json.loads(home.report.read_text())["inputs"]["project"] is None
    assert [" --no-project " in line for line in _refresh(run)] == [True]


def test_a_first_setup_from_a_deleted_folder_includes_no_project_and_never_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    gone = tmp_path / "gone"
    gone.mkdir()

    with monkeypatch.context() as m:
        for name in list(os.environ):
            m.delenv(name)
        for name, value in home.env.items():
            m.setenv(name, value)
        m.chdir(gone)
        gone.rmdir()
        result = CliRunner().invoke(main, ["statusline", "setup", "--dry-run"], input="yes\n")
    run = sx.Run(result.exit_code, result.stdout, result.stderr)

    assert run.exit_code == 0, run.stderr
    assert OFFER not in run.stdout
    _follows(run, _without_project(
        home, "the current folder cannot be read, so the project walk is skipped"))
    assert [" --no-project " in line for line in _refresh(run)] == [True]


@pytest.mark.parametrize("flags", [[], ["--store", "custom/store.json"]], ids=["defaults", "store"])
def test_the_command_to_include_a_project_later_makes_the_status_line_green_there(
    tmp_path: Path, flags: list[str],
) -> None:
    """Setup with no project, then the command its preview gives, with DIR
    the project: it rewrites the inventory and store the installed status
    line reads, which is then green there."""
    home = Home(tmp_path)
    flags = [str(tmp_path / f) if f.endswith(".json") else f for f in flags]
    env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", **home.env}
    setup = sx.run_shell(shlex.join(["weir", "statusline", "setup", *flags]), "no\nyes\n", env,
                         str(home.project))
    assert setup.exit_code == 0, setup.stderr
    (later,) = (line.strip() for line in setup.lines if " --project DIR " in line)
    status = json.loads(home.settings.read_text())["statusLine"]["command"]
    session = fx.Session(session_id=SESSION_ID)
    session.prompt("hello")
    session.write(home.transcript())
    payload = sx.status_json(home.transcript(), SESSION_ID, str(home.project))
    before = sx.run_shell(status, payload, {**env, **sx.NO_COLOR})
    words = shlex.split(status)
    read = {name: Path(words[words.index(name) + 1]) for name in ("--inventory", "--store")}
    stored = read["--store"].stat().st_ino

    run = sx.run_shell(later.replace(" DIR ", f" {shlex.quote(str(home.project))} "), "", env,
                       str(home.project))

    assert run.exit_code == 0, run.stderr
    assert json.loads(read["--inventory"].read_text())["inputs"]["project"] == str(home.project)
    assert read["--store"].stat().st_ino != stored
    assert before.stdout == "weir project not inventoried\n"
    after = sx.run_shell(status, payload, {**env, **sx.NO_COLOR})
    assert after.stdout == "weir ✓ no known key seen\n"


@pytest.mark.parametrize("folder", ["no", "yes"])
def test_the_refresh_hint_names_an_earlier_project_only_when_there_is_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder: str,
) -> None:
    home = Home(tmp_path)

    run = _setup(home, monkeypatch, "--dry-run", answer=f"{folder}\n")

    assert run.exit_code == 0, run.stderr
    assert ("earlier project" in run.stdout) is (folder == "yes")


# --- Windows ---------------------------------------------------------------------


@pytest.mark.parametrize("where", ["--cache", "--claude-dir", "--store", "interpreter"])
def test_a_path_with_a_dollar_sign_is_refused_before_anything_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str,
) -> None:
    """Every path setup writes into the /weir line: Claude Code would put
    text in for `$0` or `$ARGUMENTS` there, even inside quotes."""
    home = Home(tmp_path)
    home.settings.write_bytes(b'{"theme": "dark"}')
    odd = tmp_path / "a$0b$ARGUMENTS"
    before = home.snapshot()
    flags = [] if where == "interpreter" else [
        where, str(odd / "store.json" if where == "--store" else odd)]
    if where == "interpreter":
        monkeypatch.setattr(sys, "executable", str(odd / "python"))

    runs = [_setup(home, monkeypatch, *flags, "--dry-run"),
            _setup(home, monkeypatch, *flags, answer="no\nyes\n")]

    monkeypatch.undo()
    for run in runs:
        assert run.exit_code == 2, run.stdout
        assert str(odd) in run.stderr and "nothing changed" in run.stderr
        assert "weir inventory (names only" not in run.stdout
    assert home.snapshot() == before


def test_setup_with_no_flags_refuses_on_windows_before_any_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Home(tmp_path)
    before = home.snapshot()
    monkeypatch.setattr(os, "name", "nt")  # Windows, as setup sees it

    runs = [_setup(home, monkeypatch, "--dry-run"), _setup(home, monkeypatch, answer=_yes(home))]

    monkeypatch.undo()
    for run in runs:
        assert run.exit_code == 2
        assert "POSIX shells (Linux, macOS) only" in run.stderr
        assert "weir inventory (names only" not in run.stdout
    assert home.snapshot() == before
