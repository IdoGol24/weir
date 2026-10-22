"""The GitHub Action (`action.yml` at the repository root, its helper
`action/weir_action.py`): the exit mapping, the PR comment and the
composite steps run end to end.

The end-to-end tests execute the action's own `run:` steps the way the
runner does (`bash --noprofile --norc -eo pipefail`), with the real
`weir-run` from this workspace judging a probe flow and a stub GitHub API
on 127.0.0.1 standing in for api.github.com. Their expectations are
derived, not restated: each run's comment must carry exactly the report a
direct `weir-run run` of the same config prints (the report depends on
where values appear, never on what they are), and the planted value, which
the probe writes to a side file, must appear nowhere.

The install step needs PyPI, so it is not run here: its command is checked
as a unit, and its output is supplied as the runner would set it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import msgspec
import pytest
import weir_action

ROOT = Path(__file__).resolve().parents[3]
ACTION = ROOT / "action.yml"
PROBE = Path(__file__).parent / "_probe_flow.py"
BOT = {"login": "github-actions[bot]", "type": "Bot"}
TOKEN = "fake-actions-token-not-a-credential"
REPO = "octo-org/octo-repo"
PR = 7

CONFIG = """
[[placement]]
id = "env.APP_KEY"
kind = "env"
required = true
provider = "model"

[[flow]]
id = "main"
command = ["{{python}}", {probe}]
env = {{ {env} }}
"""


# ---------------------------------------------------------------- exit mapping


def _report(result: str | None) -> str:
    lines = ["coverage: 1 placements (0 leaked, 1 exercised, 0 not exercised, 1 required)"]
    if result is not None:
        lines.append(f"result: {result}")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("code", "result", "expected"),
    [
        (0, "clean", ("clean", 0)),
        (1, "leak", ("leak", 1)),
        (3, "incomplete", ("incomplete", 3)),
        # 2 is a usage, configuration or runner error, whatever was printed.
        (2, None, ("error", 2)),
        (2, "clean", ("error", 2)),
        # A code the report does not confirm is never taken at its word: a
        # Python that cannot import weir_run exits 1, which is no leak.
        (0, None, ("error", 2)),
        (0, "leak", ("error", 2)),
        (1, None, ("error", 2)),
        (1, "clean", ("error", 2)),
        (3, "clean", ("error", 2)),
        (3, None, ("error", 2)),
        # Any other code, a signal included, is an error.
        (4, "clean", ("error", 2)),
        (5, None, ("error", 2)),
        (127, None, ("error", 2)),
        (130, None, ("error", 2)),
        (-15, None, ("error", 2)),
        (None, "clean", ("error", 2)),
    ],
)
def test_the_exit_mapping(code: int | None, result: str | None, expected: tuple[str, int]) -> None:
    outcome = weir_action.outcome(code, _report(result))
    assert (outcome.result, outcome.exit_code) == expected
    assert outcome.passed == (expected[0] == "clean")


def test_only_the_last_result_line_counts() -> None:
    report = "result: leak\n" + _report("clean")
    assert weir_action.outcome(0, report).result == "clean"
    assert weir_action.outcome(1, report).result == "error"


# ---------------------------------------------------------------- the comment

VERDICT = [
    'LEAK env.APP_KEY file=capture/otlp/traces.jsonl:1 signal=traces span="a ```` b" form=raw',
    "not exercised: env.OTHER",
    "not scanned: capture/x.gz (compressed)",
    "blocked connection: api.example:443 (1x)",
    "blocked request: collector.example:80 (2x)",
    "incomplete: flow_not_ok main=failed",
    "coverage: 2 placements (1 leaked, 0 exercised, 1 not exercised, 1 required), 1 flows",
    "network isolated: 0 direct connections blocked",
    "result: leak",
]


def test_the_comment_shows_the_verdict_lines_and_nothing_else() -> None:
    noise = ["hello from a flow", "@octocat look", "<!-- weir-run verdict: other -->", ""]
    report = "\n".join(noise[:2] + VERDICT[:3] + noise[2:] + VERDICT[3:]) + "\n"
    body = weir_action.render(1, report, key="canary.toml", config="canary.toml", run_url=None)
    assert body.splitlines()[0] == weir_action.marker("canary.toml")
    assert _block(body) == VERDICT
    for line in noise[:3]:
        assert line not in body


def test_the_fence_outlasts_any_backtick_run_in_the_lines() -> None:
    body = weir_action.render(1, "\n".join(VERDICT), key="k", config="c", run_url=None)
    fence = re.search(r"^(`{3,})text$", body, re.MULTILINE)
    assert fence is not None
    assert len(fence.group(1)) > 4


def test_each_result_has_its_own_headline() -> None:
    bodies = {
        result: weir_action.render(code, _report(result), key="k", config="c", run_url=None)
        for code, result in ((0, "clean"), (1, "leak"), (3, "incomplete"))
    }
    bodies["error"] = weir_action.render(2, "", key="k", config="c", run_url=None)
    for result, body in bodies.items():
        assert body.splitlines()[1] == weir_action.headline(result)
    assert len({weir_action.headline(r) for r in bodies}) == 4


def test_an_error_shows_no_verdict_lines_and_names_the_code() -> None:
    body = weir_action.render(2, _report("clean"), key="k", config="c", run_url=None)
    assert _block(body) == []
    assert "exited 2" in body
    body = weir_action.render(None, "", key="k", config="c", run_url=None)
    assert _block(body) == []


def test_the_run_link_and_the_config_are_shown() -> None:
    url = "https://github.com/octo-org/octo-repo/actions/runs/1/attempts/2"
    body = weir_action.render(0, _report("clean"), key="k", config="ci/can`ary.toml", run_url=url)
    assert f"]({url})" in body
    assert "`ci/canary.toml`" in body


def test_a_long_report_is_cut_but_keeps_its_summary_lines() -> None:
    hits = [
        f"LEAK env.K{i:04d} file=capture/otlp/traces.jsonl:{i} signal=traces form=raw"
        for i in range(2000)
    ]
    report = "\n".join(hits + VERDICT[6:]) + "\n"
    body = weir_action.render(1, report, key="k", config="c", run_url=None)
    block = _block(body)
    assert len(body) <= weir_action.MAX_BODY
    assert block[-3:] == VERDICT[6:]
    shown = [line for line in block if line.startswith("LEAK ")]
    assert 0 < len(shown) < len(hits)
    assert block[: len(shown)] == hits[: len(shown)]
    assert f"{len(hits) - len(shown)} more lines" in body


def test_the_marker_keeps_the_key_inside_one_html_comment() -> None:
    assert weir_action.marker("ci/canary.toml") == "<!-- weir-run verdict: ci/canary.toml -->"
    hostile = weir_action.marker("x --> <img src=y>\n@octocat")
    assert hostile.startswith("<!-- weir-run verdict: ")
    assert hostile.endswith(" -->")
    assert hostile.count(">") == 1
    assert "\n" not in hostile and "@" not in hostile


# ---------------------------------------------------------------- install pins


def _version(package: str) -> str:
    data = tomllib.loads((ROOT / "packages" / package / "pyproject.toml").read_text("utf-8"))
    return cast(str, data["project"]["version"])


def test_the_default_pins_are_the_versions_at_the_actions_own_ref() -> None:
    assert weir_action.pins(ROOT, "", "") == (_version("weir"), _version("weir-run"))
    assert weir_action.pins(ROOT, "0.6.0", "0.2.0rc1") == ("0.6.0", "0.2.0rc1")


@pytest.mark.parametrize("bad", [">=0.6", "0.6.*", "0.6.0; echo", "latest", "0.6.0 ", "~=0.6"])
def test_a_pin_that_is_not_one_exact_version_is_refused(bad: str) -> None:
    with pytest.raises(weir_action.ActionError):
        weir_action.pins(ROOT, bad, "")
    with pytest.raises(weir_action.ActionError):
        weir_action.pins(ROOT, "", bad)


def test_the_install_command_pins_both_packages_exactly_and_takes_wheels_only() -> None:
    command = weir_action.install_command("/py", "0.6.0", "0.2.0")
    assert command[:4] == ["/py", "-m", "pip", "install"]
    assert "weir-scan==0.6.0" in command
    assert "weir-run==0.2.0" in command
    assert "--only-binary=:all:" in command


# ---------------------------------------------------------------- action.yml


def _action() -> dict[str, Any]:
    return cast(dict[str, Any], msgspec.yaml.decode(ACTION.read_bytes()))


def test_every_action_it_uses_is_allowed_and_pinned_by_full_commit_sha() -> None:
    steps = cast(list[dict[str, Any]], _action()["runs"]["steps"])
    uses = [cast(str, s["uses"]) for s in steps if "uses" in s]
    for ref in uses:
        name, _, sha = ref.partition("@")
        assert name in {"actions/setup-python", "actions/github-script"}, ref
        assert re.fullmatch(r"[0-9a-f]{40}", sha), ref


def test_no_run_script_interpolates_an_expression() -> None:
    # Inputs reach scripts through env only, so no input can inject shell.
    steps = cast(list[dict[str, Any]], _action()["runs"]["steps"])
    for step in steps:
        if "run" in step:
            assert "${{" not in step["run"], step.get("name")


# ---------------------------------------------------------------- the stub API


@dataclass
class StubGitHub:
    comments: list[dict[str, Any]] = field(default_factory=lambda: [])
    requests: list[tuple[str, str, dict[str, str], Any]] = field(default_factory=lambda: [])
    fail: dict[str, int] = field(default_factory=lambda: {})
    next_id: int = 1000
    url: str = ""

    def add(self, body: str, user: dict[str, str]) -> int:
        self.next_id += 1
        self.comments.append({"id": self.next_id, "body": body, "user": dict(user)})
        return self.next_id

    def calls(self, method: str) -> list[tuple[str, str, dict[str, str], Any]]:
        return [r for r in self.requests if r[0] == method]


def _handler(stub: StubGitHub) -> type[BaseHTTPRequestHandler]:
    comments_path = f"/repos/{REPO}/issues/{PR}/comments"
    one = re.compile(rf"^/repos/{re.escape(REPO)}/issues/comments/(\d+)$")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def _answer(self, status: int, payload: object) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _record(self) -> tuple[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw) if raw else None
            headers = {k.lower(): v for k, v in self.headers.items()}
            stub.requests.append((self.command, self.path, headers, body))
            return urlsplit(self.path).path, body

        def _refused(self) -> bool:
            status = stub.fail.get(self.command)
            if status is None:
                return False
            self._answer(status, {"message": "refused by the stub"})
            return True

        def do_GET(self) -> None:
            path, _ = self._record()
            if self._refused():
                return
            if path != comments_path:
                return self._answer(404, {"message": "Not Found"})
            query = parse_qs(urlsplit(self.path).query)
            per_page = int(query.get("per_page", ["30"])[0])
            page = int(query.get("page", ["1"])[0])
            start = (page - 1) * per_page
            self._answer(200, stub.comments[start : start + per_page])

        def do_POST(self) -> None:
            path, body = self._record()
            if self._refused():
                return
            if path != comments_path:
                return self._answer(404, {"message": "Not Found"})
            new = stub.add(body["body"], BOT)
            self._answer(201, stub.comments[-1] | {"id": new})

        def do_PATCH(self) -> None:
            path, body = self._record()
            if self._refused():
                return
            match = one.match(path)
            found = [c for c in stub.comments if match and c["id"] == int(match.group(1))]
            if not found:
                return self._answer(404, {"message": "Not Found"})
            if found[0]["user"] != BOT:
                return self._answer(403, {"message": "not your comment"})
            found[0]["body"] = body["body"]
            self._answer(200, found[0])

    return Handler


@pytest.fixture
def github() -> Iterator[StubGitHub]:
    stub = StubGitHub()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(stub))
    stub.url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield stub
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------- the steps


@dataclass
class Run:
    code: int
    stdout: str
    stderr: str
    outputs: dict[str, dict[str, str]]
    summary: str
    ran: list[str]

    @property
    def text(self) -> str:
        return "\n".join([self.stdout, self.stderr, self.summary, json.dumps(self.outputs)])


def _resolve(expr: str, context: dict[str, Any]) -> str:
    value: Any = context
    for part in expr.strip().split("."):
        value = cast(dict[str, Any], value).get(part, "") if isinstance(value, dict) else ""
    return "" if value is None else str(value)


def _expand(text: str, context: dict[str, Any]) -> str:
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: _resolve(m.group(1), context), text)


def _condition(expr: str, context: dict[str, Any]) -> bool:
    """The `if:` forms action.yml uses: `a.b == 'x'` and `!=`, joined by `&&`."""
    expr = expr.strip().removeprefix("${{").removesuffix("}}")
    for clause in expr.split("&&"):
        match = re.fullmatch(r"\s*([\w.-]+)\s*(==|!=)\s*'([^']*)'\s*", clause)
        assert match is not None, f"the harness does not understand if: {expr}"
        equal = _resolve(match.group(1), context) == match.group(3)
        if equal != (match.group(2) == "=="):
            return False
    return True


def _parse_outputs(path: Path) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for line in path.read_text("utf-8").splitlines():
        name, sep, value = line.partition("=")
        assert sep, f"not a single-line output: {line!r}"
        outputs[name] = value
    return outputs


def run_action(
    tmp: Path,
    inputs: dict[str, str],
    *,
    event: dict[str, Any],
    event_name: str,
    api: str,
) -> Run:
    """Run action.yml's run steps as the runner would, one bash per step."""
    action = _action()
    defaults = {
        name: str(spec.get("default", ""))
        for name, spec in cast(dict[str, dict[str, Any]], action["inputs"]).items()
    }
    unknown = set(inputs) - set(defaults)
    assert not unknown, f"not inputs of action.yml: {unknown}"
    runner_temp = tmp / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    event_path = tmp / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    summary = tmp / "step-summary.md"
    summary.write_text("", encoding="utf-8")
    context: dict[str, Any] = {
        "inputs": defaults | inputs,
        "github": {"token": TOKEN, "action_path": str(ROOT)},
        "runner": {"os": "Linux", "environment": "self-hosted", "temp": str(runner_temp)},
        # The install step needs PyPI; the runner would set this output.
        "steps": {"install": {"outputs": {"python": sys.executable}}},
    }
    base = {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"]),
        "HOME": str(tmp / "home"),
        "LANG": "C.UTF-8",
        "GITHUB_ACTIONS": "true",
        "GITHUB_ACTION_PATH": str(ROOT),
        "GITHUB_WORKSPACE": str(tmp),
        "GITHUB_API_URL": api,
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_RUN_ID": "4242",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_STEP_SUMMARY": str(summary),
        "RUNNER_TEMP": str(runner_temp),
        "RUNNER_OS": "Linux",
    }
    (tmp / "home").mkdir(exist_ok=True)
    code, stdout, stderr = 0, "", ""
    ran: list[str] = []
    for index, step in enumerate(cast(list[dict[str, Any]], action["runs"]["steps"])):
        if "uses" in step or ("if" in step and not _condition(str(step["if"]), context)):
            continue
        step_id = str(step.get("id", f"step{index}"))
        if step_id == "install":
            continue
        assert step.get("shell") == "bash", step_id
        output = tmp / f"output-{index}"
        output.write_text("", encoding="utf-8")
        script = tmp / f"step-{index}.sh"
        script.write_text(str(step["run"]), encoding="utf-8")
        env = base | {"GITHUB_OUTPUT": str(output)}
        env |= {k: _expand(str(v), context) for k, v in step.get("env", {}).items()}
        done = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        ran.append(step_id)
        stdout += done.stdout
        stderr += done.stderr
        context["steps"][step_id] = {"outputs": _parse_outputs(output)}
        code = done.returncode
        if code != 0:
            break
    outputs = {name: step["outputs"] for name, step in context["steps"].items()}
    return Run(code, stdout, stderr, outputs, summary.read_text("utf-8"), ran)


def _config(tmp: Path, mode: str = "") -> tuple[Path, Path]:
    side = tmp / "side.txt"
    env = {"SIDE_FILE": side.as_posix(), "MODE": mode}
    inline = ", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items())
    path = tmp / "canary.toml"
    path.write_text(CONFIG.format(env=inline, probe=json.dumps(PROBE.as_posix())), encoding="utf-8")
    return path, side


def _direct(config: Path) -> tuple[int, str]:
    """The same config through `weir-run run` itself, with fresh values."""
    done = subprocess.run(
        [sys.executable, "-m", "weir_run.cli", "run", "--config", str(config)],
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(config.parent / "home")},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    return done.returncode, done.stdout


def _block(body: str) -> list[str]:
    match = re.search(r"^(`{3,})text\n(.*?)^\1$", body, re.MULTILINE | re.DOTALL)
    return [] if match is None else match.group(2).splitlines()


PR_EVENT: dict[str, Any] = {"pull_request": {"number": PR}}


def _pr_run(tmp: Path, github: StubGitHub, **inputs: str) -> Run:
    return run_action(tmp, inputs, event=PR_EVENT, event_name="pull_request", api=github.url)


skip_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="runs the action's bash steps directly"
)


def _posted(github: StubGitHub) -> list[str]:
    return [cast(str, r[3]["body"]) for r in github.requests if r[0] in ("POST", "PATCH")]


@skip_windows
@pytest.mark.parametrize(
    ("mode", "result", "code"), [("", "clean", 0), ("leak", "leak", 1), ("crash", "incomplete", 3)]
)
def test_a_pr_run_posts_one_comment_with_the_report_weir_run_prints(
    tmp_path: Path, github: StubGitHub, mode: str, result: str, code: int
) -> None:
    config, side = _config(tmp_path, mode)
    direct_code, direct_report = _direct(config)
    assert direct_code == code, direct_report

    run = _pr_run(tmp_path, github, config="canary.toml")

    assert run.code == code, run.stderr
    assert run.outputs["check"]["result"] == result
    assert run.outputs["check"]["exit-code"] == str(code)
    assert len(github.calls("POST")) == 1 and not github.calls("PATCH")
    method, path, headers, _ = github.calls("POST")[0]
    assert path == f"/repos/{REPO}/issues/{PR}/comments", method
    assert headers["authorization"] == f"Bearer {TOKEN}"
    (body,) = _posted(github)
    assert body.splitlines()[0] == weir_action.marker("canary.toml")
    assert body.splitlines()[1] == weir_action.headline(result)
    assert _block(body) == direct_report.splitlines()
    assert _block(run.summary) == direct_report.splitlines()
    report = json.loads(Path(run.outputs["check"]["report"]).read_text("utf-8"))
    assert report["result"] == result
    value = side.read_text("utf-8")
    assert len(value) >= 20
    for text in (run.text, body, json.dumps(github.requests)):
        assert value not in text
        assert TOKEN not in text.replace(f"Bearer {TOKEN}", "")


@skip_windows
def test_a_rerun_updates_the_same_comment_in_place(tmp_path: Path, github: StubGitHub) -> None:
    config, _ = _config(tmp_path)
    first = _pr_run(tmp_path, github, config=config.name)
    assert first.code == 0, first.stderr
    (created,) = github.comments
    config, _ = _config(tmp_path, "leak")
    second = _pr_run(tmp_path, github, config=config.name)
    assert second.code == 1, second.stderr
    assert len(github.calls("POST")) == 1
    (patch,) = github.calls("PATCH")
    assert patch[1] == f"/repos/{REPO}/issues/comments/{created['id']}"
    assert len(github.comments) == 1
    assert github.comments[0]["body"].splitlines()[1] == weir_action.headline("leak")


@skip_windows
def test_only_its_own_bot_comment_is_updated(tmp_path: Path, github: StubGitHub) -> None:
    marker = weir_action.marker("canary.toml")
    human = github.add(f"{marker}\nspoofed", {"login": "mallory", "type": "User"})
    for i in range(120):
        github.add(f"chatter {i}", {"login": "dev", "type": "User"})
    other = github.add(f"{weir_action.marker('other.toml')}\nx", BOT)
    ours = github.add(f"{marker}\nold verdict", BOT)
    config, _ = _config(tmp_path)

    run = _pr_run(tmp_path, github, config=config.name)

    assert run.code == 0, run.stderr
    assert not github.calls("POST")
    (patch,) = github.calls("PATCH")
    assert patch[1] == f"/repos/{REPO}/issues/comments/{ours}"
    bodies = {c["id"]: c["body"] for c in github.comments}
    assert bodies[human] == f"{marker}\nspoofed"
    assert bodies[other] == f"{weir_action.marker('other.toml')}\nx"


@skip_windows
def test_the_comment_key_separates_two_checks(tmp_path: Path, github: StubGitHub) -> None:
    config, _ = _config(tmp_path)
    _pr_run(tmp_path, github, config=config.name)
    run = _pr_run(tmp_path, github, config=config.name, **{"comment-key": "linux"})
    assert run.code == 0, run.stderr
    assert len(github.calls("POST")) == 2
    assert github.comments[1]["body"].splitlines()[0] == weir_action.marker("linux")


@skip_windows
def test_an_error_fails_with_2_and_says_so(tmp_path: Path, github: StubGitHub) -> None:
    run = _pr_run(tmp_path, github, config="missing.toml")
    assert run.code == 2
    assert run.outputs["check"]["result"] == "error"
    (body,) = _posted(github)
    assert body.splitlines()[1] == weir_action.headline("error")
    assert _block(body) == []


@skip_windows
def test_require_isolation_is_passed_to_weir_run(tmp_path: Path, github: StubGitHub) -> None:
    config, _ = _config(tmp_path)
    run = _pr_run(tmp_path, github, config=config.name, **{"require-isolation": "true"})
    (body,) = _posted(github)
    if "network not isolated" in body:
        assert run.code == 3
        assert "incomplete: network_not_isolated" in _block(body)
    else:
        assert run.code == 0, run.stderr
    assert "--require-isolation" in run.stdout + run.stderr


@skip_windows
@pytest.mark.parametrize(
    ("event_name", "event", "inputs"),
    [
        ("push", {"ref": "refs/heads/main"}, {}),
        ("pull_request", PR_EVENT, {"comment": "false"}),
    ],
)
def test_no_comment_off_a_pr_or_when_turned_off(
    tmp_path: Path,
    github: StubGitHub,
    event_name: str,
    event: dict[str, Any],
    inputs: dict[str, str],
) -> None:
    config, _ = _config(tmp_path, "leak")
    run = run_action(
        tmp_path,
        {"config": config.name} | inputs,
        event=event,
        event_name=event_name,
        api=github.url,
    )
    assert run.code == 1, run.stderr
    assert github.requests == []
    assert run.summary.splitlines()[0] == weir_action.headline("leak")


@skip_windows
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_refused_comment_warns_and_keeps_the_verdict(
    tmp_path: Path, github: StubGitHub, method: str
) -> None:
    github.fail[method] = 403
    config, _ = _config(tmp_path)
    run = _pr_run(tmp_path, github, config=config.name)
    assert run.code == 0, run.stderr
    assert "::warning" in run.stdout
    assert "403" in run.stdout
    assert run.summary.splitlines()[0] == weir_action.headline("clean")


@skip_windows
def test_the_token_never_reaches_the_flow(tmp_path: Path, github: StubGitHub) -> None:
    dump = tmp_path / "env.json"
    flow = tmp_path / "dump.py"
    flow.write_text(
        "import json, os, sys\njson.dump(dict(os.environ), open(sys.argv[1], 'w'))\n",
        encoding="utf-8",
    )
    (tmp_path / "canary.toml").write_text(
        '[[placement]]\nid = "env.APP_KEY"\nkind = "env"\nprovider = "model"\n\n'
        f'[[flow]]\nid = "dump"\ncommand = ["{{python}}", {json.dumps(flow.as_posix())},'
        f" {json.dumps(dump.as_posix())}]\n",
        encoding="utf-8",
    )
    _pr_run(tmp_path, github, config="canary.toml")
    seen = json.loads(dump.read_text("utf-8"))
    assert TOKEN not in json.dumps(seen)


def test_the_token_never_reaches_weir_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, str]] = []

    def fake_run(command: list[str], env: dict[str, str]) -> tuple[int, str]:
        seen.append(env)
        return 0, _report("clean")

    monkeypatch.setattr(weir_action, "_run_weir", fake_run)
    for name, value in {
        "WEIR_GITHUB_TOKEN": TOKEN,
        "WEIR_CONFIG": "canary.toml",
        "WEIR_COMMENT": "false",
        "RUNNER_TEMP": str(tmp_path),
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(name, raising=False)
    assert weir_action.main(["check"]) == 0
    (env,) = seen
    assert TOKEN not in env.values()


# ---------------------------------------------------------------- added after the lock


def _fake_action(tmp: Path, scan: str, run: str, needs: str) -> Path:
    for package, version, deps in (("weir", scan, []), ("weir-run", run, [f"weir-scan>={needs}"])):
        (tmp / "packages" / package).mkdir(parents=True)
        text = f'[project]\nname = "{package}"\nversion = "{version}"\n'
        text += f"dependencies = {json.dumps(deps)}\n"
        (tmp / "packages" / package / "pyproject.toml").write_text(text, encoding="utf-8")
    return tmp


@pytest.mark.parametrize(
    ("scan", "needs", "refused"),
    [("0.6.0", "0.6.0", False), ("0.7.1", "0.6.0", False), ("0.5.0", "0.6.0", True)],
)
def test_recorded_versions_between_releases_are_refused(
    tmp_path: Path, scan: str, needs: str, refused: bool
) -> None:
    action = _fake_action(tmp_path, scan, "0.2.0", needs)
    if refused:
        with pytest.raises(weir_action.ActionError, match="between releases"):
            weir_action.check_recorded(action, scan, "0.2.0")
    else:
        weir_action.check_recorded(action, scan, "0.2.0")


def test_this_refs_recorded_versions_are_refused_exactly_when_they_disagree() -> None:
    from packaging.requirements import Requirement

    data = tomllib.loads((ROOT / "packages" / "weir-run" / "pyproject.toml").read_text("utf-8"))
    deps = cast(list[str], data["project"]["dependencies"])
    (needed,) = [Requirement(d) for d in deps if Requirement(d).name == "weir-scan"]
    scan = _version("weir")
    agrees = needed.specifier.contains(scan, prereleases=True)
    try:
        weir_action.check_recorded(ROOT, scan, _version("weir-run"))
        refused = False
    except weir_action.ActionError:
        refused = True
    assert refused == (not agrees)


def test_install_names_the_output_the_later_steps_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], str]] = []

    def fake_run(command: list[str], cwd: str, check: bool) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, cwd))
        assert list(Path(cwd).iterdir()) == []
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(weir_action.subprocess, "run", fake_run)
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_ACTION_PATH", str(_fake_action(tmp_path, "0.6.0", "0.2.0", "0.6.0")))
    monkeypatch.delenv("WEIR_SCAN_VERSION", raising=False)
    monkeypatch.delenv("WEIR_RUN_VERSION", raising=False)
    assert weir_action.main(["install"]) == 0
    ((command, cwd),) = calls
    assert "weir-scan==0.6.0" in command and "weir-run==0.2.0" in command
    assert Path(cwd).resolve() != Path.cwd().resolve()
    (name,) = _parse_outputs(output)
    steps = cast(list[dict[str, Any]], _action()["runs"]["steps"])
    readers = [s for s in steps if s.get("id") in ("check", "report")]
    assert len(readers) == 2
    for step in readers:
        assert step["env"]["WEIR_PYTHON"] == "${{ steps.install.outputs." + name + " }}"


def test_the_token_is_only_the_report_steps() -> None:
    steps = cast(list[dict[str, Any]], _action()["runs"]["steps"])
    holders = [s.get("id") for s in steps if "github.token" in json.dumps(s)]
    assert holders == ["report"]
    ids = [s.get("id") for s in steps]
    assert ids.index("check") < ids.index("report")


def test_the_comment_names_the_commit_it_judged() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    body = weir_action.render(0, _report("clean"), key="k", config="c", run_url=None, commit=sha)
    assert f"`{sha[:12]}`" in body
    body = weir_action.render(0, _report("clean"), key="k", config="c", run_url=None, commit="x`y")
    assert "Commit" not in body


@skip_windows
def test_a_pr_comment_names_the_pull_requests_head(tmp_path: Path, github: StubGitHub) -> None:
    sha = "89abcdef0123456789abcdef0123456789abcdef"
    config, _ = _config(tmp_path)
    event = {"pull_request": {"number": PR, "head": {"sha": sha}}}
    run = run_action(
        tmp_path, {"config": config.name}, event=event, event_name="pull_request", api=github.url
    )
    assert run.code == 0, run.stderr
    (body,) = _posted(github)
    assert f"Commit: `{sha[:12]}`" in body


def test_install_refuses_recorded_versions_between_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(command: list[str], cwd: str, check: bool) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("pip must not run")

    monkeypatch.setattr(weir_action.subprocess, "run", fake_run)
    monkeypatch.setenv("GITHUB_ACTION_PATH", str(_fake_action(tmp_path, "0.5.0", "0.2.0", "0.6.0")))
    monkeypatch.delenv("WEIR_SCAN_VERSION", raising=False)
    monkeypatch.delenv("WEIR_RUN_VERSION", raising=False)
    with pytest.raises(SystemExit) as stopped:
        weir_action.main(["install"])
    assert stopped.value.code == 2
    assert "between releases" in capsys.readouterr().out
