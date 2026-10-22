"""The GitHub Action's helper (action.yml at the repository root).

Three steps call it, each with the interpreter weir-run is installed into:

- `install`: pip-installs weir-scan and weir-run at exact versions, by
  default the versions in this checkout of the action, so the action's ref
  is the pin;
- `check`: runs `weir-run run` and keeps its report;
- `report`: writes the verdict to the step summary and to one PR comment
  (updated in place on a re-run), and exits 0 on clean, 1 on leak, 3 on
  incomplete and 2 on any error.

The comment shows only the judge's verdict lines, which name placements
and locations, never a value (docs/canary.md, "The text report"). It is
posted with the job's own GITHUB_TOKEN, which only the `report` step gets:
no process holds it while the flows run.

Standard library only: it runs before anything else is installed, and
under `python -I`, so nothing in the checked-out workspace can shadow it.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn, cast

ERROR = 2
CODES = {0: "clean", 1: "leak", 3: "incomplete"}
# docs/canary.md, "The text report": every line the judge can print.
VERDICT_PREFIXES = (
    "LEAK ",
    "not exercised: ",
    "not scanned: ",
    "blocked connection: ",
    "blocked request: ",
    "incomplete: ",
    "coverage: ",
    "network isolated: ",
    "network not isolated: ",
    "result: ",
)
SUMMARY_PREFIXES = ("coverage: ", "network isolated: ", "network not isolated: ", "result: ")
HEADLINES = {
    "clean": "**Weir leak check: clean.** No planted fake credential reached the capture,"
    " and the run checked everything it was asked to.",
    "leak": "**Weir leak check: leak.** A planted fake credential reached the capture."
    " Each `LEAK` line names the placement and where it went, never the value.",
    "incomplete": "**Weir leak check: incomplete.** No planted fake credential was found,"
    " but the run did not check everything it was asked to. The `incomplete` lines say"
    " what is missing.",
    "error": "**Weir leak check: error.** weir-run stopped without a verdict.",
}
# GitHub refuses a comment body over 65536 characters.
MAX_BODY = 60000
MAX_LINES = 60
BOT_LOGIN = "github-actions[bot]"
PER_PAGE = 100
MAX_PAGES = 50
API_TIMEOUT_SECONDS = 30
TOKEN_VARIABLE = "WEIR_GITHUB_TOKEN"
PIN = re.compile(r"\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
SCAN_REQUIREMENT = re.compile(r"weir-scan\s*>=\s*(\d+(?:\.\d+)*)")


class ActionError(Exception):
    pass


@dataclass(frozen=True)
class Outcome:
    result: str
    exit_code: int

    @property
    def passed(self) -> bool:
        return self.result == "clean"


def _result_line(report: str) -> str | None:
    results = [line for line in report.splitlines() if line.startswith("result: ")]
    return results[-1].removeprefix("result: ") if results else None


def outcome(code: int | None, report: str) -> Outcome:
    """weir-run's exit code, taken only when the report's result line agrees:
    a Python that cannot even import weir_run exits 1, which is no leak."""
    result = CODES.get(code) if code is not None else None
    if result is None or _result_line(report) != result:
        return Outcome("error", ERROR)
    return Outcome(result, cast(int, code))


def verdict_lines(report: str) -> list[str]:
    return [line for line in report.splitlines() if line.startswith(VERDICT_PREFIXES)]


def headline(result: str) -> str:
    return HEADLINES[result]


def marker(key: str) -> str:
    """The first line of the action's comment: finds it again on a re-run."""
    safe = re.sub(r"[^A-Za-z0-9._/:+=-]", "_", key)
    return f"<!-- weir-run verdict: {safe} -->"


def _fence(lines: list[str]) -> str:
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    return "`" * max(3, longest + 1)


def _shown(lines: list[str], budget: int) -> tuple[list[str], int]:
    """The lines to show within budget characters, the summary lines always."""
    tail = [line for line in lines if line.startswith(SUMMARY_PREFIXES)]
    head = [line for line in lines if not line.startswith(SUMMARY_PREFIXES)]
    used = sum(len(line) + 1 for line in tail)
    kept: list[str] = []
    for line in head:
        if len(kept) == MAX_LINES or used + len(line) + 1 > budget:
            break
        kept.append(line)
        used += len(line) + 1
    return kept + tail, len(head) - len(kept)


def render(
    code: int | None,
    report: str,
    *,
    key: str,
    config: str,
    run_url: str | None,
    commit: str | None = None,
) -> str:
    """The comment body: the marker, the headline, the verdict lines."""
    result = outcome(code, report).result
    parts = [marker(key), headline(result), ""]
    shown_config = re.sub(r"[`\r\n]", "", config)
    if result == "error":
        parts.append(
            f"weir-run exited {code if code is not None else 'with no code'}: a usage,"
            f" configuration or runner error. The job log has the reason."
        )
    else:
        lines, cut = _shown(verdict_lines(report), MAX_BODY - 2000)
        fence = _fence(lines)
        parts += [f"{fence}text", *lines, fence]
        if cut:
            parts.append(f"... and {cut} more lines in the job log.")
    footer = f"Config: `{shown_config}`."
    if commit and COMMIT.fullmatch(commit):
        footer += f" Head commit: `{commit[:12]}`."
    if run_url:
        footer += f" [Job log]({run_url})."
    parts += ["", footer]
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------- install


def _project(action_path: Path, package: str) -> dict[str, Any]:
    import tomllib

    path = action_path / "packages" / package / "pyproject.toml"
    try:
        return cast(dict[str, Any], tomllib.loads(path.read_text(encoding="utf-8"))["project"])
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise ActionError(f"cannot read {path}: {exc}") from None


def _pyproject_version(action_path: Path, package: str) -> str:
    try:
        return str(_project(action_path, package)["version"])
    except KeyError:
        raise ActionError(f"packages/{package}/pyproject.toml names no version") from None


def _release(version: str) -> tuple[int, ...]:
    match = re.match(r"\d+(\.\d+)*", version)
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def check_recorded(action_path: Path, scan: str, run: str) -> None:
    """Refuse recorded versions that cannot be what this ref's code is.

    Between releases the recorded versions name the last release, and the
    weir-run here may already need a newer weir-scan than the one recorded:
    installing the recorded pair would then judge with older code than the
    action documents."""
    for dependency in _project(action_path, "weir-run").get("dependencies", []):
        match = SCAN_REQUIREMENT.fullmatch(str(dependency).strip())
        if match and _release(scan) < _release(match.group(1)):
            raise ActionError(
                f"this ref is between releases: its weir-run (recorded as {run}) needs"
                f" weir-scan>={match.group(1)}, recorded as {scan}. Use a release tag of"
                " the action, or pass weir-scan-version and weir-run-version"
            )


def pins(action_path: Path, scan: str, run: str) -> tuple[str, str]:
    """The exact weir-scan and weir-run versions: the given ones, else the
    versions in the action's own checkout."""
    chosen: list[str] = []
    for given, package, name in ((scan, "weir", "weir-scan"), (run, "weir-run", "weir-run")):
        version = given or _pyproject_version(action_path, package)
        if not PIN.fullmatch(version):
            raise ActionError(f"{name}-version {version!r} is not one exact version, such as 0.6.0")
        chosen.append(version)
    return chosen[0], chosen[1]


def install_command(python: str, scan: str, run: str) -> list[str]:
    return [
        python,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--only-binary=:all:",
        f"weir-scan=={scan}",
        f"weir-run=={run}",
    ]


def _install() -> int:
    # The script itself runs on whatever Python the job has.
    if sys.version_info < (3, 12):  # noqa: UP036
        raise ActionError(
            f"weir-run needs Python 3.12 or later, and this is {sys.version.split()[0]};"
            " set the python-version input or set up Python first"
        )
    action_path = Path(_env("GITHUB_ACTION_PATH"))
    given_scan = os.environ.get("WEIR_SCAN_VERSION", "")
    given_run = os.environ.get("WEIR_RUN_VERSION", "")
    scan, run = pins(action_path, given_scan, given_run)
    if not (given_scan and given_run):
        check_recorded(action_path, scan, run)
    command = install_command(sys.executable, scan, run)
    print("+ " + " ".join(command), flush=True)
    # `-m` puts the working directory on sys.path, and the job's is the
    # workspace: run pip from an empty one, so no file there can shadow it.
    with tempfile.TemporaryDirectory(prefix="weir-pip-") as empty:
        done = subprocess.run(command, cwd=empty, check=False)
    if done.returncode != 0:
        raise ActionError(f"pip could not install weir-scan=={scan} and weir-run=={run}")
    _output("python", sys.executable)
    return 0


# ---------------------------------------------------------------- check


def weir_run_command(python: str, config: str, report: Path, require_isolation: bool) -> list[str]:
    # -P: the workspace, the job's working directory, is not on sys.path.
    command = [python, "-P", "-m", "weir_run.cli", "run", "--config", config]
    command += ["--report", str(report)]
    if require_isolation:
        command.append("--require-isolation")
    return command


def _run_weir(command: list[str], env: dict[str, str]) -> tuple[int, str]:
    """Run weir-run, its stdout (the report) passed through and kept."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, env=env)

    # A cancelled job stops this step: let weir-run stop the same way, so it
    # deletes the ledger and the capture.
    def forward(signum: int, frame: FrameType | None) -> None:
        try:
            process.send_signal(signum)
        except (ValueError, OSError):
            # Windows sends no SIGINT to a child process.
            process.terminate()

    stopping = (signal.SIGINT, signal.SIGTERM)
    previous = {signum: signal.signal(signum, forward) for signum in stopping}
    try:
        assert process.stdout is not None
        fd = process.stdout.fileno()
        kept = bytearray()
        while chunk := os.read(fd, 65536):
            kept += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        code = process.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return code, kept.decode("utf-8", "replace")


def _event_pull_request() -> dict[str, Any]:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(event, dict):
        return {}
    pull_request = cast(dict[str, Any], event).get("pull_request")
    return cast(dict[str, Any], pull_request) if isinstance(pull_request, dict) else {}


def _pull_request() -> int | None:
    number = _event_pull_request().get("number")
    return number if isinstance(number, int) else None


def _commit() -> str | None:
    """The commit named: a pull request's head commit, else the pushed commit.

    On a pull_request event GitHub checks out the merge of that head into
    the base branch, so the tree judged is that merge commit.
    """
    head = _event_pull_request().get("head")
    sha = cast(dict[str, Any], head).get("sha") if isinstance(head, dict) else None
    return sha if isinstance(sha, str) else os.environ.get("GITHUB_SHA")


def _run_url() -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not REPOSITORY.fullmatch(repository) or not run_id.isdigit():
        return None
    url = f"{server}/{repository}/actions/runs/{run_id}"
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    return f"{url}/attempts/{attempt}" if attempt.isdigit() else url


class GitHub:
    """The few REST calls the comment needs, with the job's own token."""

    def __init__(self, api: str, repository: str, token: str) -> None:
        if not REPOSITORY.fullmatch(repository):
            raise ActionError(f"GITHUB_REPOSITORY {repository!r} is not owner/name")
        self.base = f"{api.rstrip('/')}/repos/{repository}"
        self.token = token

    def _call(self, method: str, path: str, body: dict[str, str] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", "weir-run-action")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            raise ActionError(f"{method} {path.split('?')[0]}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ActionError(f"{method} {path.split('?')[0]}: {type(exc).__name__}") from None

    def find(self, number: int, first_line: str) -> int | None:
        """The oldest comment the Actions bot wrote that starts with first_line."""
        for page in range(1, MAX_PAGES + 1):
            path = f"/issues/{number}/comments?per_page={PER_PAGE}&page={page}"
            comments = self._call("GET", path)
            if not isinstance(comments, list):
                return None
            for comment in cast(list[dict[str, Any]], comments):
                user = cast(dict[str, Any], comment.get("user") or {})
                body = str(comment.get("body") or "")
                if (
                    user.get("login") == BOT_LOGIN
                    and user.get("type") == "Bot"
                    and body.split("\n", 1)[0] == first_line
                ):
                    return int(comment["id"])
            if len(cast(list[Any], comments)) < PER_PAGE:
                return None
        return None

    def upsert(self, number: int, body: str) -> str:
        existing = self.find(number, body.split("\n", 1)[0])
        if existing is None:
            self._call("POST", f"/issues/{number}/comments", {"body": body})
            return "posted"
        self._call("PATCH", f"/issues/comments/{existing}", {"body": body})
        return "updated"


def _check() -> int:
    """Run weir-run and keep its report for the `report` step."""
    # The token is only the `report` step's; never pass one to weir-run.
    os.environ.pop(TOKEN_VARIABLE, None)
    config = _env("WEIR_CONFIG")
    require = _flag("WEIR_REQUIRE_ISOLATION")
    workdir = Path(tempfile.mkdtemp(prefix="weir-run-", dir=os.environ.get("RUNNER_TEMP")))
    report = workdir / "report.json"
    verdict = workdir / "verdict.txt"
    command = weir_run_command(sys.executable, config, report, require)
    print("+ weir-run " + " ".join(command[4:]), flush=True)
    try:
        code, text = _run_weir(command, dict(os.environ))
    except OSError as exc:
        print(f"::error::cannot start weir-run: {exc.strerror}", flush=True)
        code, text = None, ""
    verdict.write_text(text, encoding="utf-8")
    _output("result", outcome(code, text).result)
    _output("exit-code", "" if code is None else str(code))
    _output("verdict", str(verdict))
    if report.is_file():
        _output("report", str(report))
    return 0


def _report() -> int:
    """The step summary, the PR comment, and the verdict's exit code."""
    token = os.environ.pop(TOKEN_VARIABLE, "")
    config = _env("WEIR_CONFIG")
    key = os.environ.get("WEIR_COMMENT_KEY") or config
    raw = os.environ.get("WEIR_EXIT_CODE", "")
    code = int(raw) if re.fullmatch(r"-?\d+", raw) else None
    try:
        text = Path(_env("WEIR_VERDICT")).read_text(encoding="utf-8")
    except OSError:
        text = ""
    result = outcome(code, text)
    body = render(code, text, key=key, config=config, run_url=_run_url(), commit=_commit())
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(body.split("\n", 1)[1])
    number = _pull_request()
    if not _flag("WEIR_COMMENT", default=True):
        print("comment: turned off", flush=True)
    elif number is None:
        print("comment: not a pull request event, so none was posted", flush=True)
    else:
        try:
            api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
            github = GitHub(api, os.environ.get("GITHUB_REPOSITORY", ""), token)
            print(f"comment: {github.upsert(number, body)} on pull request #{number}", flush=True)
        except ActionError as exc:
            # A pull request from a fork gets a read-only token. The verdict
            # still stands, and the step summary has it.
            print(f"::warning title=Weir leak check::no PR comment: {exc}", flush=True)
    if not result.passed:
        print(f"::error title=Weir leak check::{result.result} (weir-run exit {code})", flush=True)
    return result.exit_code


# ---------------------------------------------------------------- plumbing


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ActionError(f"{name} is not set")
    return value


def _flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value not in ("true", "false"):
        raise ActionError(f"{name} must be true or false, not {value!r}")
    return value == "true"


def _output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path and "\n" not in value:
        with open(path, "a", encoding="utf-8") as out:
            out.write(f"{name}={value}\n")


def _fail(message: str) -> NoReturn:
    print(f"::error title=Weir leak check::{message}", flush=True)
    sys.exit(ERROR)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    commands = {"install": _install, "check": _check, "report": _report}
    if len(argv) != 1 or argv[0] not in commands:
        _fail("usage: weir_action.py install|check|report")
    try:
        return commands[argv[0]]()
    except ActionError as exc:
        _fail(str(exc))
    except Exception as exc:
        # A fault in this helper is an error, never a leak's exit 1.
        _fail(f"the action failed ({type(exc).__name__})")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
