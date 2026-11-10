"""The pytest plugin, subprocess mode.

The plugin is exercised the way a maintainer meets it: an inner pytest
session in a fresh directory, with the plugin loaded through its `pytest11`
entry point and its default judge, the workspace's `weir canary judge`
judge. The declaration rules are checked in process on `CanaryCheck`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from weir_run.check import WITHHELD
from weir_run.pytest_plugin import CanaryCheck
from weir_run.shapes import SHAPES
from weir_run.spec import SpecError

PROBE = Path(__file__).parent / "_probe_flow.py"
TOOL_FLOW = Path(__file__).parent / "_tool_flow.py"

INNER_TESTS = f"""
PROBE = {json.dumps(PROBE.as_posix())}
TOOL_FLOW = {json.dumps(TOOL_FLOW.as_posix())}

def _env(tmp_path, mode):
    return {{"SIDE_FILE": str(tmp_path / "side"), "MODE": mode}}

def test_clean(canary_check, tmp_path):
    canary_check.env("APP_KEY", required=True, provider="model")
    assert canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "")) == "ok"

def test_leaky(canary_check, tmp_path):
    canary_check.env("APP_KEY", provider="model")
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "leak"))

def test_crashing(canary_check, tmp_path):
    canary_check.env("APP_KEY", provider="model")
    canary_check.run(["{{python}}", PROBE], id="crashy", env=_env(tmp_path, "crash"))

def test_unexercised_by_default(canary_check, tmp_path):
    canary_check.env("APP_KEY", provider="model")
    canary_check.env("UNUSED_KEY")
    canary_check.code("code.unused")
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, ""))

def test_unexercised_opted_out(canary_check, tmp_path):
    canary_check.env("APP_KEY", provider="model")
    canary_check.env("UNUSED_KEY", required=False)
    canary_check.code("code.unused", required=False)
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, ""))

def test_explicit_judge(canary_check, tmp_path):
    canary_check.env("APP_KEY", provider="model")
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "leak"))
    result = canary_check.judge()
    assert result.code == 1
    assert "LEAK env.APP_KEY" in result.report

def _tools(canary_check, tmp_path, mode):
    files = canary_check.endpoint("files", reply='{{"ok": true}}', tool="send_file")
    canary_check.env("MODEL_KEY", provider="model")
    canary_check.env("FILES_KEY", provider="files")
    env = {{"SIDE_FILE": str(tmp_path / "side"), "MODE": mode, "API": "chat"}}
    canary_check.run(["{{python}}", TOOL_FLOW], env={{**env, "FILES_BASE_URL": files}})

def test_tool_run_asked(canary_check, tmp_path):
    _tools(canary_check, tmp_path, "model")

def test_tool_run_unasked(canary_check, tmp_path):
    _tools(canary_check, tmp_path, "injected")

def test_fragment(canary_check, tmp_path):
    from weir_run.shapes import ID_OVERLAP, SHAPES

    prefix = SHAPES["anthropic"].prefix
    canary_check.env("APP_KEY", provider="model", shape="anthropic")
    env = {{**_env(tmp_path, "fragment"), "PREFIX_LENGTH": str(len(prefix))}}
    canary_check.run(["{{python}}", PROBE], env=env)
    result = canary_check.judge()
    body = (tmp_path / "side").read_text(encoding="utf-8")[len(prefix):]
    windows = {{body[i : i + ID_OVERLAP] for i in range(len(body) - ID_OVERLAP + 1)}}
    assert not [w for w in windows if w in result.output + result.report]
    assert f"prefix {{prefix}}\\n" in result.output.replace("\\r\\n", "\\n")
"""

# An inner conftest that makes isolation unavailable, as on a host without
# user namespaces.
UNAVAILABLE = """
from weir_run import isolation

def _unavailable():
    raise isolation.Unavailable("user namespaces are disabled")

isolation.jail = _unavailable
"""


def _inner(root: Path, *options: str) -> subprocess.CompletedProcess[str]:
    (root / "test_inner.py").write_text(INNER_TESTS, encoding="utf-8")
    # Only what an interpreter needs to start; not the test process's environment.
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root), "TMP": str(root)}
    env["TEMP"] = env["TMPDIR"] = str(root)
    if sys.platform == "win32":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        env["USERPROFILE"] = str(root)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-rA", "-p", "no:cacheprovider", *options, str(root)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.fixture(scope="module")
def inner(tmp_path_factory: pytest.TempPathFactory) -> subprocess.CompletedProcess[str]:
    return _inner(tmp_path_factory.mktemp("inner"))


def test_the_plugin_loads_through_its_entry_point(inner: subprocess.CompletedProcess[str]) -> None:
    assert "fixture 'canary_check' not found" not in inner.stdout


def test_a_clean_flow_passes(inner: subprocess.CompletedProcess[str]) -> None:
    assert "PASSED test_inner.py::test_clean" in inner.stdout, inner.stdout
    # The verdict is given at teardown, which pytest reports as its own ERROR.
    assert "ERROR test_inner.py::test_clean" not in inner.stdout, inner.stdout


def test_a_leak_fails_the_test_with_the_value_free_report(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "ERROR test_inner.py::test_leaky" in inner.stdout, inner.stdout
    assert "canary check exited 1" in inner.stdout
    assert "LEAK env.APP_KEY" in inner.stdout


def test_an_incomplete_run_fails_the_test(inner: subprocess.CompletedProcess[str]) -> None:
    assert "ERROR test_inner.py::test_crashing" in inner.stdout, inner.stdout
    assert "incomplete: flow_not_ok crashy=failed" in inner.stdout
    assert "canary check exited 3" in inner.stdout


def test_placements_are_required_unless_they_opt_out(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "ERROR test_inner.py::test_unexercised_by_default" in inner.stdout, inner.stdout
    for pid in ("env.UNUSED_KEY", "code.unused"):
        assert f"incomplete: required_not_exercised {pid}" in inner.stdout, inner.stdout
    assert "PASSED test_inner.py::test_unexercised_opted_out" in inner.stdout, inner.stdout
    assert "ERROR test_inner.py::test_unexercised_opted_out" not in inner.stdout, inner.stdout


def test_a_tool_run_no_model_request_asked_for_fails_the_test(
    inner: subprocess.CompletedProcess[str],
) -> None:
    """`endpoint(..., tool=...)` names the tool, as `tool` does in a config."""
    assert "PASSED test_inner.py::test_tool_run_asked" in inner.stdout, inner.stdout
    assert "ERROR test_inner.py::test_tool_run_asked" not in inner.stdout, inner.stdout
    assert "ERROR test_inner.py::test_tool_run_unasked" in inner.stdout, inner.stdout
    line = "unmediated tool call: send_file (executed without a model request)"
    assert line in inner.stdout.splitlines(), inner.stdout
    assert "result: unmediated-tool-call" in inner.stdout.splitlines()


def test_judge_can_be_called_to_assert_on_the_result(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "PASSED test_inner.py::test_explicit_judge" in inner.stdout, inner.stdout


def test_a_slice_of_the_key_never_reaches_the_relayed_output(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "PASSED test_inner.py::test_fragment" in inner.stdout, inner.stdout


def test_a_withheld_line_keeps_the_crlf_the_flow_printed(tmp_path: Path, judge: list[str]) -> None:
    """A flow that ends its lines with CRLF, as any Windows program does: a
    withheld line ends with CRLF like the lines around it, and the lines
    that hold no value are relayed as printed."""
    prefix = SHAPES["anthropic"].prefix
    plain = "an ordinary line from the flow"
    check = CanaryCheck(judge, tmp_path)
    try:
        check.env("APP_KEY", provider="model", shape="anthropic")
        env = {
            "SIDE_FILE": str(tmp_path / "side"),
            "MODE": "fragment",
            "PREFIX_LENGTH": str(len(prefix)),
            "PLAIN": plain,
            "NEWLINE": "\r\n",
        }
        check.run(["{python}", PROBE.as_posix()], id="main", env=env)
        output = check.judge().output
    finally:
        check.close()
    stdout = f"{plain}\r\n{WITHHELD}\r\nprefix {prefix}\r\n"
    assert f"--- flow main stdout (canaries redacted) ---\n{stdout}--- end" in output, output
    assert f"--- flow main stderr (canaries redacted) ---\n{WITHHELD}\r\n--- end" in output


def test_declarations_close_at_the_first_run(tmp_path: Path, judge: list[str]) -> None:
    check = CanaryCheck(judge, tmp_path)
    try:
        check.env("APP_KEY")
        variable = check.code("code.client.secret")
        assert variable == "CANARY_CODE_CLIENT_SECRET"
        assert check.mock_url.startswith("http://127.0.0.1:")
        with pytest.raises(RuntimeError):
            check.env("LATE_KEY")
        with pytest.raises(RuntimeError):
            check.mock(oauth=True)
    finally:
        check.close()


def test_a_placement_without_a_provider_is_named_at_the_first_run(
    tmp_path: Path, judge: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    check = CanaryCheck(judge, tmp_path)
    try:
        check.env("OWNED_KEY", provider="model")
        check.env("LOOSE_KEY")
        assert capsys.readouterr().err == ""
        check.mock_url  # noqa: B018 - starts the run
        assert capsys.readouterr().err == (
            "placement env.LOOSE_KEY has no provider: any request holding it counts as a leak\n"
        )
    finally:
        check.close()


def test_a_bad_declaration_is_refused_at_once(tmp_path: Path, judge: list[str]) -> None:
    check = CanaryCheck(judge, tmp_path)
    check.env("APP_KEY")
    with pytest.raises(Exception, match="already taken"):
        check.env("APP_KEY", id="env.SECOND")
    with pytest.raises(Exception, match="set by the runner|already taken"):
        check.env("PATH")


@pytest.mark.parametrize("value", [None, 0, "false"], ids=["none", "zero", "string"])
@pytest.mark.parametrize("kind", ["env", "code"])
def test_a_required_flag_that_is_not_a_bool_is_refused(
    tmp_path: Path, judge: list[str], kind: str, value: object
) -> None:
    # Only `required=False` opts out: anything else that is not a bool would
    # be read as not required and could turn an unexercised placement clean.
    check = CanaryCheck(judge, tmp_path)
    declare = check.env if kind == "env" else check.code
    name = "APP_KEY" if kind == "env" else "code.app"
    with pytest.raises(SpecError, match="required must be True or False"):
        declare(name, required=value)  # pyright: ignore[reportArgumentType]
    assert check._placements == []  # pyright: ignore[reportPrivateUsage]


def test_a_repeated_flow_id_is_refused_before_the_flow_starts(
    tmp_path: Path, judge: list[str]
) -> None:
    check = CanaryCheck(judge, tmp_path)
    try:
        check.env("APP_KEY", provider="model")
        first, second = tmp_path / "first", tmp_path / "second"
        probe = ["{python}", PROBE.as_posix()]
        assert check.run(probe, id="main", env={"SIDE_FILE": str(first)}) == "ok"
        with pytest.raises(SpecError, match="defined twice"):
            check.run(probe, id="main", env={"SIDE_FILE": str(second)})
        assert first.exists() and not second.exists()
        assert check.judge().clean
    finally:
        check.close()


def test_the_isolation_option_reaches_the_check(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(UNAVAILABLE, encoding="utf-8")
    done = _inner(tmp_path, "--canary-require-isolation", "-k", "test_clean")
    assert "ERROR test_inner.py::test_clean" in done.stdout, done.stdout
    assert "canary check exited 3" in done.stdout
    assert "incomplete: network_not_isolated" in done.stdout
    assert "network: not isolated (user namespaces are disabled)" in done.stdout
