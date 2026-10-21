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

from weir_run.pytest_plugin import CanaryCheck

PROBE = Path(__file__).parent / "_probe_flow.py"

INNER_TESTS = f"""
PROBE = {json.dumps(PROBE.as_posix())}

def _env(tmp_path, mode):
    return {{"SIDE_FILE": str(tmp_path / "side"), "MODE": mode}}

def test_clean(canary_check, tmp_path):
    canary_check.env("APP_KEY", required=True)
    assert canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "")) == "ok"

def test_leaky(canary_check, tmp_path):
    canary_check.env("APP_KEY")
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "leak"))

def test_crashing(canary_check, tmp_path):
    canary_check.env("APP_KEY")
    canary_check.run(["{{python}}", PROBE], id="crashy", env=_env(tmp_path, "crash"))

def test_explicit_judge(canary_check, tmp_path):
    canary_check.env("APP_KEY")
    canary_check.run(["{{python}}", PROBE], env=_env(tmp_path, "leak"))
    result = canary_check.judge()
    assert result.code == 1
    assert "LEAK env.APP_KEY" in result.report
"""


@pytest.fixture(scope="module")
def inner(tmp_path_factory: pytest.TempPathFactory) -> subprocess.CompletedProcess[str]:
    root = tmp_path_factory.mktemp("inner")
    (root / "test_inner.py").write_text(INNER_TESTS, encoding="utf-8")
    # Only what an interpreter needs to start; not the test process's environment.
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root), "TMP": str(root)}
    env["TEMP"] = env["TMPDIR"] = str(root)
    if sys.platform == "win32":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        env["USERPROFILE"] = str(root)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-rA", "-p", "no:cacheprovider", str(root)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_the_plugin_loads_through_its_entry_point(inner: subprocess.CompletedProcess[str]) -> None:
    assert "fixture 'canary_check' not found" not in inner.stdout


def test_a_clean_flow_passes(inner: subprocess.CompletedProcess[str]) -> None:
    assert "PASSED test_inner.py::test_clean" in inner.stdout, inner.stdout


def test_a_leak_fails_the_test_with_the_value_free_report(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "ERROR test_inner.py::test_leaky" in inner.stdout, inner.stdout
    assert "canary check exited 1" in inner.stdout
    assert "LEAK env.APP_KEY" in inner.stdout


def test_an_incomplete_run_fails_the_test(inner: subprocess.CompletedProcess[str]) -> None:
    assert "ERROR test_inner.py::test_crashing" in inner.stdout, inner.stdout
    assert "incomplete: flow_not_ok crashy=failed" in inner.stdout


def test_judge_can_be_called_to_assert_on_the_result(
    inner: subprocess.CompletedProcess[str],
) -> None:
    assert "PASSED test_inner.py::test_explicit_judge" in inner.stdout, inner.stdout


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


def test_a_bad_declaration_is_refused_at_once(tmp_path: Path, judge: list[str]) -> None:
    check = CanaryCheck(judge, tmp_path)
    check.env("APP_KEY")
    with pytest.raises(Exception, match="already taken"):
        check.env("APP_KEY", id="env.SECOND")
    with pytest.raises(Exception, match="set by the runner|already taken"):
        check.env("PATH")
