"""`weir-run verify` and `weir-run predicate` end to end (docs/verify.md).

Every run is judged by the real `weir canary judge`. The target is
`_fake_target.py` behind a shell shim, in fake values only, so CI needs
neither real tool. The fake writes the key it held to a side file in the
test's own directory: the only way a test learns a value.

Expectations come from the artifacts: the sink names, verdicts and
incomplete reasons from the committed schema, and each run's verdict from
the evidence record it wrote.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import msgspec
import pytest
from click.testing import CliRunner, Result

from weir_run import cli, evidence, isolation, verify

SCHEMA_FILE = Path(__file__).parents[1] / "schema_artifacts" / "weir-verify-evidence.v1.schema.json"
FAKE = Path(__file__).parent / "_fake_target.py"
DIGEST = "sha256:" + hashlib.sha256(b"weir-run verify test image").hexdigest()
TARGET = "iron-proxy"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the fake target is a shell shim")


def _enum(definition: str, field: str) -> list[str]:
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    return schema["$defs"][definition]["properties"][field]["enum"]


SINKS = _enum("Sink", "name")


def _verify(tmp_path: Path, judge: list[str], mode: str | None) -> tuple[Result, Any, str]:
    """Run verify against the fake in mode (None: no target at all).
    Returns the result, the evidence record and the key the target held."""
    side, shim = tmp_path / "held.txt", tmp_path / "fake-target"
    if mode is not None:
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" {mode} "{side}" "$@"\n')
        shim.chmod(0o755)
    record_path = tmp_path / "evidence.json"
    args = ["verify", "--target", TARGET, "--target-command", str(shim)]
    args += ["--evidence", str(record_path), "--image-digest", DIGEST, "--weir", judge[0]]
    result = CliRunner().invoke(cli.main, args)
    record = json.loads(record_path.read_bytes()) if record_path.exists() else None
    held = side.read_text(encoding="utf-8") if side.exists() else ""
    return result, record, held


def _predicate(tmp_path: Path, record: Any) -> Result:
    source = tmp_path / "record.json"
    source.write_text(json.dumps(record), encoding="utf-8")
    return CliRunner().invoke(cli.main, ["predicate", "--evidence", str(source)])


def _result_of(tmp_path: Path, record: Any) -> str:
    result = _predicate(tmp_path, record)
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)["result"]


# -- the verdicts ----------------------------------------------------------


@posix_only
def test_a_working_swap_is_clean_on_every_sink(
    tmp_path: Path, judge: list[str], isolated: None
) -> None:
    result, record, held = _verify(tmp_path, judge, "clean")
    assert result.exit_code == 0, result.output
    assert held, "the target never held the key"
    assert [s["name"] for s in record["sinks"]] == SINKS
    assert all(s["verdict"] == "clean" and s["received"] >= 1 for s in record["sinks"])
    assert (record["verdict"], record["incomplete"]) == ("clean", [])
    assert [p["state"] for p in record["placements"]] == ["exercised"]
    assert record["image_digest"] == DIGEST
    assert record["target"] == TARGET
    assert TARGET in {t["name"] for t in record["tools"]}
    assert _result_of(tmp_path, record) == "PASSED"


@posix_only
@pytest.mark.parametrize(
    ("mode", "leaking"), [("log", ["console"]), ("anyhost", ["outbound", "telemetry"])]
)
def test_a_key_that_reaches_a_sink_is_a_leak(
    tmp_path: Path, judge: list[str], isolated: None, mode: str, leaking: list[str]
) -> None:
    result, record, _ = _verify(tmp_path, judge, mode)
    assert result.exit_code == 1, result.output
    assert record["verdict"] == "leak"
    assert [s["name"] for s in record["sinks"] if s["verdict"] == "leak"] == leaking
    assert _result_of(tmp_path, record) == "FAILED"


# -- never a false clean ----------------------------------------------------


@posix_only
@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        (None, "target_missing"),
        ("noversion", "target_missing"),
        ("noinject", "required_not_exercised"),
        ("crash", "flow_not_ok"),
        ("drop", "sink_not_reached"),
        ("drop", "flow_not_ok"),
    ],
)
def test_what_could_not_be_checked_is_incomplete(
    tmp_path: Path, judge: list[str], isolated: None, mode: str | None, reason: str
) -> None:
    result, record, _ = _verify(tmp_path, judge, mode)
    assert result.exit_code == 3, result.output
    assert reason in _enum("Incomplete", "reason")
    assert record["verdict"] == "incomplete"
    assert reason in {i["reason"] for i in record["incomplete"]}
    assert _result_of(tmp_path, record) == "FAILED"


@posix_only
@pytest.mark.parametrize("mode", ["fragment", "fragmentbody"])
def test_a_slice_of_the_key_is_incomplete_and_never_printed(
    tmp_path: Path, judge: list[str], isolated: None, mode: str
) -> None:
    """A slice of the key is no needle, so the judge finds no hit in the
    target's log or in a request body; the run is still never clean, and
    verify's own output holds no 6-character run of the key."""
    result, record, held = _verify(tmp_path, judge, mode)
    assert result.exit_code == 3, result.output
    assert "value_fragment" in _enum("Incomplete", "reason")
    assert [s["verdict"] for s in record["sinks"]] == ["clean"] * len(SINKS)
    assert [i["reason"] for i in record["incomplete"]] == ["value_fragment"]
    assert _result_of(tmp_path, record) == "FAILED"
    windows = {held[i : i + 6] for i in range(len(held) - 5)}
    assert not [w for w in windows if w in result.stdout + result.stderr]


@posix_only
def test_a_run_without_isolation_is_incomplete(
    tmp_path: Path, judge: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def jail() -> isolation.Jail:
        raise isolation.Unavailable("user namespaces are disabled")

    monkeypatch.setattr(isolation, "jail", jail)
    result, record, _ = _verify(tmp_path, judge, "clean")
    assert result.exit_code == 3, result.output
    assert [i["reason"] for i in record["incomplete"]] == ["network_not_isolated"]
    assert record["network"]["isolated"] is False
    assert _result_of(tmp_path, record) == "FAILED"


@posix_only
def test_a_record_the_judge_does_not_call_clean_is_incomplete(
    tmp_path: Path, judge: list[str], isolated: None
) -> None:
    """The real judge, but its plain verdict is never clean: the record's
    fields alone cannot make the run clean."""
    wrapper = tmp_path / "weir"
    wrapper.write_text(
        f'#!/bin/sh\n"{judge[0]}" "$@" || exit\n'
        'case "$*" in *--help*|*--json*|*--version*) ;; *) exit 3 ;; esac\n'
    )
    wrapper.chmod(0o755)
    result, record, _ = _verify(tmp_path, [str(wrapper)], "clean")
    assert result.exit_code == 3, result.output
    assert [s["verdict"] for s in record["sinks"]] == ["clean"] * len(SINKS)
    assert "judge_not_clean" in _enum("Incomplete", "reason")
    assert [i["reason"] for i in record["incomplete"]] == ["judge_not_clean"]
    assert _result_of(tmp_path, record) == "FAILED"


UNKNOWN_REASON = "a_reason_this_verify_does_not_know"
ADD_REASON = f"""import json, subprocess, sys
done = subprocess.run(sys.argv[1:], capture_output=True)
out = done.stdout
if "--json" in sys.argv:
    report = json.loads(out)
    report["incomplete"].append({{"reason": "{UNKNOWN_REASON}"}})
    out = json.dumps(report).encode()
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(done.stderr)
sys.exit(done.returncode)
"""


@posix_only
def test_a_judge_reason_verify_does_not_know_is_incomplete(
    tmp_path: Path, judge: list[str], isolated: None
) -> None:
    """The real judge, its report given a reason no release of it has yet,
    as a newer judge may: a record, never clean and never refused."""
    script, wrapper = tmp_path / "add_reason.py", tmp_path / "weir"
    script.write_text(ADD_REASON, encoding="utf-8")
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "{judge[0]}" "$@"\n')
    wrapper.chmod(0o755)
    result, record, _ = _verify(tmp_path, [str(wrapper)], "clean")
    assert result.exit_code == 3, result.output
    reasons = _enum("Incomplete", "reason")
    assert UNKNOWN_REASON not in reasons and "judge_other" in reasons
    assert [s["verdict"] for s in record["sinks"]] == ["clean"] * len(SINKS)
    assert (record["verdict"], record["incomplete"]) == (
        "incomplete",
        [{"reason": "judge_other", "count": 1}],
    )
    predicate = _predicate(tmp_path, record)
    assert predicate.exit_code == 0, predicate.output
    doc = json.loads(predicate.stdout)
    assert doc["result"] == "FAILED"
    assert "incomplete:judge_other" in doc["failedTests"]


# -- the record holds no value ------------------------------------------------


def _forms(data: bytes) -> list[str]:
    """data as text, URL-decoded, JSON-unescaped, and every base64 run decoded."""
    text = data.decode("utf-8")
    forms = [text, unquote(text), json.dumps(json.loads(text), ensure_ascii=False)]
    for run in re.findall(r"[A-Za-z0-9+/_=-]{8,}", text):
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                forms.append(decode(run + "=" * (-len(run) % 4)).decode("latin-1"))
            except (binascii.Error, ValueError):
                pass
    return forms


@posix_only
def test_the_record_and_predicate_hold_no_trace_of_the_key(
    tmp_path: Path, judge: list[str], isolated: None
) -> None:
    result, record, held = _verify(tmp_path, judge, "anyhost")
    assert result.exit_code == 1, result.output
    assert len(held) >= 16
    predicate = _predicate(tmp_path, record).stdout.encode()
    windows = {held[i : i + 6] for i in range(len(held) - 5)}
    for artifact in ((tmp_path / "evidence.json").read_bytes(), predicate):
        for form in _forms(artifact):
            assert not [w for w in windows if w in form]


# -- the contract ------------------------------------------------------------


def test_the_committed_schema_is_generated_from_the_record() -> None:
    committed = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert msgspec.json.schema(evidence.Evidence) == committed, (
        "schema_artifacts/weir-verify-evidence.v1.schema.json is stale - regenerate it"
        " with msgspec.json.schema(weir_run.evidence.Evidence)"
    )


def _record(verdict: str) -> dict[str, Any]:
    """A self-consistent record with verdict, for the predicate's checks."""
    sinks = [{"name": n, "verdict": "clean", "received": 1, "hits": 0} for n in SINKS]
    placement: dict[str, Any] = {"id": "env.ANTHROPIC_API_KEY", "state": "exercised", "hits": 0}
    incomplete: list[dict[str, Any]] = []
    if verdict == "leak":
        sinks[0].update(verdict="leak", hits=1)
        placement.update(state="leaked", hits=1)
    if verdict == "incomplete":
        sinks[-1].update(verdict="not_reached", received=0)
        incomplete = [{"reason": "sink_not_reached", "count": 1}]
    return {
        "schema": "weir-verify-evidence/1",
        "target": TARGET,
        "tools": [{"name": "weir-run", "version": "0.2.1"}],
        "manifest_sha256": "0" * 64,
        "image_digest": DIGEST,
        "verdict": verdict,
        "placements": [placement],
        "sinks": sinks,
        "incomplete": incomplete,
        "network": {"isolated": True, "direct_attempts": 0},
    }


def test_only_clean_passes_and_nothing_is_warned(tmp_path: Path) -> None:
    for verdict in _enum("Evidence", "verdict"):
        result = _predicate(tmp_path, _record(verdict))
        assert result.exit_code == 0, result.output
        predicate = json.loads(result.stdout)
        assert predicate["result"] == ("PASSED" if verdict == "clean" else "FAILED")
        assert predicate["warnedTests"] == []
        described = predicate["configuration"][1]
        assert described["annotations"] == _record(verdict)
        source = (tmp_path / "record.json").read_bytes()
        assert described["digest"]["sha256"] == hashlib.sha256(source).hexdigest()


@pytest.mark.parametrize("where", ["top", "nested"])
def test_a_record_with_another_field_is_refused(tmp_path: Path, where: str) -> None:
    record = _record("clean")
    (record if where == "top" else record["sinks"][0])["note"] = "x"
    result = _predicate(tmp_path, record)
    assert result.exit_code == 2, result.output
    assert result.stdout == ""


def test_a_target_tool_or_placement_that_is_not_built_in_still_validates(
    tmp_path: Path,
) -> None:
    """Names are patterns: a record from a later target, tool or placement
    is still weir-verify-evidence/1."""
    record = _record("clean")
    record["target"] = "other-swap"
    record["tools"].append({"name": "other-swap", "version": "1.0.0"})
    record["placements"][0]["id"] = "env.OTHER_API_KEY"
    assert record["target"] not in verify.TARGETS
    assert _result_of(tmp_path, record) == "PASSED"


@pytest.mark.parametrize(
    "change",
    [
        {"target": "Iron Proxy"},
        {"target": "x" * 41},
        {"tools": [{"name": "-weir-run", "version": "1.0.0"}]},
        {"placements": [{"id": "file.key", "state": "exercised", "hits": 0}]},
    ],
)
def test_a_name_outside_its_pattern_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    result = _predicate(tmp_path, _record("clean") | change)
    assert result.exit_code == 2, result.output
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("base", "change"),
    [
        ("incomplete", {"verdict": "clean"}),
        ("incomplete", {"verdict": "leak"}),
        ("clean", {"network": {"isolated": True, "direct_attempts": 5}}),
        ("clean", {"network": {"isolated": False, "direct_attempts": 0}}),
    ],
)
def test_a_record_whose_verdict_its_fields_do_not_support_is_refused(
    tmp_path: Path, base: str, change: dict[str, Any]
) -> None:
    result = _predicate(tmp_path, _record(base) | change)
    assert result.exit_code == 2, result.output
    assert result.stdout == ""


def test_an_unusable_image_digest_is_refused_before_anything_runs(
    tmp_path: Path, judge: list[str]
) -> None:
    args = ["verify", "--target", "iron-proxy", "--image-digest", "sha256:abc"]
    result = CliRunner().invoke(cli.main, [*args, "--weir", judge[0]])
    assert result.exit_code == 2
    assert "image digest" in result.output
