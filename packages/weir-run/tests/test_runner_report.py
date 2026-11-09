"""The run's JSON report, `canary-report/2` (weir-run README, "Output";
docs/canary.md, "Tool calls"): its committed schema is generated from the
report's structs, refuses other fields on every object weir-run defines,
and names exactly the results, finding types and reasons the contract
names. Its `result` and `exit_code` are the run's, and the judge's own
report is kept unchanged as `judge`. The run's own verdict is combined in
one place.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import msgspec
import pytest

from weir_run import verdict

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_FILE = Path(__file__).parents[1] / "schema_artifacts" / "canary-report.v2.schema.json"
DOC = (ROOT / "docs" / "canary.md").read_text(encoding="utf-8")
SECTION = DOC.split("\n## Tool calls\n", 1)[1].split("\n## ", 1)[0]
JUDGE_SCHEMA = ROOT / "packages" / "weir" / "schema_artifacts" / "canary-report.v1.schema.json"


def _schema() -> Any:
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def test_the_committed_schema_is_generated_from_the_report() -> None:
    assert msgspec.json.schema(verdict.Report) == _schema(), (
        "schema_artifacts/canary-report.v2.schema.json is stale - regenerate it"
        " with msgspec.json.schema(weir_run.verdict.Report)"
    )


def test_every_object_weir_run_defines_refuses_other_fields() -> None:
    objects = [d for d in _schema()["$defs"].values() if d.get("type") == "object"]
    assert {d["title"] for d in objects} == {"Report", "UnmediatedEntry"}
    assert all(d["additionalProperties"] is False for d in objects)


def _judge_report(result: str, code: int) -> dict[str, Any]:
    """A canary-report/1 with every field its committed schema requires."""
    fields: list[str] = json.loads(JUDGE_SCHEMA.read_text(encoding="utf-8"))["$defs"]["Report"][
        "required"
    ]
    doc: dict[str, Any] = {f: [] for f in fields}
    doc.update(schema="canary-report/1", result=result, exit_code=code, coverage={}, network={})
    return doc


@pytest.mark.parametrize(("code", "judged"), sorted(verdict.JUDGE_RESULTS.items()))
def test_the_top_level_result_is_always_the_runs(code: int, judged: str) -> None:
    """Never a false clean in the report: with an unmediated tool call the
    top-level result is never clean and exit_code is 1, whatever the judge
    said; without one it is the judge's. The judge's report is kept as
    it was."""
    judge = _judge_report(judged, code)
    data = json.dumps(judge, indent=2).encode()
    for entries in ([], [_entry()]):
        result, findings = verdict.combine(code, entries)
        doc = json.loads(verdict.report(data, entries, result, findings))
        assert doc["schema"] == _schema()["$defs"]["Report"]["properties"]["schema"]["enum"][0]
        assert doc["judge"] == judge
        assert doc["unmediated"] == [msgspec.to_builtins(e) for e in entries]
        if entries:
            assert doc["result"] != "clean" and doc["exit_code"] == 1
            assert "unmediated-tool-call" in doc["findings"]
        else:
            assert (doc["result"], doc["exit_code"]) == (judged, code)


def test_a_report_outside_its_schema_is_refused_on_the_way_out() -> None:
    data = json.dumps(_judge_report("clean", 0)).encode()
    with pytest.raises(msgspec.ValidationError):
        verdict.report(data, [], "clean", ["no-such-finding"])  # pyright: ignore[reportArgumentType]


def test_the_schema_names_what_the_contract_names() -> None:
    defs = _schema()["$defs"]
    results = re.search(r"`result: ([a-z|-]+)`", SECTION)
    assert results is not None
    assert sorted(defs["Report"]["properties"]["result"]["enum"]) == sorted(
        results.group(1).split("|")
    )
    reasons = set(re.findall(r"^\| `(\w+)` \| ", SECTION, re.MULTILINE))
    assert set(defs["UnmediatedEntry"]["properties"]["reason"]["enum"]) == reasons
    findings = defs["Report"]["properties"]["findings"]["items"]["enum"]
    assert set(findings) == {"leak", "unmediated-tool-call"} <= set(results.group(1).split("|"))


def _entry(reason: str = "not_issued") -> verdict.UnmediatedEntry:
    issued = None if reason == "not_issued" else "read_file"
    return verdict.UnmediatedEntry(tool="send_file", reason=reason, issued_tool=issued, count=1)  # pyright: ignore[reportArgumentType]


def test_any_finding_fails_the_run_otherwise_any_gap_otherwise_clean() -> None:
    """docs/canary.md: "Any finding fails the run; otherwise any gap makes
    it incomplete; only a run with neither is clean." The judge's codes
    are the contract's; the run's code is the run's result's."""
    judge_results = dict(verdict.JUDGE_RESULTS)
    for code, judged in judge_results.items():
        assert verdict.combine(code, []) == (judged, ["leak"] if judged == "leak" else [])
        result, findings = verdict.combine(code, [_entry()])
        assert "unmediated-tool-call" in findings and verdict.EXIT_CODES[result] == 1
        assert result == ("leak" if judged == "leak" else "unmediated-tool-call")


def test_the_text_report_keeps_the_judges_lines_and_ends_in_the_runs_result() -> None:
    judged = (
        b"not exercised: env.A\r\ncoverage: 1 placements\r\n"
        b"network isolated: 0 direct connections blocked\r\nresult: incomplete\r\n"
    )
    entries = [_entry("tool_mismatch"), _entry()]
    out = verdict.text(judged, entries, "unmediated-tool-call").decode().splitlines()
    assert out == [
        "not exercised: env.A",
        verdict.line(entries[0]),
        verdict.line(entries[1]),
        "coverage: 1 placements",
        "network isolated: 0 direct connections blocked",
        "result: unmediated-tool-call",
    ]
    assert verdict.text(judged, [], "incomplete") == judged.replace(b"\r\n", b"\n")


def test_a_tool_name_the_program_offered_is_printed_only_under_the_rules() -> None:
    from weir_run.mock.tools import Unmediated

    found = [
        (Unmediated("send_file", "tool_mismatch", "two words"), 1),
        (Unmediated("send_file", "tool_mismatch", "holds_a_value"), 2),
        (Unmediated("send_file", "tool_mismatch", "read_file"), 1),
    ]
    shown = verdict.entries(found, lambda s: "[withheld]" if "value" in s else s)
    assert [(e.issued_tool, e.count) for e in shown] == [
        ("[unnamed]", 1),
        ("[withheld]", 2),
        ("read_file", 1),
    ]
