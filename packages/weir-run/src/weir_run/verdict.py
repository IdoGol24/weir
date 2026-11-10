"""The run's verdict (docs/canary.md, "Tool calls" and "Exit codes"): the
one place it is combined. The judge decides where the planted values went;
the mock's tool ledger decides which tools ran without a model request.
Any finding fails the run (exit 1: a leak, or an unmediated tool call);
otherwise any gap makes it incomplete (exit 3); only neither is clean.

The run's text report is the judge's, with one line per group of
unmediated tool calls before its coverage line and the run's result as
its last line. The run's JSON report, `canary-report/2`, carries the run's
result, exit code and finding types as data, and the judge's own report
(canary-report/1) unchanged as `judge`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from typing import Annotated, Any, Literal

import msgspec

from weir_run.mock.tools import NOT_ISSUED, TOOL_MISMATCH, Unmediated
from weir_run.spec import TOOL_NAME_RE

SCHEMA = "canary-report/2"
Result = Literal["clean", "leak", "unmediated-tool-call", "incomplete"]
FindingType = Literal["leak", "unmediated-tool-call"]
Reason = Literal["not_issued", "tool_mismatch"]
# docs/canary.md, "Exit codes": the judge's codes that carry a report.
JUDGE_RESULTS: dict[int, Result] = {0: "clean", 1: "leak", 3: "incomplete"}
EXIT_CODES: dict[Result, int] = {"clean": 0, "leak": 1, "unmediated-tool-call": 1, "incomplete": 3}
# docs/canary.md, "Tool calls": the name of a tool the program offered
# under a name the runner does not print.
UNNAMED = "[unnamed]"
_COVERAGE = "coverage: "
_RESULT = "result: "


class _Struct(msgspec.Struct, forbid_unknown_fields=True, kw_only=True):
    pass


class UnmediatedEntry(_Struct):
    """One group of unmediated tool calls: the tool that executed, why, the
    tool the model asked for (`tool_mismatch`) and how many."""

    tool: Annotated[str, msgspec.Meta(pattern=f"^{TOOL_NAME_RE.pattern}$")]
    reason: Reason
    issued_tool: str | None
    count: Annotated[int, msgspec.Meta(ge=1)]


class Report(_Struct):
    """canary-report/2: what `weir-run run --report` writes."""

    schema: Literal["canary-report/2"]
    result: Result
    exit_code: Literal[0, 1, 3]
    findings: list[FindingType]
    unmediated: list[UnmediatedEntry]
    judge: Annotated[
        dict[str, Any],
        msgspec.Meta(
            description="The judge's own JSON report (canary-report/1), unchanged:"
            " its own JSON Schema is weir-scan's canary-report.v1.schema.json."
        ),
    ]


def entries(
    found: Sequence[tuple[Unmediated, int]], safe: Callable[[str], str]
) -> list[UnmediatedEntry]:
    """The tool ledger's unmediated tool calls as printed: the tool the
    model asked for under the capture-text rule (safe), `[unnamed]` when it
    breaks the tool-name rule, and grouped as printed."""
    groups: Counter[tuple[str, str, str | None]] = Counter()
    for u, count in found:
        issued = u.issued_tool
        if issued is not None:
            issued = safe(issued) if TOOL_NAME_RE.fullmatch(issued) else UNNAMED
        groups[(u.tool, u.reason, issued)] += count
    ordered = sorted(groups.items(), key=lambda g: (g[0][0], g[0][1], g[0][2] or ""))
    return [
        msgspec.convert(
            {"tool": tool, "reason": reason, "issued_tool": issued, "count": count},
            UnmediatedEntry,
        )
        for (tool, reason, issued), count in ordered
    ]


def combine(
    judge_code: int, unmediated: Sequence[UnmediatedEntry]
) -> tuple[Result, list[FindingType]]:
    """The run's result and finding types from the judge's exit code (0, 1
    or 3) and the unmediated tool calls: a leak first, then an unmediated
    tool call, then the judge's own result."""
    findings: list[FindingType] = []
    if judge_code == 1:
        findings.append("leak")
    if unmediated:
        findings.append("unmediated-tool-call")
    return (findings[0] if findings else JUDGE_RESULTS[judge_code]), findings


def line(entry: UnmediatedEntry) -> str:
    """On execution only: an unmediated tool call is never called a leak."""
    if entry.reason == TOOL_MISMATCH:
        why = f"executed in answer to a model request for {entry.issued_tool or UNNAMED}"
    else:
        assert entry.reason == NOT_ISSUED
        why = "executed without a model request"
    repeat = f" ({entry.count}x)" if entry.count > 1 else ""
    return f"unmediated tool call: {entry.tool} ({why}){repeat}"


def text(judge_stdout: bytes, unmediated: Sequence[UnmediatedEntry], result: Result) -> bytes:
    """The judge's text report with the unmediated lines before its coverage
    line and the run's result as its last line."""
    lines = judge_stdout.replace(b"\r\n", b"\n").decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if lines and lines[-1].startswith(_RESULT):
        lines.pop()
    at = next((i for i, x in enumerate(lines) if x.startswith(_COVERAGE)), len(lines))
    lines[at:at] = [line(e) for e in unmediated]
    lines.append(f"{_RESULT}{result}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def report(
    judge_json: bytes,
    unmediated: Sequence[UnmediatedEntry],
    result: Result,
    findings: list[FindingType],
) -> bytes:
    """The run's JSON report, checked against its schema on the way out."""
    doc = msgspec.convert(
        {
            "schema": SCHEMA,
            "result": result,
            "exit_code": EXIT_CODES[result],
            "findings": findings,
            "unmediated": [msgspec.to_builtins(e) for e in unmediated],
            "judge": msgspec.json.decode(judge_json),
        },
        Report,
    )
    return msgspec.json.format(msgspec.json.encode(doc), indent=2) + b"\n"
