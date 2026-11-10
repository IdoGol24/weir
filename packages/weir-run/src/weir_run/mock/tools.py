"""The mock's tool ledger (docs/canary.md, "Tool calls"): the runner's own
record of which tool calls the model issued and which tools executed, and
the one place an unmediated tool call is decided.

It lives in memory for one run and is never written to the canary ledger,
so the judge reads exactly what it always has. The model API puts every
call it issues here before the reply that carries it; the mock tells it
of every request it serves at an endpoint whose `tool` names the tool
that calls it, which is that tool executing. An execution is judged when
it happens: it answers the oldest call issued for that tool in the flow
that no execution has answered yet and whose result has not gone back
yet; or it repeats an execution whose result has not gone back yet (a
retry, or a tool's several requests), because a call issued for that
tool in the flow has no result in a model request yet; or it repeats
the tool's unmediated execution just before it; or else it is an
unmediated tool call. Tool results in model requests only say which
calls of the flow have gone back, so no later execution answers them,
and never clear a finding: a result under a call id issued in the flow
for one tool, naming another tool that executed while the asked tool
never did, is that other tool's unmediated tool call with the reason
`tool_mismatch`.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

NOT_ISSUED = "not_issued"
TOOL_MISMATCH = "tool_mismatch"
REASONS = (NOT_ISSUED, TOOL_MISMATCH)

# A tool result in a model request: the call id it answers and the tools
# the request names for it.
type ToolResult = tuple[str, frozenset[str]]


@dataclass(frozen=True, order=True)
class Unmediated:
    """One unmediated tool call: the tool that executed, why, and for
    `tool_mismatch` the tool the model asked for, as the program offered
    it (program-chosen text: print it only under the capture-text rule)."""

    tool: str
    reason: str
    issued_tool: str | None = None


class ToolLedger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # This flow's: the calls issued in it, by id; the calls no execution
        # has answered and whose result has not gone back yet, by tool, in
        # issue order; the calls whose result has gone back in a model
        # request; the tools that executed; for each tool, the unmediated
        # tool call its latest execution was, or None when that execution
        # was mediated; the calls whose result already made a substitution.
        self._flow: dict[str, str] = {}
        self._open: dict[str, list[str]] = {}
        self._reported: set[str] = set()
        self._ran: set[str] = set()
        self._last: dict[str, Unmediated | None] = {}
        self._substituted: set[tuple[str, str]] = set()
        self._found: Counter[Unmediated] = Counter()

    # -- what the mock tells it --------------------------------------------

    def issue(self, call_id: str, tool: str) -> str:
        """A call the model API issued; returns the id for the reply."""
        with self._lock:
            self._flow[call_id] = tool
            self._open.setdefault(tool, []).append(call_id)
        return call_id

    def executed(self, tool: str) -> None:
        """A request served at the tool's endpoint: the tool executed."""
        with self._lock:
            self._ran.add(tool)
            if self._open.get(tool):
                self._open[tool].pop(0)
                self._last[tool] = None
            elif any(t == tool and c not in self._reported for c, t in self._flow.items()):
                self._last[tool] = None
            elif self._last.get(tool) is None:
                found = Unmediated(tool, NOT_ISSUED)
                self._last[tool] = found
                self._found[found] += 1

    def start_flow(self) -> None:
        """A flow answers only the calls issued in it."""
        with self._lock:
            self._flow.clear()
            self._open.clear()
            self._reported.clear()
            self._ran.clear()
            self._last.clear()
            self._substituted.clear()

    def results(self, results: Sequence[ToolResult]) -> None:
        """A model request's tool results. Each result under a call id issued
        in this flow says that call's result has gone back, so no later
        execution answers it. One that names a tool that executed in this
        flow other than the tool the call was issued for, while that tool
        never executed in it, is an unmediated tool call with the reason
        `tool_mismatch`, once per call: it takes the place of that tool's
        `not_issued` run when its latest execution was one, and adds one
        otherwise."""
        with self._lock:
            for call_id, names in results:
                issued = self._flow.get(call_id)
                if issued is None:
                    continue
                self._reported.add(call_id)
                if call_id in self._open.get(issued, ()):
                    self._open[issued].remove(call_id)
                if issued in self._ran:
                    continue
                for tool in sorted(names - {issued}):
                    if tool not in self._ran or (call_id, tool) in self._substituted:
                        continue
                    self._substituted.add((call_id, tool))
                    mismatch = Unmediated(tool, TOOL_MISMATCH, issued)
                    found = self._last.get(tool)
                    if found is not None and found.reason == NOT_ISSUED:
                        self._found[found] -= 1
                        if not self._found[found]:
                            del self._found[found]
                    self._found[mismatch] += 1
                    self._last[tool] = mismatch

    # -- what the run reads ------------------------------------------------

    def unmediated(self) -> list[tuple[Unmediated, int]]:
        """Each unmediated tool call and how many times, sorted."""
        with self._lock:
            return sorted(self._found.items())
