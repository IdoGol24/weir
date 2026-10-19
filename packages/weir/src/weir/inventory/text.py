"""`weir inventory` screen output: names only.

Every string printed here comes from a value-free `Inventory`, so this module
cannot print a value even by mistake: there is none to print. Unknown
environment variables are a count on screen; their names go to a file.
"""

from __future__ import annotations

from weir._text_safety import plural
from weir.inventory._types import (
    Credential,
    EnvSource,
    EnvVarName,
    Inventory,
    Reason,
    Source,
    ValueState,
)

_SOURCE_TITLES = {
    Source.STANDARD_LOCATION: "standard locations",
    Source.PROJECT_SCAN: "project files",
    Source.ENVIRONMENT: "launch environment and shell startup files",
    Source.MAP: "approved map (.weir/reach.yml)",
}
# Why each credential counts, as a short code plus the legend printed under
# the list.
_REASONS = {
    Reason.LOCATION: "field",
    Reason.NAME: "name",
    Reason.SHAPE: "shape",
    Reason.SCANNER: "scanner",
    Reason.MAP: "map",
}
_LEGEND = {
    Reason.LOCATION: "a credential field of a standard credential file",
    Reason.NAME: "the field or variable name suggests a secret",
    Reason.SHAPE: "the value has a credential shape",
    Reason.SCANNER: "an imported gitleaks or trufflehog result",
    Reason.MAP: "approved in .weir/reach.yml",
}
_STATES = {
    ValueState.LITERAL: None,
    ValueState.DYNAMIC: "value from a shell expansion",
    ValueState.ABSENT: "whole file",
    ValueState.NOT_IN_FILE: "value not in the file",
    ValueState.TYPED_SCALAR: "value typed as a non-string",
    ValueState.PARTIAL: "value not fully read",
}
_MAX_COLUMN = 60


def where(location_display: str, line: int | None, commit: str | None = None) -> str:
    text = f"{location_display}:{line}" if line is not None else location_display
    return f"{text} @ {commit[:12]}" if commit else text


def _label(c: Credential) -> str:
    return f"{c.name} [{c.scope}]" if c.scope else c.name


def _notes(c: Credential) -> str:
    notes = [
        n for n in (
            _STATES[c.value_state],
            f"same value as {plural(len(c.same_value_as), 'other')}"
            if c.same_value_as else None,
            "git-ignored" if c.git_ignored else None,
        ) if n
    ]
    return f"  ({', '.join(notes)})" if notes else ""


def unknown_list_lines(names: list[EnvVarName]) -> list[str]:
    """The unknown-variable file: `NAME<TAB>location`, one per line."""
    return [
        f"{n.name}\t{where(n.location.display, n.location.line)}" for n in names
    ]


def inventory_lines(report: Inventory, *, unknown_list_path: str | None) -> list[str]:
    inputs = report.inputs
    counts = report.counts
    env = {
        EnvSource.FILE: f"env file {inputs.env_file}",
        EnvSource.PROCESS: "this process's environment",
        EnvSource.NONE: "not given (shell startup files only)",
    }[inputs.env_source]
    lines = [
        f"weir inventory (names only; standard location list v{inputs.location_list_version})",
        f"  home        {inputs.home}",
        f"  project     {inputs.project}",
        f"  launch env  {env}",
        f"  map         {inputs.map_file or 'none (.weir/reach.yml not found)'}",
        "",
        f"{plural(counts.credentials, 'credential')}"
        f" ({plural(counts.distinct_values, 'distinct value')} read)",
    ]
    rows = [(c, _label(c), where(c.location.display, c.location.line, c.location.commit))
            for c in report.credentials]
    name_w = min(max((len(r[1]) for r in rows), default=0), _MAX_COLUMN)
    where_w = min(max((len(r[2]) for r in rows), default=0), _MAX_COLUMN)
    why_w = max(len(code) for code in _REASONS.values())
    for source in Source:
        group = [r for r in rows if r[0].source is source]
        lines.append(f"  {_SOURCE_TITLES[source]}: {len(group)}")
        for cred, label, loc in group:
            why = _REASONS[cred.reason].ljust(why_w)
            lines.append(
                f"    {label.ljust(name_w)}  {loc.ljust(where_w)}  {why}{_notes(cred)}".rstrip()
            )
    if rows:
        lines.append("")
        for i, (reason, meaning) in enumerate(_LEGEND.items()):
            lead = "why" if i == 0 else ""
            lines.append(f"  {lead:<5}{_REASONS[reason].ljust(why_w)}  {meaning}")

    if report.git_ignored:
        lines += [
            "",
            f"git-ignored, so not covered: {plural(len(report.git_ignored), 'file')}",
            "  hidden from the Grep tool's directory search;"
            " Read, cat and grep -r still reach them",
        ]
        lines += [f"  {g.display}" for g in report.git_ignored]

    lines.append("")
    unknown = f"unknown environment variables: {counts.env_unknown}"
    if unknown_list_path is not None:
        unknown += f" (names in {unknown_list_path})"
    lines.append(unknown)
    if counts.env_fine:
        lines.append(f"marked fine in the map: {counts.env_fine}")
    lines.append(f"not secrets (number, boolean, path, hostname, empty): {counts.env_not_secret}")
    if counts.env_withheld:
        lines.append(f"names withheld (they read as key material): {counts.env_withheld}")

    if report.not_scanned:
        lines += ["", f"not scanned: {counts.not_scanned}"]
        width = min(max(len(n.display) for n in report.not_scanned), _MAX_COLUMN)
        lines += [
            f"  {n.display.ljust(width)}  {n.reason.value.replace('_', ' ')}"
            for n in report.not_scanned
        ]
    if report.not_fully_read:
        lines += ["", f"present, not fully read: {counts.not_fully_read}"]
        spots = [(where(p.display, p.line), p.reason.value.replace("_", " "))
                 for p in report.not_fully_read]
        width = min(max(len(w) for w, _ in spots), _MAX_COLUMN)
        lines += [f"  {w.ljust(width)}  {why}" for w, why in spots]
    return lines
