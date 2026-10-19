"""Source 2, imported half: gitleaks and trufflehog results.

Free scanners out-find Weir's own catalog, so the inventory imports their
results rather than competing on detection. A report holds the secret itself
(gitleaks `Secret`, trufflehog `Raw`); it is read into memory, fingerprinted
and located, and never copied anywhere. Error messages name the report and
the entry index, never an entry's content.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import msgspec

from weir.inventory._scan import absolute


class ScannerReportError(Exception):
    pass


@dataclass(frozen=True)
class ScannerResult:
    tool: str  # "gitleaks" | "trufflehog"
    rule: str
    path: Path | None
    line: int | None
    commit: str | None
    value: str | None


class _GitleaksFinding(msgspec.Struct, frozen=True):
    RuleID: str
    File: str = ""
    StartLine: int = 0
    Secret: str = ""
    Commit: str = ""


class _TrufflehogFile(msgspec.Struct, frozen=True):
    file: str = ""
    line: int = 0
    commit: str = ""


class _TrufflehogData(msgspec.Struct, frozen=True):
    Filesystem: _TrufflehogFile | None = None
    Git: _TrufflehogFile | None = None


class _TrufflehogMeta(msgspec.Struct, frozen=True):
    Data: _TrufflehogData = msgspec.field(default_factory=_TrufflehogData)


class _TrufflehogResult(msgspec.Struct, frozen=True):
    DetectorName: str
    SourceMetadata: _TrufflehogMeta = msgspec.field(default_factory=_TrufflehogMeta)
    Raw: str = ""
    RawV2: str = ""


def _resolve(raw: str, project: Path) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    return absolute(path if path.is_absolute() else project / path)


def _gitleaks_secret(secret: str) -> str | None:
    """`--redact` writes `REDACTED`, `--redact=N` a truncated `prefix...`:
    neither is the credential's value."""
    if not secret or secret == "REDACTED" or secret.endswith("..."):
        return None
    return secret


def _read(report: Path) -> bytes:
    try:
        return report.read_bytes()
    except OSError as exc:
        raise ScannerReportError(f"cannot read scanner report {report}: {exc.strerror}") from exc


def load_gitleaks(report: Path, project: Path) -> list[ScannerResult]:
    """A gitleaks JSON report (`gitleaks detect --report-format json`): one
    array of findings. Relative `File` paths resolve against the project."""
    try:
        findings = msgspec.json.decode(_read(report), type=list[_GitleaksFinding])
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ScannerReportError(f"not a gitleaks JSON report: {report}: {exc}") from exc
    return [
        ScannerResult(
            tool="gitleaks", rule=f.RuleID, path=_resolve(f.File, project),
            line=f.StartLine or None, commit=f.Commit or None, value=_gitleaks_secret(f.Secret),
        )
        for f in findings
    ]


def load_trufflehog(report: Path, project: Path) -> list[ScannerResult]:
    """A trufflehog JSON report (`trufflehog filesystem|git --json`): one
    result per line."""
    decoder = msgspec.json.Decoder(_TrufflehogResult)
    results: list[_TrufflehogResult] = []
    for number, line in enumerate(_read(report).splitlines(), start=1):
        if line.strip():
            try:
                results.append(decoder.decode(line))
            except (msgspec.DecodeError, msgspec.ValidationError) as exc:
                raise ScannerReportError(
                    f"not a trufflehog JSON report: {report}: line {number}: {exc}"
                ) from exc
    out: list[ScannerResult] = []
    for r in results:
        where = r.SourceMetadata.Data.Filesystem or r.SourceMetadata.Data.Git
        out.append(ScannerResult(
            tool="trufflehog", rule=r.DetectorName,
            path=_resolve(where.file, project) if where else None,
            line=(where.line or None) if where else None,
            commit=(where.commit or None) if where else None,
            value=(r.Raw or r.RawV2) or None,
        ))
    return out
