"""The inventory core: run the four sources, then split what they found into
a value-free report and a store of keyed fingerprints plus offsets. Values
exist only while the run fingerprints them; none is returned.

Every input is explicit. There is no default home, project or environment:
a caller that wants the real home must say so, which is what lets a guard
refuse to touch it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import msgspec

from weir._text_safety import flatten_untrusted
from weir.inventory._scan import (
    Hit,
    Unreadable,
    absolute,
    byte_spans,
    display_path,
    find_all,
    line_of,
    posix,
    read_text,
)
from weir.inventory._types import (
    INVENTORY_SCHEMA,
    STORE_SCHEMA,
    Counts,
    Credential,
    EnvSource,
    EnvVarName,
    GitIgnoredFile,
    Inputs,
    Inventory,
    Location,
    LocationKind,
    NotScanned,
    NotScannedReason,
    PartlyRead,
    Reason,
    Source,
    Store,
    StoredRecord,
    ValueState,
)
from weir.inventory.classify import EnvVerdict, looks_secret_shaped
from weir.inventory.environment import (
    EnvEntry,
    judge,
    parse_env_file,
    parse_startup_file,
    process_env_entries,
    to_hit,
)
from weir.inventory.fingerprint import (
    FINGERPRINT_VERSION,
    FingerprintKeyError,
    fingerprint,
    load_or_create_key,
)
from weir.inventory.gitignore import IGNORED_ROUTES
from weir.inventory.locations import (
    LOCATION_LIST_VERSION,
    STANDARD_LOCATIONS,
    STARTUP_FILES,
    candidate_paths,
    parse_location,
)
from weir.inventory.project import (
    MAX_PROJECT_FILE_BYTES,
    assignment_values,
    merge_hits,
    scan_shapes,
    scan_text,
    walk_project,
)
from weir.inventory.reach_map import MapError, load_map, resolve_entry
from weir.inventory.scanners import (
    ScannerReportError,
    ScannerResult,
    load_gitleaks,
    load_trufflehog,
)

_SOURCE_ORDER = {s: i for i, s in enumerate(Source)}
_WITHHELD = "[withheld: credential-shaped]"
_LAUNCH_ENV = "launch env"


class InventoryInputError(Exception):
    """An input the caller named cannot be used: a missing home or project,
    an unreadable env file, a malformed scanner report or map, a bad key.
    The message never contains a value from any input."""


@dataclass(frozen=True, kw_only=True)
class InventoryInputs:
    home: Path
    project: Path
    # The fingerprint key file; created (0600) when missing.
    key_path: Path
    # The launch environment: an env file, or a mapping the caller read
    # from its own process. At most one. Neither: startup files only.
    env_file: Path | None = None
    process_env: Mapping[str, str] | None = None
    gitleaks_reports: Sequence[Path] = ()
    trufflehog_reports: Sequence[Path] = ()


@dataclass(frozen=True)
class InventoryResult:
    report: Inventory
    store: Store


def default_key_path(home: Path) -> Path:
    return home / ".weir" / "fingerprint.key"


@dataclass
class _Found:
    source: Source
    hit: Hit
    location: Location
    git_ignored: bool = False
    byte_offsets: list[tuple[int, int]] = field(default_factory=list[tuple[int, int]])


def _launch_location(path: Path | None, line: int | None) -> Location:
    return Location(
        kind=LocationKind.LAUNCH_ENV, display=_LAUNCH_ENV,
        path=posix(path) if path is not None else None, line=line,
    )


@dataclass
class _Collector:
    home: Path
    project: Path
    found: list[_Found] = field(default_factory=list[_Found])
    not_scanned: list[NotScanned] = field(default_factory=list[NotScanned])
    not_fully_read: list[PartlyRead] = field(default_factory=list[PartlyRead])
    env_unknown: list[EnvVarName] = field(default_factory=list[EnvVarName])
    env_not_secret: int = 0
    env_withheld: int = 0
    # Files sources 1 and 3 already read: the project walk skips them so a
    # project that is (or contains) the home does not report them twice.
    claimed: set[Path] = field(default_factory=set[Path])

    def display(self, path: Path) -> str:
        return display_path(path, home=self.home, project=self.project)

    def file_location(self, path: Path, line: int | None, commit: str | None = None) -> Location:
        return Location(
            kind=LocationKind.FILE, display=self.display(path), path=posix(path), line=line,
            commit=commit,
        )

    def add(
        self, source: Source, hits: list[Hit], *, path: Path | None, text: str | None,
        git_ignored: bool = False, launch_env: bool = False,
    ) -> None:
        for hit in hits:
            if launch_env:
                location = _launch_location(path, hit.line)
            elif path is not None:
                location = self.file_location(path, hit.line, hit.commit)
            else:
                tool = hit.name.split(":")[0]
                location = Location(kind=LocationKind.FILE, display=f"{tool} result")
            offsets = byte_spans(text, hit.spans) if text is not None else []
            self.found.append(_Found(source, hit, location, git_ignored, offsets))

    def skip(self, path: Path, reason: NotScannedReason) -> None:
        self.not_scanned.append(
            NotScanned(display=self.display(path), reason=reason, path=posix(path))
        )


def _whole_file_hit(location_id: str, reason: Reason, name: str) -> Hit:
    """A credential file as a whole, value not extracted; named after the
    file unless a person named it in the map."""
    return Hit(
        name=name, reason=reason, detectors={location_id}, value=None, spans=[], line=None,
    )


def _standard_locations(c: _Collector, env: Mapping[str, str]) -> None:
    for location in STANDARD_LOCATIONS:
        for path in candidate_paths(location, c.home, env):
            if not path.is_file():
                continue
            c.claimed.add(path)
            detector = f"location:{location.id}"
            whole_file = [_whole_file_hit(detector, Reason.LOCATION, path.name)]
            if location.format == "opaque":
                c.add(Source.STANDARD_LOCATION, whole_file, path=path, text=None)
                continue
            try:
                text = read_text(path)
            except Unreadable as exc:
                # A credential file weir cannot read is still a credential
                # file the agent may be able to read: report both facts.
                c.skip(path, exc.reason)
                c.add(Source.STANDARD_LOCATION, whole_file, path=path, text=None)
                continue
            try:
                hits = parse_location(location, text)
            except ValueError:
                # Never surface the parser's message: it can quote the file.
                c.skip(path, NotScannedReason.UNDECODABLE)
                hits = whole_file
            c.add(Source.STANDARD_LOCATION, hits, path=path, text=text)


def _launch_env_entries(inputs: InventoryInputs) -> tuple[list[EnvEntry], str | None, EnvSource]:
    if inputs.env_file is not None and inputs.process_env is not None:
        raise InventoryInputError(
            "give the launch environment as an env file or the process, not both"
        )
    if inputs.env_file is not None:
        try:
            text = inputs.env_file.read_bytes().decode("utf-8", "surrogateescape")
        except OSError as exc:
            raise InventoryInputError(
                f"cannot read env file {inputs.env_file}: {exc.strerror}"
            ) from exc
        return parse_env_file(text), text, EnvSource.FILE
    if inputs.process_env is not None:
        return process_env_entries(inputs.process_env), None, EnvSource.PROCESS
    return [], None, EnvSource.NONE


def _judge_env(
    c: _Collector, entries: list[EnvEntry], *, path: Path | None, text: str | None,
    detector: str, location: Location,
) -> None:
    launch_env = location.kind is LocationKind.LAUNCH_ENV
    for entry in entries:
        judged = judge(entry)
        if not entry.exported and judged.verdict is not EnvVerdict.SECRET:
            # Not in the launch environment: only a secret in the file matters.
            continue
        if judged.verdict is EnvVerdict.SECRET:
            c.add(
                Source.ENVIRONMENT, [to_hit(judged, detector)], path=path, text=text,
                launch_env=launch_env,
            )
        elif looks_secret_shaped(entry.name):
            c.env_withheld += 1
        elif judged.verdict is EnvVerdict.UNKNOWN:
            where = msgspec.structs.replace(location, line=entry.line)
            c.env_unknown.append(EnvVarName(name=entry.name, location=where))
        else:
            c.env_not_secret += 1


def _environment(
    c: _Collector, entries: list[EnvEntry], env_text: str | None, env_file: Path | None
) -> None:
    _judge_env(
        c, entries, path=env_file, text=env_text, detector="launch_env",
        location=_launch_location(env_file, None),
    )
    for rel in STARTUP_FILES:
        path = c.home / rel
        if not path.is_file():
            continue
        c.claimed.add(path)
        try:
            text = read_text(path)
        except Unreadable as exc:
            c.skip(path, exc.reason)
            continue
        parsed = parse_startup_file(text)
        _judge_env(
            c, parsed.entries, path=path, text=text, detector="startup_file",
            location=c.file_location(path, None),
        )
        c.not_fully_read.extend(
            PartlyRead(display=c.display(path), path=posix(path), line=line, reason=why)
            for line, why in parsed.not_fully_read
        )
        c.add(Source.ENVIRONMENT, _unread_shapes(text, parsed.unread), path=path, text=text)


def _unread_shapes(text: str, spans: list[tuple[int, int]]) -> list[Hit]:
    """Credential shapes inside the spans of a startup file it could not
    fully read, at their own lines in the file."""
    hits: list[Hit] = []
    for start, end in spans:
        for hit in scan_shapes(text[start:end]):
            hit.spans = [(s + start, e + start) for s, e in hit.spans]
            hit.line = line_of(text, hit.spans[0][0])
            hits.append(hit)
    return hits


def _scanner_hit(result: ScannerResult, text: str | None) -> Hit:
    spans = find_all(text, result.value) if text is not None and result.value else []
    line = result.line
    if line is None and spans and text is not None:
        line = line_of(text, spans[0][0])
    # A value the file it names does not hold is not that file's credential
    # value (a redacted or since-changed report): name the finding, no value.
    value = result.value if text is None or spans else None
    return Hit(
        name=f"{result.tool}:{result.rule}", reason=Reason.SCANNER,
        detectors={f"{result.tool}:{result.rule}"}, value=value, spans=spans, line=line,
        commit=result.commit, name_rank=35, missing=ValueState.NOT_IN_FILE,
    )


def _project(c: _Collector, results: list[ScannerResult]) -> dict[Path, bool]:
    """Returns {file: git-ignored} for every project file walked. An env file
    inside the project is a project file too, reported here as well as by
    the launch environment."""
    files, skipped = walk_project(c.home, c.project)
    for s in skipped:
        c.skip(s.path, s.reason)
    by_path: dict[Path, list[ScannerResult]] = {}
    elsewhere: list[ScannerResult] = []
    for result in results:
        if result.path is not None and result.commit is None:
            by_path.setdefault(result.path, []).append(result)
        else:
            elsewhere.append(result)

    for file in files:
        path = file.path
        try:
            text = read_text(path, max_bytes=MAX_PROJECT_FILE_BYTES)
        except Unreadable as exc:
            c.skip(path, exc.reason)
            continue
        hits = [] if path in c.claimed else scan_text(text, rel=file.rel)
        scanner = [_scanner_hit(r, text) for r in by_path.pop(path, [])]
        located = [h for h in scanner if h.spans]
        if located:
            hits = merge_hits(hits + located)
        hits += [h for h in scanner if not h.spans]
        c.add(Source.PROJECT_SCAN, hits, path=path, text=text, git_ignored=file.git_ignored)

    # Scanner results the walk did not reach: a file outside the project, a
    # file that has since moved, a commit in git history, or no file at all.
    for path in sorted(by_path):
        text: str | None = None
        if path.is_file():
            try:
                text = read_text(path)
            except Unreadable as exc:
                c.skip(path, exc.reason)
        else:
            c.skip(path, NotScannedReason.MISSING)
        hits = [_scanner_hit(r, text) for r in by_path[path]]
        c.add(Source.PROJECT_SCAN, hits, path=path, text=text)
    for result in elsewhere:
        c.add(Source.PROJECT_SCAN, [_scanner_hit(result, None)], path=result.path, text=None)
    return {f.path: f.git_ignored for f in files}


def _map(c: _Collector, ignored: dict[Path, bool]) -> tuple[str | None, list[str]]:
    try:
        loaded = load_map(c.project)
    except MapError as exc:
        raise InventoryInputError(str(exc)) from exc
    if loaded is None:
        return None, []
    map_path, reach = loaded
    for entry in reach.credentials:
        path = absolute(resolve_entry(entry.path, home=c.home, project=c.project))
        git_ignored = ignored.get(path, False)
        if not path.is_file():
            c.skip(path, NotScannedReason.MISSING)
            continue
        if entry.field is None:
            hit = _whole_file_hit("map", Reason.MAP, entry.name or path.name)
            c.add(Source.MAP, [hit], path=path, text=None, git_ignored=git_ignored)
            continue
        try:
            text = read_text(path)
        except Unreadable as exc:
            c.skip(path, exc.reason)
            c.add(Source.MAP, [_whole_file_hit("map", Reason.MAP, entry.name or entry.field)],
                  path=path, text=None, git_ignored=git_ignored)
            continue
        hits = [
            Hit(name=entry.name or entry.field, reason=Reason.MAP, detectors={"map"},
                value=h.value, spans=h.spans, line=h.line)
            for h in assignment_values(text, entry.field)
        ] or [_whole_file_hit("map", Reason.MAP, entry.name or entry.field)]
        c.add(Source.MAP, hits, path=path, text=text, git_ignored=git_ignored)
    return posix(map_path), list(reach.env.fine)


def _safe_label(text: str | None) -> str | None:
    if text is None:
        return None
    flat = flatten_untrusted(text)
    return _WITHHELD if looks_secret_shaped(flat) else flat


def _credential_id(f: _Found, name: str, scope: str | None) -> str:
    """Base32 of a digest over the record's identity as displayed (`~/...`,
    `./...`), so the id does not change when the same home is inventoried
    from another absolute path."""
    identity = "\0".join([
        f.source.value, f.location.display, str(f.location.line),
        name, scope or "", f.location.commit or "",
    ])
    digest = hashlib.sha256(identity.encode("utf-8", "surrogateescape")).digest()
    return base64.b32encode(digest).decode("ascii").lower()[:16]


def take_inventory(inputs: InventoryInputs) -> InventoryResult:
    home = absolute(inputs.home)
    project = absolute(inputs.project)
    for label, directory in (("home", home), ("project", project)):
        if not directory.is_dir():
            raise InventoryInputError(f"{label} directory does not exist: {directory}")
    try:
        key = load_or_create_key(inputs.key_path)
    except FingerprintKeyError as exc:
        raise InventoryInputError(str(exc)) from exc

    entries, env_text, env_source = _launch_env_entries(inputs)
    env_map = {e.name: e.value for e in entries if e.value is not None}
    results: list[ScannerResult] = []
    try:
        for report in inputs.gitleaks_reports:
            results.extend(load_gitleaks(report, project))
        for report in inputs.trufflehog_reports:
            results.extend(load_trufflehog(report, project))
    except ScannerReportError as exc:
        raise InventoryInputError(str(exc)) from exc

    c = _Collector(home, project)
    env_file = absolute(inputs.env_file) if inputs.env_file is not None else None
    _standard_locations(c, env_map)
    _environment(c, entries, env_text, env_file)
    ignored = _project(c, results)
    map_file, fine = _map(c, ignored)

    return _assemble(
        c, key, set(fine),
        Inputs(
            home=posix(home), project=posix(project), env_source=env_source,
            env_file=posix(env_file) if env_file is not None else None,
            gitleaks_reports=[posix(absolute(p)) for p in inputs.gitleaks_reports],
            trufflehog_reports=[posix(absolute(p)) for p in inputs.trufflehog_reports],
            map_file=map_file, location_list_version=LOCATION_LIST_VERSION,
        ),
    )


def _assemble(c: _Collector, key: bytes, fine: set[str], inputs: Inputs) -> InventoryResult:
    rows: list[tuple[Credential, _Found]] = []
    for f in c.found:
        name = _safe_label(f.hit.name) or "?"
        scope = _safe_label(f.hit.scope)
        state = ValueState.LITERAL if f.hit.value is not None else f.hit.missing
        cred = Credential(
            id="", name=name, source=f.source, reason=f.hit.reason, location=f.location,
            value_state=state, detectors=sorted(f.hit.detectors), same_value_as=[],
            scope=scope, git_ignored=f.git_ignored,
        )
        rows.append((cred, f))
    rows.sort(key=lambda r: (
        _SOURCE_ORDER[r[0].source], r[0].location.display, r[0].location.line or 0,
        r[0].name, r[0].scope or "", r[0].location.commit or "",
    ))

    credentials: list[Credential] = []
    records: list[StoredRecord] = []
    seen: dict[str, int] = {}
    for cred, f in rows:
        base = _credential_id(f, cred.name, cred.scope)
        seen[base] = seen.get(base, 0) + 1
        cid = base if seen[base] == 1 else f"{base}-{seen[base]}"
        credentials.append(msgspec.structs.replace(cred, id=cid))
        if f.hit.value is not None:
            records.append(StoredRecord(
                credential_id=cid, fingerprint=fingerprint(key, f.hit.value),
                fingerprint_v=FINGERPRINT_VERSION, path=f.location.path,
                offsets=f.byte_offsets,
            ))
    by_value: dict[str, list[str]] = {}
    for record in records:
        by_value.setdefault(record.fingerprint, []).append(record.credential_id)
    same = {cid: ids for ids in by_value.values() for cid in ids}
    credentials = [
        msgspec.structs.replace(
            cred, same_value_as=sorted(i for i in same.get(cred.id, []) if i != cred.id),
        )
        for cred in credentials
    ]

    unknown_sorted = sorted(
        c.env_unknown, key=lambda e: (e.name, e.location.display, e.location.line or 0)
    )
    env_unknown = [e for e in unknown_sorted if e.name not in fine]
    env_fine = [e for e in unknown_sorted if e.name in fine]
    ignored_files: dict[str, GitIgnoredFile] = {}
    for cred in credentials:
        if cred.git_ignored and cred.location.path is not None:
            ignored_files.setdefault(cred.location.path, GitIgnoredFile(
                display=cred.location.display, path=cred.location.path,
                routes=list(IGNORED_ROUTES),
            ))
    not_scanned = sorted(
        {(n.display, n.reason): n for n in c.not_scanned}.values(),
        key=lambda n: (n.display, n.reason.value),
    )
    not_fully_read = sorted(
        c.not_fully_read, key=lambda p: (p.display, p.line, p.reason.value)
    )
    by_source = {s: sum(1 for cr in credentials if cr.source is s) for s in Source}
    report = Inventory(
        schema=INVENTORY_SCHEMA,
        inputs=inputs,
        counts=Counts(
            credentials=len(credentials),
            distinct_values=len(by_value),
            standard_location=by_source[Source.STANDARD_LOCATION],
            project_scan=by_source[Source.PROJECT_SCAN],
            environment=by_source[Source.ENVIRONMENT],
            map=by_source[Source.MAP],
            env_not_secret=c.env_not_secret,
            env_withheld=c.env_withheld,
            env_unknown=len(env_unknown),
            env_fine=len(env_fine),
            git_ignored_files=len(ignored_files),
            not_scanned=len(not_scanned),
            not_fully_read=len(not_fully_read),
        ),
        credentials=credentials,
        env_unknown=env_unknown,
        env_fine=env_fine,
        git_ignored=sorted(ignored_files.values(), key=lambda g: g.display),
        not_scanned=not_scanned,
        not_fully_read=not_fully_read,
    )
    store = Store(
        schema=STORE_SCHEMA, records=sorted(records, key=lambda r: r.credential_id)
    )
    return InventoryResult(report=report, store=store)


def encode_report(report: Inventory) -> bytes:
    """Deterministic, indented JSON: the `weir inventory --json` bytes."""
    return msgspec.json.format(msgspec.json.encode(report), indent=2) + b"\n"


def encode_store(store: Store) -> bytes:
    return msgspec.json.format(msgspec.json.encode(store), indent=2) + b"\n"


def write_private(path: Path, data: bytes) -> None:
    """Write atomically, readable by the owner only (0600 on POSIX)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
