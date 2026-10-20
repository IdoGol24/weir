"""Read and validate a canary ledger (canary-ledger/1, docs/canary.md).

The ledger is strict and is never read in part: a ledger the judge cannot
read in full would leave a value unsearched. Every rejection names the
ledger and the line number, never content: a message is built only from
this module's own words and the contract's field names, because an unknown
field name or a bad enum value read from the file could be a canary.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable
from typing import cast

import msgspec

from weir.canary._types import (
    RECORD_TYPES,
    Exercised,
    Flow,
    Ledger,
    LedgerHeader,
    LedgerRecord,
    Placement,
    Unexpected,
)

_ID = re.compile(r"[A-Za-z0-9._:#/-]{1,128}", re.ASCII)
_RUN = 8  # an id may hold no run of this many consecutive characters of a value
_BY_TAG: dict[str, type[LedgerRecord]] = {
    str(cls.__struct_config__.tag): cls for cls in RECORD_TYPES
}


class LedgerError(Exception):
    """An unusable ledger: exit 2. The message never holds ledger content."""


class _DuplicateKey(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # A repeated key would let a parser keep one value and silently drop the
    # other, leaving it unsearched.
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey
        obj[key] = value
    return obj


def _reject_constant(_name: str) -> object:
    raise ValueError("not JSON")


def _decode_object(line: bytes) -> dict[str, object] | None:
    try:
        obj: object = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return cast("dict[str, object]", obj) if isinstance(obj, dict) else None


def _field_of(exc: msgspec.ValidationError, cls: type[LedgerRecord]) -> str | None:
    """The contract field a validation error is about, if msgspec names one.

    Only a name that is one of the struct's own fields is returned, so a
    message can quote it without quoting the file.
    """
    message = str(exc)
    fields = {f.name for f in msgspec.structs.fields(cls)}
    match = re.search(r"`\$\.([A-Za-z_]+)`$", message) or re.search(
        r"^Object missing required field `([A-Za-z_]+)`$", message
    )
    if match and match.group(1) in fields:
        return match.group(1)
    return None


def _record(obj: dict[str, object], where: str) -> LedgerRecord:
    tag = obj.get("type")
    cls = _BY_TAG.get(tag) if isinstance(tag, str) else None
    if cls is None:
        raise LedgerError(f"{where}: unknown record type")
    known = {"type"} | {f.encode_name for f in msgspec.structs.fields(cls)}
    if not set(obj) <= known:
        raise LedgerError(f"{where}: unknown field in a {tag} record")
    try:
        return msgspec.convert(obj, cls)
    except msgspec.ValidationError as exc:
        field = _field_of(exc, cls)
        what = f"field {field!r}" if field else "a field"
        raise LedgerError(f"{where}: {what} is missing or invalid in a {tag} record") from None


def _ids(record: LedgerRecord) -> Iterable[str]:
    if isinstance(record, Exercised):
        yield record.placement
    else:
        yield record.id


def parse_ledger(data: bytes, name: str) -> Ledger:
    """Validate ledger bytes. `name` is how errors refer to the ledger."""
    lines = data.split(b"\n")
    if lines[-1]:
        raise LedgerError(f"ledger {name} line {len(lines)}: does not end in a newline")
    lines.pop()
    if not lines:
        raise LedgerError(f"ledger {name}: the header is missing")

    header = _decode_object(lines[0])
    try:
        msgspec.convert(header, LedgerHeader)
    except msgspec.ValidationError:
        raise LedgerError(
            f"ledger {name} line 1: the header is missing or names another schema"
        ) from None

    records: list[tuple[int, LedgerRecord]] = []
    for number, line in enumerate(lines[1:], start=2):
        where = f"ledger {name} line {number}"
        obj = _decode_object(line)
        if obj is None:
            raise LedgerError(f"{where}: not a JSON object")
        records.append((number, _record(obj, where)))

    for number, record in records:
        for record_id in _ids(record):
            if not _ID.fullmatch(record_id):
                raise LedgerError(f"ledger {name} line {number}: an id breaks the id rule")

    seen_values: set[str] = set()
    for number, record in records:
        if isinstance(record, Placement):
            if record.value in seen_values:
                raise LedgerError(
                    f"ledger {name} line {number}: a value repeats an earlier placement's"
                )
            seen_values.add(record.value)

    runs = {v[i : i + _RUN] for v in seen_values for i in range(len(v) - _RUN + 1)}
    unique: dict[type, set[str]] = {}
    for number, record in records:
        for record_id in _ids(record):
            windows = (record_id[i : i + _RUN] for i in range(len(record_id) - _RUN + 1))
            if any(w in runs for w in windows):
                raise LedgerError(
                    f"ledger {name} line {number}: an id holds 8 or more consecutive"
                    " characters of a ledger value"
                )
        if isinstance(record, Exercised):
            continue
        ids = unique.setdefault(type(record), set())
        if record.id in ids:
            raise LedgerError(
                f"ledger {name} line {number}: an id repeats among {record.__struct_config__.tag}"
                " records"
            )
        ids.add(record.id)

    placement_ids = unique.get(Placement, set())
    if not placement_ids:
        raise LedgerError(f"ledger {name}: defines no placement")
    for number, record in records:
        if isinstance(record, Exercised) and record.placement not in placement_ids:
            raise LedgerError(
                f"ledger {name} line {number}: an exercised record names no defined placement"
            )

    by_type = [r for _, r in records]
    return Ledger(
        placements=tuple(r for r in by_type if isinstance(r, Placement)),
        exercised=tuple(r for r in by_type if isinstance(r, Exercised)),
        flows=tuple(r for r in by_type if isinstance(r, Flow)),
        unexpected=tuple(r for r in by_type if isinstance(r, Unexpected)),
    )


def read_ledger(path: str) -> Ledger:
    """Read and validate the ledger at `path`, in full or not at all."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise LedgerError(f"ledger {path}: not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise LedgerError(f"ledger {path}: not a regular file")
            if os.name == "posix" and info.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                raise LedgerError(
                    f"ledger {path}: readable by group or others; it must be mode 0600"
                )
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read()
        finally:
            os.close(fd)
    except OSError as exc:
        raise LedgerError(f"ledger {path}: cannot be read ({exc.strerror})") from None
    return parse_ledger(data, path)
