"""The audit's three inventory inputs (docs/audit.md, "The three inventory
inputs"): the `weir-inventory/1` report, the `weir-inventory-store/1` store
and the fingerprint key.

The key is read, never created: a new key would match nothing and read as a
clean result. The store's key check proves the key is the one the store was
written under, and the report and the store must describe the same run.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

import msgspec

from weir.inventory._types import INVENTORY_SCHEMA, STORE_SCHEMA, Inventory, Store, ValueState
from weir.inventory.keyfile import key_file_problem

# docs/inventory.md, "The store": the version of the fingerprint input and
# algorithm this audit computes, and the key check's message. Both are
# restated rather than imported because weir.inventory.fingerprint also
# makes keys, with `secrets`, which the audit's purity contract forbids;
# tests/test_audit_units.py proves the two agree.
FINGERPRINT_VERSION = 1
KEY_CHECK_MESSAGE = b"weir-inventory-store key check"
_KEY_BYTES = 32


class AuditInputError(Exception):
    """An unusable or mismatched input: exit 2. Names the input only."""


@dataclass(frozen=True)
class Credential:
    """One credential from the report, and the fingerprint the store holds
    for its value (None: not checkable)."""

    id: str
    name: str
    source: str
    display: str
    scope: str | None
    value_state: str
    fingerprint: bytes | None


@dataclass(frozen=True)
class Inputs:
    key: bytes
    credentials: list[Credential]
    # fingerprint -> the ids of every credential with that value
    by_fingerprint: dict[bytes, tuple[str, ...]]
    # The project directory the inventory walked; None: none.
    project: str | None


def fingerprint(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, hashlib.sha256)


def key_check(key: bytes) -> str:
    return hmac.new(key, KEY_CHECK_MESSAGE, hashlib.sha256).hexdigest()


def _read(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AuditInputError(f"{label} {path}: cannot be read ({exc.strerror})") from None


def _read_key(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            problem = key_file_problem(os.fstat(handle.fileno()))
            data = handle.read()
    except OSError as exc:
        raise AuditInputError(f"key {path}: cannot be read ({exc.strerror})") from None
    if problem is not None:
        raise AuditInputError(f"key {path}: {problem}")
    try:
        key = bytes.fromhex(data.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise AuditInputError(f"key {path}: not 64 hex characters") from None
    if len(key) != _KEY_BYTES:
        raise AuditInputError(f"key {path}: not 64 hex characters")
    return key


def _decode[T](data: bytes, struct: type[T], path: Path, label: str, schema: str) -> T:
    try:
        header = msgspec.json.decode(data)
    except msgspec.DecodeError:
        raise AuditInputError(f"{label} {path}: not JSON") from None
    if not isinstance(header, dict) or header.get("schema") != schema:  # type: ignore[union-attr]
        raise AuditInputError(f"{label} {path}: not a {schema} file")
    if struct is Store and "key_check" not in header:
        raise AuditInputError(
            f"store {path}: has no key check (written before weir-scan 0.7.0); "
            "run weir inventory --store again"
        )
    try:
        return msgspec.json.decode(data, type=struct)
    except msgspec.ValidationError:
        raise AuditInputError(f"{label} {path}: does not match {schema}") from None


def load_inputs(report_path: Path, store_path: Path, key_path: Path) -> Inputs:
    report = _decode(
        _read(report_path, "inventory report"), Inventory, report_path, "inventory report",
        INVENTORY_SCHEMA,
    )
    store = _decode(_read(store_path, "store"), Store, store_path, "store", STORE_SCHEMA)
    key = _read_key(key_path)
    if not hmac.compare_digest(key_check(key), store.key_check):
        raise AuditInputError(
            f"key {key_path}: is not the key store {store_path} was written under"
        )

    stored: dict[str, bytes] = {}
    for record in store.records:
        if record.fingerprint_v != FINGERPRINT_VERSION:
            raise AuditInputError(
                f"store {store_path}: fingerprint_v {record.fingerprint_v} is not supported"
            )
        try:
            stored[record.credential_id] = bytes.fromhex(record.fingerprint)
        except ValueError:
            raise AuditInputError(f"store {store_path}: a fingerprint is not hex") from None

    credentials: list[Credential] = []
    literal: set[str] = set()
    for c in report.credentials:
        if c.value_state is ValueState.LITERAL:
            literal.add(c.id)
        credentials.append(Credential(
            id=c.id, name=c.name, source=c.source.value, display=c.location.display,
            scope=c.scope, value_state=c.value_state.value, fingerprint=stored.get(c.id),
        ))
    if literal != set(stored):
        raise AuditInputError(
            f"store {store_path} and inventory report {report_path}: not from the same"
            " weir inventory run"
        )

    by_fingerprint: dict[bytes, list[str]] = {}
    for c in credentials:
        if c.fingerprint is not None:
            by_fingerprint.setdefault(c.fingerprint, []).append(c.id)
    return Inputs(
        key=key, credentials=credentials,
        by_fingerprint={fp: tuple(sorted(ids)) for fp, ids in by_fingerprint.items()},
        project=report.inputs.project,
    )
