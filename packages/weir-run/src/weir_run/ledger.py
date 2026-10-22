"""The canary ledger (`canary-ledger/1`, docs/canary.md "The ledger").

The ledger is the one place canary values are written. It is created with
mode 0600 in the run's private temporary directory, written in whole lines
under a lock (the mock appends from its request threads), and deleted when
the run ends. The same object answers the two questions the runner asks of
values while it runs: which placements does this byte string hold a needle
of, and what does this text look like with every needle replaced.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from weir_run.needles import needles
from weir_run.shapes import ByteSource, generate, overlaps

SCHEMA = "canary-ledger/1"
KINDS = ("env", "code", "file", "mock-oauth")
EVIDENCE = ("request", "minted", "egress", "tool_call")
FLOW_STATUSES = ("ok", "failed", "timeout", "skipped")
DIRECT_PROTOCOLS = ("tcp", "udp", "dns")
MIN_VALUE_LENGTH = 16

_ID = re.compile(r"[A-Za-z0-9._:#/-]{1,128}")
_TARGET = re.compile(r"[A-Za-z0-9._:\[\]-]{1,260}")


class LedgerError(Exception):
    """A record would break the ledger contract. Never carries a value."""


@dataclass(frozen=True)
class Placement:
    id: str
    kind: str
    value: str = field(repr=False)
    required: bool = False
    providers: tuple[str, ...] = ()
    provider_host: str | None = None


class Ledger:
    def __init__(self, path: Path, source: ByteSource, reserved_ids: Iterable[str] = ()) -> None:
        self.path = path
        self.source = source
        self._lock = threading.Lock()
        self._placements: dict[str, Placement] = {}
        # Every id that is or will be printed. A new value must share no
        # 6-character run with any of them; the stems of ids the mock mints
        # later (`runtime.oauth.access_token`, `unexpected.<ep>.<field>`)
        # are reserved up front for the same reason.
        self._ids: list[str] = list(reserved_ids)
        self._ids_by_type: dict[str, set[str]] = {}
        self._exercised: set[tuple[str, str]] = set()
        self._counters: dict[str, int] = {}
        self._network = False
        self._needles: list[tuple[bytes, str]] = []
        self._pattern: re.Pattern[bytes] | None = None
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        self._file = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        self._write({"schema": SCHEMA})

    # -- writing -------------------------------------------------------

    def _write(self, record: dict[str, object]) -> None:
        self._file.write(json.dumps(record, ensure_ascii=False, separators=(", ", ": ")) + "\n")
        self._file.flush()

    def _claim_id(self, record_type: str, record_id: str) -> None:
        if not _ID.fullmatch(record_id):
            raise LedgerError(
                f"{record_type} id breaks the id rule (1 to 128 of [A-Za-z0-9._:#/-])"
            )
        taken = self._ids_by_type.setdefault(record_type, set())
        if record_id in taken:
            raise LedgerError(f"{record_type} id {record_id} is not unique")
        if any(overlaps(p.value, record_id) for p in self._placements.values()):
            raise LedgerError(f"{record_type} id {record_id} holds a run of a ledger value")
        taken.add(record_id)
        self._ids.append(record_id)

    def plant(
        self,
        placement_id: str,
        kind: str,
        make: Callable[[], str],
        required: bool = False,
        providers: Sequence[str] = (),
        provider_host: str | None = None,
    ) -> Placement:
        """Draw a fresh value with `make` and add it as a placement, with
        its own provider (docs/canary.md, "A placement's own provider")."""
        with self._lock:
            if kind not in KINDS:
                raise LedgerError(f"unknown placement kind {kind}")
            value = generate(
                make, (p.value for p in self._placements.values()), [*self._ids, placement_id]
            )
            if len(value) < MIN_VALUE_LENGTH:
                raise LedgerError(f"placement {placement_id}: value shorter than 16 characters")
            self._claim_id("placement", placement_id)
            placement = Placement(
                placement_id, kind, value, required, tuple(providers), provider_host
            )
            self._placements[placement_id] = placement
            record: dict[str, object] = {
                "type": "placement",
                "id": placement_id,
                "kind": kind,
                "value": value,
            }
            if required:
                record["required"] = True
            if providers:
                record["providers"] = list(providers)
            if provider_host is not None:
                record["provider_host"] = provider_host
            self._write(record)
            self._needles += [(n, placement_id) for _, n in needles(value)]
            self._pattern = None
            return placement

    def mint(self, token: str, make: Callable[[], str], providers: Sequence[str]) -> Placement:
        """A credential the mock's OAuth endpoints issue: ledgered as a
        `mock-oauth` placement with `minted` evidence before it is handed out.
        Its providers are the OAuth endpoints and the program's own APIs."""
        with self._lock:
            n = self._counters.get(token, 0) + 1
            self._counters[token] = n
        placement = self.plant(f"runtime.oauth.{token}#{n}", "mock-oauth", make, False, providers)
        self.exercised(placement.id, "minted")
        return placement

    def exercised(self, placement_id: str, evidence: str) -> None:
        with self._lock:
            if evidence not in EVIDENCE:
                raise LedgerError(f"unknown evidence {evidence}")
            if placement_id not in self._placements:
                raise LedgerError(f"exercised names no placement: {placement_id}")
            if (placement_id, evidence) in self._exercised:
                return
            self._exercised.add((placement_id, evidence))
            self._write({"type": "exercised", "placement": placement_id, "evidence": evidence})

    def unexpected(self, endpoint: str, field_name: str) -> str:
        """Record a credential field that held no needle. Never the value."""
        with self._lock:
            stem = f"unexpected.{endpoint}.{field_name}"
            n = self._counters.get(stem, 0) + 1
            self._counters[stem] = n
            record_id = f"{stem}#{n}"
            self._claim_id("unexpected", record_id)
            self._write({"type": "unexpected", "id": record_id})
            return record_id

    def flow(self, flow_id: str, status: str, *, telemetry: bool = True) -> None:
        """One flow's status; telemetry False for a flow whose program has
        its telemetry off, so an empty telemetry capture says nothing."""
        with self._lock:
            if status not in FLOW_STATUSES:
                raise LedgerError(f"unknown flow status {status}")
            self._claim_id("flow", flow_id)
            record: dict[str, object] = {"type": "flow", "id": flow_id, "status": status}
            if not telemetry:
                record["telemetry"] = False
            self._write(record)

    def network(self, *, isolated: bool, required: bool) -> None:
        """Whether the flows ran isolated, and whether the run requires it."""
        with self._lock:
            if self._network:
                raise LedgerError("the network record is already written")
            self._network = True
            record: dict[str, object] = {"type": "network", "isolated": isolated}
            if required:
                record["required"] = True
            self._write(record)

    def direct(self, flow_id: str, protocol: str, target: str, attempts: int) -> None:
        """A direct connection attempt the isolated network blocked."""
        with self._lock:
            if protocol not in DIRECT_PROTOCOLS or not _TARGET.fullmatch(target) or attempts < 1:
                raise LedgerError(f"flow {flow_id}: not a direct connection record")
            self._write(
                {
                    "type": "direct",
                    "flow": flow_id,
                    "protocol": protocol,
                    "target": target,
                    "attempts": attempts,
                }
            )

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.close()

    # -- reading -------------------------------------------------------

    @property
    def placements(self) -> list[Placement]:
        with self._lock:
            return list(self._placements.values())

    def provider_endpoints(self, host: str) -> list[str]:
        """The providers of every placement whose provider host is host,
        matched without regard to letter case, in ledger order."""
        endpoints: list[str] = []
        for p in self.placements:
            if p.provider_host is not None and p.provider_host.lower() == host.lower():
                endpoints += [e for e in p.providers if e not in endpoints]
        return endpoints

    def value(self, placement_id: str) -> str:
        return self._placements[placement_id].value

    def holders(self, data: bytes) -> list[str]:
        """The placements whose needles data holds, sorted."""
        with self._lock:
            return sorted({pid for needle, pid in self._needles if needle in data})

    def redact(self, data: bytes) -> bytes:
        """data with every needle replaced by `<canary:PLACEMENT-ID>`."""
        with self._lock:
            if not self._needles:
                return data
            by_needle = dict(self._needles)
            if self._pattern is None:
                # Longest first, so a needle never leaves part of a longer one.
                ordered = sorted(by_needle, key=len, reverse=True)
                self._pattern = re.compile(b"|".join(re.escape(n) for n in ordered))
            pattern = self._pattern
        return pattern.sub(lambda m: f"<canary:{by_needle[m.group(0)]}>".encode(), data)

    def withheld(self, text: str) -> bool:
        """Would the judge's printing rule withhold text? (any needle, or any
        6-character run of any ledger value)"""
        data = text.encode("utf-8", "surrogateescape")
        if self.holders(data):
            return True
        return any(overlaps(p.value, text) for p in self.placements)
