"""Synthetic fixtures for the canary judge tests (docs/canary.md).

Fake data only. Every value here is built from a seed by hashing, so it is
prefix-free, has no real provider shape, and two seeds give two unrelated
values: the determinism test plants fresh values in the same places. No
fixture is built from a capture of a real framework run.

Every encoding a test places is built here from the contract's definitions
with the standard library (json, urllib.parse, base64, bytes.hex), never
with the judge's own forms module, so a test cannot pass by agreeing with a
wrong encoder.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from click.testing import CliRunner

from weir.cli.main import main

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# docs/canary.md "Canary values": a value never holds these words.
_DEMOTED = ("FAKE", "TEST", "EXAMPLE", "DEMO", "PLACEHOLDER", "REDACTED")
RUN = 6  # the contract's "run of 6 or more consecutive characters"


def fake_value(seed: str, length: int = 24) -> str:
    """A prefix-free alphanumeric fake value derived from `seed`."""
    digest = hashlib.sha256(seed.encode()).digest() * 4
    value = "".join(_ALPHABET[b % len(_ALPHABET)] for b in digest[:length])
    assert not any(word in value.upper() for word in _DEMOTED), seed
    return value


def write(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text with `\n` line ends on every platform: the judge counts
    lines and bytes, so a Windows newline translation would move both."""
    path.write_bytes(text.encode(encoding))


def write_ledger(path: Path, records: Iterable[dict[str, object]]) -> Path:
    lines = [{"schema": "canary-ledger/1"}, *records]
    write(path, "".join(json.dumps(r) + "\n" for r in lines), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def placement(pid: str, value: str, kind: str = "env", **extra: object) -> dict[str, object]:
    return {"type": "placement", "id": pid, "kind": kind, "value": value, **extra}


def kv(key: str, value: str) -> dict[str, object]:
    return {"key": key, "value": {"stringValue": value}}


def span(name: str, span_id: str = "0123456789abcdef", **fields: object) -> dict[str, object]:
    return {"name": name, "spanId": span_id, "traceId": "0" * 32, **fields}


def traces(*spans: dict[str, object], resource: Sequence[dict[str, object]] = ()) -> str:
    return json.dumps(
        {
            "resourceSpans": [
                {
                    "resource": {"attributes": list(resource)},
                    "scopeSpans": [{"scope": {"name": "fixture"}, "spans": list(spans)}],
                }
            ]
        }
    )


def logs(*records: dict[str, object]) -> str:
    return json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]})


def metrics(*metric_list: dict[str, object]) -> str:
    return json.dumps({"resourceMetrics": [{"scopeMetrics": [{"metrics": list(metric_list)}]}]})


def gauge(name: str, points: int = 1, **fields: object) -> dict[str, object]:
    return {
        "name": name,
        "gauge": {"dataPoints": [{"asDouble": 1.0} for _ in range(points)]},
        **fields,
    }


# docs/canary.md, "Runtime values": a credential field of every request.
AUTH_HEADERS = (("header", "authorization"), ("header", "proxy-authorization"))


def request(
    outcome: str = "served",
    endpoint: str | None = "model",
    *,
    host: str = "127.0.0.1",
    port: int = 4318,
    method: str = "POST",
    path: str | None = "/v1/chat/completions",
    query: str | None = "",
    headers: Sequence[tuple[str, str]] = (),
    body: bytes | None = b"",
    unread: str | None = None,
    credential_fields: Sequence[tuple[str, str]] = AUTH_HEADERS,
) -> dict[str, object]:
    """One request record (docs/canary.md, "The request capture")."""
    if outcome == "connect":
        path = query = body = None
    return {
        "outcome": outcome,
        "endpoint": endpoint if outcome == "served" else None,
        "host": host,
        "port": port,
        "method": "CONNECT" if outcome == "connect" else method,
        "path": path,
        "query": query,
        "headers": [list(h) for h in headers],
        "body": None if body is None else base64.b64encode(body).decode(),
        "unread": unread,
        "credential_fields": [list(f) for f in credential_fields],
    }


def write_requests(path: Path, records: Iterable[dict[str, object]]) -> Path:
    lines = [{"schema": "canary-requests/1"}, *records]
    write(path, "".join(json.dumps(r) + "\n" for r in lines))
    return path


# --- the encoded forms, built from the contract's definitions -------------


def json_content(value: str, *, ensure_ascii: bool = True) -> str:
    """The value as JSON string content (stdlib json, `/` kept)."""
    return json.dumps(value, ensure_ascii=ensure_ascii)[1:-1]


def base64_embedded(value: str, offset: int, *, urlsafe: bool = False) -> str:
    """The value inside a larger plaintext at byte `offset` mod 3, encoded
    whole: what an HTTP Basic value or a JWT segment carries."""
    plain = b"u" * offset + b":" * 3 + value.encode() + b"!tail"
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encode(plain).decode().rstrip("=")


# --- running the judge ----------------------------------------------------


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()

    @property
    def report(self) -> dict[str, object]:
        return json.loads(self.stdout)


def judge(
    ledger: Path,
    otlp: Sequence[Path | str],
    swept: Sequence[Path | str] = (),
    *,
    as_json: bool = False,
    requests: Sequence[Path | str] = (),
) -> Run:
    args = ["canary", "judge", "--ledger", str(ledger)]
    for path in otlp:
        args += ["--otlp", str(path)]
    for path in requests:
        args += ["--requests", str(path)]
    if as_json:
        args.append("--json")
    args += [str(p) for p in swept]
    result = CliRunner().invoke(main, args, catch_exceptions=False)
    return Run(result.exit_code, result.stdout, result.stderr)


def assert_value_free(text: str, values: Iterable[str]) -> None:
    """No value and no run of 6 consecutive characters of one is printed."""
    for value in values:
        for i in range(len(value) - RUN + 1):
            assert value[i : i + RUN] not in text, "output holds a fragment of a canary"


def leak_lines(run: Run) -> list[str]:
    return [line for line in run.lines if line.startswith("LEAK ")]
