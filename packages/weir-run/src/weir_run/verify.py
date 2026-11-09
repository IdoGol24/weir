"""`weir-run verify`: does a credential swap or sandbox keep a planted key
out of every sink? `weir-run run`'s mock, isolation and judge, driven with
the probe through a named target (docs/verify.md)."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

import msgspec

from weir_run import evidence, probe
from weir_run.check import CheckRun, FlowOutcome
from weir_run.shapes import SHAPES, overlaps
from weir_run.spec import EndpointSpec, FlowSpec, MockSpec, PlacementSpec, RunSpec, validate

OUTBOUND = "outbound"
INJECT_HOST = "127.0.0.1"
PLACEMENT = PlacementSpec(
    "env.ANTHROPIC_API_KEY", "env", probe.VAR, "anthropic", required=True, provider="model"
)
SPEC = RunSpec((PLACEMENT,), (), MockSpec(tool_calls="none", endpoints=(EndpointSpec(OUTBOUND),)))
PROBE = Path(probe.__file__)
FLOW_TIMEOUT_SECONDS = 120.0
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.-]+)?")
# 1 is a finding, either type (docs/canary.md, "Exit codes").
EXIT_CODES = {"clean": 0, "leak": 1, "unmediated-tool-call": 1, "incomplete": 3}
# The mock's endpoints, by the sink a request to each one reaches.
ENDPOINT_SINKS = {"model": "model", "otlp": "telemetry", OUTBOUND: "outbound"}


def _listen(port: int) -> str:
    return f"127.0.0.1:{port}"


def _free_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sockets.append(socket.socket())
            sockets[-1].bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


def _iron_proxy(binary: str, port: int, workdir: Path) -> tuple[str, ...]:
    """iron-proxy runs beside the probe, which the launcher starts with the
    stand-in; it swaps the stand-in for the key in `x-api-key` on the
    inject host. The config is JSON, which YAML reads as it is."""
    tunnel, plain, tls, metrics = _free_ports(4)
    secret = {
        "source": {"type": "env", "var": probe.VAR},
        "replace": {"proxy_value": probe.STAND_IN, "match_headers": ["x-api-key"], "require": True},
        "rules": [{"host": INJECT_HOST}],
    }
    config: dict[str, Any] = {
        "dns": {"enabled": False},
        "tls": {"mode": "sni-only"},
        "proxy": {
            "tunnel_listen": _listen(tunnel),
            "http_listen": _listen(plain),
            "https_listen": _listen(tls),
            "upstream_deny_cidrs": [],
        },
        "metrics": {"listen": _listen(metrics)},
        "transforms": [
            {
                "name": "allowlist",
                "config": {"domains": ["localhost"], "cidrs": [f"{INJECT_HOST}/32"]},
            },
            {"name": "secrets", "config": {"secrets": [secret]}},
        ],
        "log": {"level": "info"},
    }
    path = workdir / "iron-proxy.yaml"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return ("{python}", str(PROBE), "--sidecar", str(tunnel), binary, "-config", str(path))


# Each target's executable, the arguments that print its version, its flow.
TARGETS: dict[str, tuple[str, tuple[str, ...], Callable[[str, int, Path], tuple[str, ...]]]] = {
    "iron-proxy": ("iron-proxy", ("version",), _iron_proxy),
}


def tool_version(command: Sequence[str]) -> str | None:
    """The first version number a command prints, or None."""
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"}
    try:
        done = subprocess.run(
            list(command), env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    found = VERSION_RE.search((done.stdout + done.stderr).decode("utf-8", "replace"))
    return found.group(0)[:64] if found and done.returncode == 0 else None


def manifest_sha256(target: str) -> str:
    """What was checked: the target, the placement, the sinks and the probe."""
    doc = {
        "schema": evidence.SCHEMA,
        "target": target,
        "placement": [PLACEMENT.id, PLACEMENT.kind, PLACEMENT.shape, PLACEMENT.provider],
        "inject_host": INJECT_HOST,
        "sinks": evidence.SINKS,
        "probe_sha256": hashlib.sha256(PROBE.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def _received(run: CheckRun, outcome: FlowOutcome) -> Counter[str]:
    """What reached each sink: requests the mock served, output streams."""
    counts: Counter[str] = Counter()
    for line in run.capture.requests.read_bytes().splitlines()[1:]:
        request: Any = json.loads(line)
        if request["outcome"] == "served" and request["endpoint"] in ENDPOINT_SINKS:
            counts[ENDPOINT_SINKS[request["endpoint"]]] += 1
    streams = (outcome.stdout, outcome.stderr)
    counts["console"] = sum(1 for p in streams if p.exists() and p.stat().st_size)
    return counts


def _fragments(run: CheckRun) -> int:
    """The captured files and requests that hold a 6-character run of the
    key's random part once every needle is replaced: a slice of the key,
    which no needle matches."""
    value = run.planted[PLACEMENT.variable][len(SHAPES[PLACEMENT.shape].prefix) :]

    def holds(data: bytes) -> bool:
        return overlaps(value, run.ledger.redact(data).decode("utf-8", "replace"))

    files = [p for p in run.capture.root.rglob("*") if p.is_file() and p != run.capture.requests]
    count = sum(holds(p.read_bytes()) for p in files)
    for line in run.capture.requests.read_bytes().splitlines()[1:]:
        request: Any = json.loads(line)
        body = base64.b64decode(request.pop("body") or "")
        count += any(holds(part) for part in (json.dumps(request).encode(), body))
    return count


def _sink_of(hit: Any) -> str:
    """The sink a judge's hit is in, by its signal, request sink or file."""
    if hit["signal"] == "requests":
        return ENDPOINT_SINKS.get(hit["sink"], "outbound")
    if hit["signal"] != "raw" or hit["file"].startswith(("capture/otlp/", "capture/swept/otlp-")):
        return "telemetry"
    return "console" if hit["file"].startswith("capture/swept/flow-") else "outbound"


def _record(
    target: str,
    run_report: Any,
    received: Counter[str],
    tools: list[dict[str, str]],
    missing: bool,
    image_digest: str | None,
    code: int,
    fragments: int,
) -> evidence.Evidence:
    """The record from the run's JSON report (canary-report/2): the
    judge's hits, placements, reasons and network, and the run's own
    unmediated tool calls; code is the run's exit code."""
    report = run_report["judge"]
    hits = Counter(_sink_of(h) for h in report["hits"])
    reasons = Counter(
        r if r in evidence.JUDGE_REASONS else "judge_other"
        for r in (str(i["reason"]) for i in report["incomplete"])
    )
    reasons.update(["target_missing"] if missing else [])
    reasons.update({"value_fragment": fragments} if fragments else {})
    sinks: list[dict[str, object]] = []
    for name in evidence.SINKS:
        verdict = evidence.sink_verdict(received[name], hits[name])
        reasons.update(["sink_not_reached"] if verdict == "not_reached" else [])
        sinks.append(
            {"name": name, "verdict": verdict, "received": received[name], "hits": hits[name]}
        )
    # docs/canary.md, "Tool calls": the mock's own groups, by reason.
    unmediated: Counter[str] = Counter()
    for entry in run_report["unmediated"]:
        unmediated[str(entry["reason"])] += int(entry["count"])
    findings = [{"type": "leak", "reason": None, "count": hits.total()}] if hits else []
    findings += [
        {"type": "unmediated-tool-call", "reason": r, "count": n}
        for r, n in sorted(unmediated.items())
    ]
    doc = {
        "schema": evidence.SCHEMA,
        "target": target,
        "tools": tools,
        "manifest_sha256": manifest_sha256(target),
        "image_digest": image_digest,
        "verdict": "incomplete",
        "findings": findings,
        "placements": [{k: p[k] for k in ("id", "state", "hits")} for p in report["placements"]],
        "sinks": sinks,
        "incomplete": [{"reason": r, "count": n} for r, n in sorted(reasons.items())],
        "network": {
            "isolated": report["network"]["isolated"],
            "direct_attempts": sum(d["attempts"] for d in report["network"]["direct"]),
        },
    }
    record = msgspec.convert(doc, evidence.Evidence)
    if evidence.derive(record) == "clean" and code != 0:
        # The record's fields and the run's own verdict disagree.
        reason = evidence.Incomplete(reason="judge_not_clean", count=1)
        record = msgspec.structs.replace(record, incomplete=[reason])
    return msgspec.structs.replace(record, verdict=evidence.derive(record))


def verify(
    target: str,
    judge: Sequence[str],
    *,
    out: TextIO,
    err: TextIO,
    target_command: str | None = None,
    image_digest: str | None = None,
) -> tuple[int, bytes]:
    """Run the probe against target, judge every sink. Returns the exit code
    (0 clean, 1 a finding: a leak or an unmediated tool call, 3 incomplete)
    and the evidence record's bytes."""
    name, version_args, flow_of = TARGETS[target]
    binary = target_command or shutil.which(name)
    version = None if binary is None else tool_version([binary, *version_args])
    tools = [{"name": "weir-run", "version": importlib.metadata.version("weir-run")}]
    for tool, found in (("weir-scan", tool_version([*judge, "--version"])), (target, version)):
        tools += [{"name": tool, "version": found}] if found else []
    if version is None:
        err.write(f"weir-run: no usable {name} found: nothing to check, so incomplete\n")
    validate(SPEC, require_flows=False)
    with tempfile.TemporaryDirectory(prefix="weir-verify-", ignore_cleanup_errors=True) as tmp:
        workdir = Path(tmp)
        run = CheckRun(SPEC, judge, validate_spec=False, require_isolation=True)
        try:
            if binary is None or version is None:
                flow = FlowSpec("verify", ("{python}",), workdir, skip="target missing")
            else:
                command = flow_of(binary, run.mock.port, workdir)
                flow = FlowSpec("verify", command, workdir, FLOW_TIMEOUT_SECONDS)
            received = _received(run, run.run_flow(flow))
            run.stop()
            fragments = _fragments(run)
            run.relay(err, withhold=True)
            verdict = run.judge(json_report=True)
            out.write(run.redacted(verdict.stdout))
            if verdict.stderr:
                err.write(run.redacted(verdict.stderr))
            report = json.loads(run.json_verdict.stdout if run.json_verdict else b"")
        finally:
            for directory in run.cleanup():
                err.write(f"weir-run: could not delete {directory}; delete it by hand\n")
    record = _record(
        target, report, received, tools, version is None, image_digest, verdict.code, fragments
    )
    for s in record.sinks:
        out.write(f"sink {s.name}: {s.verdict} ({s.received} received, {s.hits} hits)\n")
    out.write(f"verify {target}: {record.verdict}\n")
    return EXIT_CODES[record.verdict], evidence.encode(record)
