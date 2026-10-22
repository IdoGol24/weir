"""Network isolation (docs/canary.md, "Network isolation"), beyond the locked
acceptance tests in test_runner_isolation_acceptance.py.

Packets for the parser are built from the header layouts of RFC 791 (IPv4),
RFC 8200 (IPv6), RFC 9293 (TCP), RFC 768 (UDP) and RFC 1035 (a DNS query).
Every address a flow here tries is a documentation address (RFC 5737,
RFC 3849) that is never routed on the internet, and every one is tried only
inside the namespace, where there is no route out at all.

The isolated cases skip where isolation is unavailable, unless
WEIR_TEST_REQUIRE_NETNS is set (CI on Linux sets it), when they fail.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from weir_run import cli, flows, isolation
from weir_run import judge as judge_cli
from weir_run.pytest_plugin import CanaryCheck
from weir_run.spec import FlowSpec


def _jail() -> isolation.Jail:
    try:
        return isolation.jail()
    except isolation.Unavailable as exc:
        if os.environ.get("WEIR_TEST_REQUIRE_NETNS"):
            pytest.fail(f"isolation is required here but was unavailable: {exc}")
        pytest.skip(f"network isolation is not available here: {exc}")


@pytest.fixture
def jail() -> Generator[isolation.Jail]:
    made = _jail()
    try:
        yield made
    finally:
        made.close()


@pytest.fixture
def isolated() -> None:
    """Skip a whole run that needs isolation where there is none."""
    _jail().close()


# -- the packet parser -----------------------------------------------------


def _ipv4(protocol: int, destination: str, transport: bytes, options: bytes = b"") -> bytes:
    ihl = 5 + len(options) // 4
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        ihl * 4 + len(transport),
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton(destination),
    )
    return header + options + transport


def _ipv6(next_header: int, destination: str, transport: bytes) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(transport),
        next_header,
        64,
        ipaddress.IPv6Address("2001:db8::1").packed,
        ipaddress.IPv6Address(destination).packed,
    )
    return header + transport


def _syn(port: int) -> bytes:
    return struct.pack("!HHIIBBHHH", 40000, port, 1, 0, 5 << 4, 0x02, 65535, 0, 0)


def _udp(port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", 40000, port, 8 + len(payload), 0) + payload


def _dns_query(name: str, *, reply: bool = False) -> bytes:
    flags = 0x8180 if reply else 0x0100
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0) + labels + b"\0" + b"\0\1\0\1"


@pytest.mark.parametrize(
    ("packet", "expected"),
    [
        (_ipv4(6, "203.0.113.7", _syn(443)), ("tcp", "203.0.113.7:443")),
        (_ipv4(6, "203.0.113.7", _syn(80), options=b"\1\1\1\0"), ("tcp", "203.0.113.7:80")),
        (_ipv4(6, "127.0.0.1", _syn(443)), None),
        (_ipv6(6, "2001:db8::7", _syn(443)), ("tcp", "[2001:db8::7]:443")),
        (_ipv6(6, "::1", _syn(443)), None),
        (_ipv6(6, "::ffff:127.0.0.1", _syn(443)), None),
        (_ipv4(17, "198.51.100.9", _udp(8125, b"m:1|c")), ("udp", "198.51.100.9:8125")),
        (_ipv4(17, "127.0.0.1", _udp(8125, b"m:1|c")), None),
        (
            _ipv4(17, "192.0.2.53", _udp(53, _dns_query("api.example.com"))),
            ("dns", "api.example.com"),
        ),
        (
            _ipv4(17, "127.0.0.53", _udp(53, _dns_query("api.example.com"))),
            ("dns", "api.example.com"),
        ),
        (_ipv6(17, "2001:db8::53", _udp(53, _dns_query("a_b.example"))), ("dns", "a_b.example")),
        (
            _ipv4(17, "192.0.2.53", _udp(53, _dns_query("api.example.com", reply=True))),
            ("udp", "192.0.2.53:53"),
        ),
        (_ipv4(17, "127.0.0.53", _udp(53, b"\0" * 12)), None),
        (_ipv4(1, "203.0.113.7", b"\x08\0\0\0\0\0\0\0"), None),
        (b"", None),
        (b"\x45\0", None),
    ],
)
def test_the_parser_names_each_direct_attempt(
    packet: bytes, expected: tuple[str, str] | None
) -> None:
    attempt = isolation.parse(packet)
    assert (attempt and (attempt.protocol, attempt.target)) == expected


def test_a_datagram_keeps_its_payload_for_the_capture() -> None:
    attempt = isolation.parse(_ipv4(17, "198.51.100.9", _udp(8125, b"payload")))
    assert attempt is not None and attempt.payload == b"payload"


@pytest.mark.parametrize(
    "payload",
    [
        _dns_query("api.example.com")[:20],  # truncated
        _dns_query("api.example.com").replace(b"\3api", b"\3a i"),  # not a host name
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c",  # a compression pointer
        struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0) + b"\3api\0",  # no question
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\0",  # the root
    ],
)
def test_a_dns_payload_that_is_not_a_plain_query_has_no_name(payload: bytes) -> None:
    assert isolation.dns_name(payload) is None


def test_isolation_needs_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(isolation.Unavailable, match="needs Linux"):
        isolation.jail()


# -- flows inside the namespace ----------------------------------------------


def _flow(tmp_path: Path, body: str, timeout: float = 30.0) -> FlowSpec:
    script = tmp_path / "flow.py"
    script.write_text(body, encoding="utf-8")
    return FlowSpec(
        id="f", command=("{python}", str(script)), cwd=tmp_path, timeout_seconds=timeout
    )


def _env(tmp_path: Path) -> dict[str, str]:
    return flows.flow_environment("http://127.0.0.1:9", {}, {}, tmp_path, tmp_path)


def _run(jail: isolation.Jail, flow: FlowSpec, tmp_path: Path) -> str:
    out, err = tmp_path / "out", tmp_path / "err"
    return flows.run(flow, _env(tmp_path), out, err, sys.executable, jail)


def test_an_isolated_flow_sees_loopback_only_and_holds_no_capability(
    tmp_path: Path, jail: isolation.Jail
) -> None:
    body = f"""
import json, socket
caps = [line.split()[1] for line in open("/proc/self/status") if line.startswith("CapEff")]
json.dump({{"interfaces": [name for _, name in socket.if_nameindex()], "caps": caps}},
          open({str(tmp_path / "seen.json")!r}, "w"))
"""
    assert _run(jail, _flow(tmp_path, body), tmp_path) == "ok", (tmp_path / "err").read_text()
    seen = json.loads((tmp_path / "seen.json").read_text())
    # No interface to leave by, and no capability to add one or to undo
    # the routes: the flow cannot get out of the namespace.
    assert seen == {"interfaces": ["lo"], "caps": ["0000000000000000"]}


def test_an_isolated_flow_that_cannot_start_failed(tmp_path: Path, jail: isolation.Jail) -> None:
    flow = FlowSpec(id="f", command=(str(tmp_path / "no-such-program"),), cwd=tmp_path)
    assert _run(jail, flow, tmp_path) == "failed"
    assert b"could not start the flow" in (tmp_path / "err").read_bytes()


def test_an_isolated_flow_still_times_out_and_its_children_stop(
    tmp_path: Path, jail: isolation.Jail
) -> None:
    marker = tmp_path / "child-alive"
    body = f"""
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c",
    "import time, pathlib; time.sleep(1.5); pathlib.Path({str(marker)!r}).write_text('x')"])
time.sleep(30)
"""
    assert _run(jail, _flow(tmp_path, body, timeout=0.5), tmp_path) == "timeout"
    time.sleep(2.5)
    assert not marker.exists()


def test_every_attempt_is_seen_by_the_time_its_flow_has_exited(
    tmp_path: Path, jail: isolation.Jail
) -> None:
    body = """
import socket
for port in range(1000, 1300):
    try:
        socket.create_connection(("203.0.113.7", port), timeout=5).close()
    except OSError:
        pass
"""
    assert _run(jail, _flow(tmp_path, body), tmp_path) == "ok"
    targets = sorted(a.target for a in jail.collect())
    assert targets == sorted(f"203.0.113.7:{port}" for port in range(1000, 1300))
    assert jail.collect() == []


# -- whole runs ----------------------------------------------------------------

CONFIG = """
[[placement]]
id = "env.APP_KEY"
kind = "env"
required = true

[[flow]]
id = "main"
command = ["{{python}}", {flow}]
"""

DATAGRAMS = """
import json, os, socket, struct, urllib.request

def post(url, body, headers):
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers)) as r:
        r.read()

key = os.environ["APP_KEY"]
mock = os.environ["CANARY_MOCK_URL"]
post(mock + "/v1/chat/completions", b"{}", {"Authorization": "Bearer " + key})
doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "clean span"}]}]}]}
post(os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"], json.dumps(doc).encode(),
     {"Content-Type": "application/json"})
# A metrics client that sends straight to its collector, key and all...
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(("deploys:1|c|#key:" + key).encode(), ("198.51.100.9", 8125))
# ...and a resolver of its own, asking a server that is not the host's.
query = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
query += b"\\x09telemetry\\x09collector\\x07example\\x00\\x00\\x01\\x00\\x01"
udp.sendto(query, ("192.0.2.53", 53))
"""


def _cli(
    monkeypatch: pytest.MonkeyPatch,
    judge: list[str],
    tmp_path: Path,
    body: str,
    *args: str,
    config: str | None = None,
) -> Result:
    """Run body as the flow `main`, or the flows of config."""
    flow = tmp_path / "flow.py"
    flow.write_text(body, encoding="utf-8")
    path = tmp_path / "canary.toml"
    text = config or CONFIG.format(flow=json.dumps(flow.as_posix()))
    path.write_text(text, encoding="utf-8")

    def resolve(explicit: str | None = None) -> list[str]:
        return judge

    monkeypatch.setattr(judge_cli, "resolve", resolve)
    return CliRunner().invoke(cli.main, ["run", "--config", str(path), *args])


@pytest.mark.usefixtures("isolated")
def test_a_canary_in_a_blocked_datagram_is_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    result = _cli(monkeypatch, judge, tmp_path, DATAGRAMS)
    assert result.exit_code == 1, result.output
    lines = result.stdout.splitlines()
    assert "LEAK env.APP_KEY file=capture/swept/direct-main-1.udp:1 signal=raw form=raw" in lines
    assert "incomplete: direct_connection main=dns:telemetry.collector.example" in lines
    assert "incomplete: direct_connection main=udp:198.51.100.9:8125" in lines
    assert "network isolated: 2 direct connections blocked" in lines
    assert "blocked direct udp datagram to 198.51.100.9:8125 from flow main (1x)" in result.stderr
    assert (
        "blocked direct dns lookup of telemetry.collector.example from flow main (1x)"
        in result.stderr
    )


@pytest.mark.usefixtures("isolated")
def test_a_lookup_of_an_underscore_name_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # Service and policy names, as SRV and DMARC lookups ask for.
    clean = DATAGRAMS.split("# A metrics client")[0]
    body = clean + """
query = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
query += b"\\x06_dmarc\\x07example\\x03com\\x00\\x00\\x10\\x00\\x01"
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(query, ("192.0.2.53", 53))
"""
    result = _cli(monkeypatch, judge, tmp_path, body)
    assert result.exit_code == 3, result.output
    direct = [line for line in result.stdout.splitlines() if "direct_connection" in line]
    assert direct == ["incomplete: direct_connection main=dns:_dmarc.example.com"]
    assert "blocked direct dns lookup of _dmarc.example.com from flow main (1x)" in result.stderr


@pytest.mark.usefixtures("isolated")
def test_flows_whose_ids_share_a_file_name_keep_their_own_datagrams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # `agent:a` and `agent/a` both become `agent_a` in a file name; only the
    # first flow's datagram carries the key.
    clean = DATAGRAMS.split("# A metrics client")[0]
    send = """
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(%s, ("198.51.100.9", 8125))
"""
    (tmp_path / "first.py").write_text(clean + send % '("k:" + key).encode()', encoding="utf-8")
    (tmp_path / "second.py").write_text("import socket\n" + send % 'b"m:1|c"', encoding="utf-8")
    config = "".join(
        f"""
[[flow]]
id = "{flow_id}"
command = ["{{python}}", {json.dumps((tmp_path / name).as_posix())}]
"""
        for flow_id, name in (("agent:a", "first.py"), ("agent/a", "second.py"))
    )
    placement = CONFIG.split("[[flow]]")[0]
    result = _cli(monkeypatch, judge, tmp_path, "", config=placement + config)
    assert result.exit_code == 1, result.output
    lines = result.stdout.splitlines()
    assert "LEAK env.APP_KEY file=capture/swept/direct-agent_a-1.udp:1 signal=raw form=raw" in lines


def test_the_plugin_requires_isolation_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    def unavailable() -> isolation.Jail:
        raise isolation.Unavailable("user namespaces are disabled")

    monkeypatch.setattr(isolation, "jail", unavailable)
    probe = Path(__file__).parent / "_probe_flow.py"
    for require, code in ((False, 0), (True, 3)):
        check = CanaryCheck(judge, tmp_path, require_isolation=require)
        try:
            check.env("APP_KEY", required=True)
            check.run(["{python}", probe.as_posix()], env={"SIDE_FILE": str(tmp_path / "side")})
            result = check.judge()
        finally:
            check.close()
        assert result.code == code, result.report
        assert "network not isolated: direct connections were not observed" in result.report
        assert "network: not isolated (user namespaces are disabled)" in result.output
        assert ("incomplete: network_not_isolated" in result.report) is require


BYPASS = """
import socket
try:
    socket.create_connection(("203.0.113.7", 443), timeout=5).close()
except OSError:
    pass
"""


@pytest.mark.usefixtures("isolated")
def test_each_attempt_is_reported_against_the_flow_that_made_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, judge: list[str]
) -> None:
    # The first flow bypasses the proxy; the second does not.
    clean = DATAGRAMS.split("# A metrics client")[0]
    (tmp_path / "first.py").write_text(clean + BYPASS, encoding="utf-8")
    second = f"""
[[flow]]
id = "second"
command = ["{{python}}", {json.dumps((tmp_path / "flow.py").as_posix())}]
"""
    config = CONFIG.format(flow=json.dumps((tmp_path / "first.py").as_posix()))
    result = _cli(monkeypatch, judge, tmp_path, clean, config=config + second)
    assert result.exit_code == 3, result.output
    direct = [line for line in result.stdout.splitlines() if "direct_connection" in line]
    assert direct == ["incomplete: direct_connection main=tcp:203.0.113.7:443"]
