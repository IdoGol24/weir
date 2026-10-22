"""Network isolation: flows run where the only network is loopback.

On Linux, `jail()` makes an unprivileged user and network namespace (what
`unshare --user --net` makes) whose only interface is loopback. The mock
listens on 127.0.0.1 inside it, and every flow is started inside it, so a
client that ignores the proxy settings reaches nothing: there is no route
out. Every other address is routed to the namespace's own loopback, so such
a connection is refused at once instead of hanging, and a packet socket on
that loopback sees the attempt:

- a TCP connection opened to any address but loopback (`tcp`, the address
  and port);
- a UDP datagram sent to any address but loopback (`udp`), its payload kept
  for the capture;
- a DNS query, to any address (`dns`, the name asked for), its payload kept
  for the capture.

The namespace is made by a helper process (`_netns.py`) because a process
must be single-threaded to enter a new user namespace. It hands back the
mock's listening socket, the packet socket and handles on the namespace;
each flow starts through the same helper, which joins the namespace before
it execs the flow, and never runs the flow if it cannot.

Where namespaces are unavailable (not Linux, user namespaces disabled or
restricted), `jail()` raises `Unavailable` naming why, and the run goes
ahead unisolated: the report says direct connections were not observed.
"""

from __future__ import annotations

import ipaddress
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

HELPER = Path(__file__).with_name("_netns.py")
HELPER_TIMEOUT_SECONDS = 30
MAX_PACKET = 0x40000
# <linux/if_packet.h>: getsockopt(SOL_PACKET, PACKET_STATISTICS)
SOL_PACKET = 263
PACKET_STATISTICS = 6
IPPROTO_TCP = 6
IPPROTO_UDP = 17
DNS_PORT = 53
_LABEL = re.compile(rb"[A-Za-z0-9_-]{1,63}")
MAX_NAME = 253


class Unavailable(Exception):
    """Network isolation cannot be set up here. The message says why."""


@dataclass(frozen=True)
class Attempt:
    """One direct connection attempt a flow made, blocked by the namespace."""

    protocol: str  # tcp | udp | dns
    target: str  # address:port, or the DNS name asked for
    payload: bytes = field(default=b"", repr=False)


def _address(raw: bytes) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.IPv4Address(raw) if len(raw) == 4 else ipaddress.IPv6Address(raw)


def _loopback(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def _target(address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> str:
    host = str(address) if address.version == 4 else f"[{address}]"
    return f"{host}:{port}"


def dns_name(payload: bytes) -> str | None:
    """The name a DNS query asks for, or None when payload is not a query
    for a plain host name."""
    if len(payload) < 12 or payload[2] & 0x80 or int.from_bytes(payload[4:6]) < 1:
        return None
    labels: list[str] = []
    i = 12
    while i < len(payload):
        length = payload[i]
        i += 1
        if length == 0:
            name = ".".join(labels)
            return name if 0 < len(name) <= MAX_NAME else None
        label = payload[i : i + length]
        if len(label) != length or not _LABEL.fullmatch(label):
            return None
        labels.append(label.decode("ascii"))
        i += length
    return None


def parse(packet: bytes) -> Attempt | None:
    """The attempt an outgoing IP packet is, if any. The packet socket's
    filter passes only TCP SYNs and UDP datagrams."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        start = (packet[0] & 0x0F) * 4
        protocol, destination = packet[9], _address(packet[16:20])
    elif version == 6 and len(packet) >= 40:
        start = 40
        protocol, destination = packet[6], _address(packet[24:40])
    else:
        return None
    if len(packet) < start + 8:
        return None
    port = int.from_bytes(packet[start + 2 : start + 4])
    if protocol == IPPROTO_TCP:
        return None if _loopback(destination) else Attempt("tcp", _target(destination, port))
    if protocol == IPPROTO_UDP:
        payload = packet[start + 8 :]
        if port == DNS_PORT:
            name = dns_name(payload)
            if name is not None:
                return Attempt("dns", name, payload)
        if not _loopback(destination):
            return Attempt("udp", _target(destination, port), payload)
    return None


class Jail:
    """A loopback-only network namespace, alive for one check run."""

    def __init__(self, user_ns: int, net_ns: int, listener: socket.socket, packets: socket.socket):
        self._user_ns = user_ns
        self._net_ns = net_ns
        self.listener = listener
        self._packets = packets
        self._packets.setblocking(False)
        self._lock = threading.Lock()
        self._attempts: list[Attempt] = []
        self._dropped = 0
        self._wake_r, self._wake_w = os.pipe()
        self._closed = False
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def command(self, command: Sequence[str]) -> list[str]:
        """command, started inside the namespace."""
        user, net = str(self._user_ns), str(self._net_ns)
        return [sys.executable, "-I", "-S", str(HELPER), "enter", user, net, *command]

    @property
    def fds(self) -> tuple[int, int]:
        """The descriptors a flow's process must inherit to join."""
        return (self._user_ns, self._net_ns)

    def _drain(self) -> None:
        # Called with the lock held.
        while True:
            try:
                packet = self._packets.recv(MAX_PACKET)
            except (BlockingIOError, InterruptedError):
                break
            attempt = parse(packet)
            if attempt is not None:
                self._attempts.append(attempt)
        stats = self._packets.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        self._dropped += struct.unpack("II", stats)[1]

    def _watch(self) -> None:
        while True:
            ready, _, _ = select.select([self._packets, self._wake_r], [], [])
            if self._wake_r in ready:
                return
            with self._lock:
                self._drain()

    def collect(self) -> list[Attempt]:
        """Every attempt seen since the last call. A flow's packets are all
        queued by the time its processes have exited: the kernel hands an
        outgoing packet to the packet socket as it is sent."""
        with self._lock:
            self._drain()
            if self._dropped:
                raise RuntimeError("the isolated network's watcher dropped packets")
            attempts, self._attempts = self._attempts, []
        return attempts

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.write(self._wake_w, b"x")
        self._thread.join()
        for fd in (self._user_ns, self._net_ns, self._wake_r, self._wake_w):
            os.close(fd)
        self._packets.close()
        self.listener.close()


def jail() -> Jail:
    """A new loopback-only namespace, or `Unavailable` saying why not."""
    if sys.platform != "linux":
        raise Unavailable("network isolation needs Linux")
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with ours:
            try:
                done = subprocess.run(
                    [sys.executable, "-I", "-S", str(HELPER), "create", str(theirs.fileno())],
                    pass_fds=(theirs.fileno(),),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    env={"LANG": "C.UTF-8"},
                    timeout=HELPER_TIMEOUT_SECONDS,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise Unavailable(f"the namespace helper did not run ({exc})") from None
            theirs.close()
            message, fds, _, _ = socket.recv_fds(ours, 4096, 4)
    finally:
        theirs.close()
    for fd in fds:
        # Received descriptors are inheritable; only a flow's own may pass.
        os.set_inheritable(fd, False)
    if message == b"ok" and len(fds) == 4:
        user, net, listener, packets = fds
        return Jail(user, net, socket.socket(fileno=listener), socket.socket(fileno=packets))
    for fd in fds:
        os.close(fd)
    if message.startswith(b"error "):
        raise Unavailable(message.removeprefix(b"error ").decode("utf-8", "replace"))
    raise Unavailable(f"the namespace helper failed (exit {done.returncode})")
