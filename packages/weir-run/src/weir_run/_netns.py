"""The network namespace helper, run as its own process by `weir_run.isolation`.

    python -I -S _netns.py create FD [stub]
        Make a user and network namespace whose only interface is loopback,
        route every address to loopback so a direct connection is refused at
        once instead of leaving, and open two sockets inside it: the mock's
        listening socket on 127.0.0.1 and a packet socket that sees each
        connection attempt. With `stub`, also open the name and TLS stub's
        sockets: UDP 127.0.0.1:53, and TCP 127.0.0.1:443 and 127.0.0.1:80.
        Send them, with handles on the two namespaces, over the Unix socket
        FD, then exit. The handles keep the namespace.

    python -I -S _netns.py enter USERFD NETFD COMMAND [ARG]...
        Join that namespace and exec COMMAND. If the namespace cannot be
        joined, COMMAND does not run.

It runs in a fresh process because a process must be single-threaded to
enter a user namespace, and the runner is not. Standard library only: `-S`
leaves site-packages out.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import socket
import struct
import sys

if sys.platform != "linux":
    raise SystemExit("weir-run: the network namespace helper runs on Linux only")

# <linux/sockios.h>, <linux/if.h>
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
# <linux/netlink.h>, <linux/rtnetlink.h>
NETLINK_ROUTE = 0
RTM_NEWROUTE = 24
NLMSG_ERROR = 2
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
RT_TABLE_LOCAL = 255
RTPROT_STATIC = 4
RT_SCOPE_HOST = 254
RTN_LOCAL = 2
RTA_OIF = 4
# <linux/if_ether.h>, <linux/if_packet.h>, <linux/filter.h>
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
PACKET_OUTGOING = 4
SO_ATTACH_FILTER = 26
SKF_AD_PROTOCOL = 0xFFFFF000
SKF_AD_PKTTYPE = 0xFFFFF004
IPPROTO_TCP = 6
IPPROTO_UDP = 17
TCP_SYN = 0x02
TCP_SYN_ACK = 0x12

LD_W_ABS = 0x20
LD_B_ABS = 0x30
LD_B_IND = 0x50
LDX_B_MSH = 0xB1
JEQ_K = 0x15
AND_K = 0x54
RET_K = 0x06
KEEP = 0x40000
DROP = 0

# Pass only what a flow sends out: a TCP SYN (a connection being opened) or
# a UDP datagram, over IPv4 or IPv6. The mock's own traffic is everything
# else and never wakes the reader. Offsets start at the network header,
# as on a SOCK_DGRAM packet socket. (code, jump if true, jump if false, k)
FILTER: tuple[tuple[int, int, int, int], ...] = (
    (LD_W_ABS, 0, 0, SKF_AD_PKTTYPE),  # 0
    (JEQ_K, 0, 17, PACKET_OUTGOING),  # 1: -> 19 drop
    (LD_W_ABS, 0, 0, SKF_AD_PROTOCOL),  # 2
    (JEQ_K, 1, 0, ETH_P_IP),  # 3: -> 5 IPv4
    (JEQ_K, 7, 14, ETH_P_IPV6),  # 4: -> 12 IPv6, else -> 19 drop
    (LD_B_ABS, 0, 0, 9),  # 5: IPv4 protocol
    (JEQ_K, 11, 0, IPPROTO_UDP),  # 6: -> 18 keep
    (JEQ_K, 0, 11, IPPROTO_TCP),  # 7: else -> 19 drop
    (LDX_B_MSH, 0, 0, 0),  # 8: X = IPv4 header length
    (LD_B_IND, 0, 0, 13),  # 9: TCP flags
    (AND_K, 0, 0, TCP_SYN_ACK),  # 10
    (JEQ_K, 6, 7, TCP_SYN),  # 11: -> 18 keep, else -> 19 drop
    (LD_B_ABS, 0, 0, 6),  # 12: IPv6 next header
    (JEQ_K, 4, 0, IPPROTO_UDP),  # 13: -> 18 keep
    (JEQ_K, 0, 4, IPPROTO_TCP),  # 14: else -> 19 drop
    (LD_B_ABS, 0, 0, 40 + 13),  # 15: TCP flags after the fixed IPv6 header
    (AND_K, 0, 0, TCP_SYN_ACK),  # 16
    (JEQ_K, 0, 1, TCP_SYN),  # 17: -> 18 keep, else -> 19 drop
    (RET_K, 0, 0, KEEP),  # 18
    (RET_K, 0, 0, DROP),  # 19
)


class Failed(Exception):
    pass


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii") as f:
        f.write(text)


def _loopback_up() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        request = struct.pack("16sH22x", b"lo", 0)
        flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, request)[:18])[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH22x", b"lo", flags | IFF_UP))


def _route_everything_to_loopback(family: int) -> None:
    """`ip route add local default dev lo table local`: every address is
    this namespace's own, so a connection to one is refused at once, and
    seen, instead of failing with no packet at all."""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE) as nl:
        rtmsg = struct.pack(
            "BBBBBBBBI", family, 0, 0, 0, RT_TABLE_LOCAL, RTPROT_STATIC, RT_SCOPE_HOST, RTN_LOCAL, 0
        )
        oif = struct.pack("HHI", 8, RTA_OIF, socket.if_nametoindex("lo"))
        body = rtmsg + oif
        flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        nl.send(struct.pack("IHHII", 16 + len(body), RTM_NEWROUTE, flags, 1, 0) + body)
        reply = nl.recv(4096)
    kind = struct.unpack("H", reply[4:6])[0]
    code = struct.unpack("i", reply[16:20])[0] if kind == NLMSG_ERROR else 0
    if code:
        raise OSError(-code, os.strerror(-code))


def _packet_socket() -> socket.socket:
    packets = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
    program = b"".join(struct.pack("HBBI", *insn) for insn in FILTER)
    buffer = ctypes.create_string_buffer(program)
    fprog = struct.pack("HP", len(FILTER), ctypes.addressof(buffer))
    packets.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    # Bound only now, with the filter in place: nothing unfiltered is queued.
    packets.bind(("lo", ETH_P_ALL))
    return packets


# The name and TLS stub's sockets: (type, port), all on 127.0.0.1.
STUB_SOCKETS = ((socket.SOCK_DGRAM, 53), (socket.SOCK_STREAM, 443), (socket.SOCK_STREAM, 80))


def _stub_sockets() -> list[socket.socket]:
    """Bound inside the namespace, where its user holds every capability,
    so the privileged ports are open to it."""
    out: list[socket.socket] = []
    for kind, port in STUB_SOCKETS:
        s = socket.socket(socket.AF_INET, kind)
        s.bind(("127.0.0.1", port))
        if kind == socket.SOCK_STREAM:
            s.listen(128)
        out.append(s)
    return out


def create(channel: socket.socket, stub: bool = False) -> None:
    uid, gid = os.geteuid(), os.getegid()
    try:
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        except OSError as exc:
            raise Failed(f"cannot create a user and network namespace ({exc.strerror})") from None
        try:
            _write("/proc/self/setgroups", "deny")
            _write("/proc/self/uid_map", f"{uid} {uid} 1")
            _write("/proc/self/gid_map", f"{gid} {gid} 1")
        except OSError as exc:
            raise Failed(f"cannot map the user into the namespace ({exc.strerror})") from None
        try:
            _loopback_up()
        except OSError as exc:
            raise Failed(f"cannot bring up loopback in the namespace ({exc.strerror})") from None
        try:
            _route_everything_to_loopback(socket.AF_INET)
        except OSError as exc:
            raise Failed(f"cannot route addresses to loopback ({exc.strerror})") from None
        try:
            _route_everything_to_loopback(socket.AF_INET6)
        except OSError as exc:
            # IPv6 off in this kernel: an IPv6 attempt fails with no packet
            # and cannot leave either way.
            if exc.errno not in (errno.EAFNOSUPPORT, errno.EACCES, errno.EPERM):
                raise Failed(f"cannot route IPv6 addresses to loopback ({exc.strerror})") from None
        try:
            packets = _packet_socket()
        except OSError as exc:
            raise Failed(f"cannot watch the namespace's loopback ({exc.strerror})") from None
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        try:
            stubs = _stub_sockets() if stub else []
        except OSError as exc:
            raise Failed(f"cannot open the name and TLS stub ({exc.strerror})") from None
        user = os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC)
        net = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    except Failed as exc:
        channel.sendall(f"error {exc}".encode())
        return
    fds = [user, net, listener.fileno(), packets.fileno(), *(s.fileno() for s in stubs)]
    socket.send_fds(channel, [b"ok"], fds)


def enter(user: int, net: int, command: list[str]) -> None:
    try:
        os.setns(user, os.CLONE_NEWUSER)
        os.setns(net, os.CLONE_NEWNET)
    except OSError as exc:
        sys.stderr.write(f"weir-run: cannot enter the isolated network ({exc.strerror})\n")
        os._exit(126)
    os.close(user)
    os.close(net)
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        sys.stderr.write(f"weir-run: could not start the flow: {exc.strerror}\n")
        os._exit(127)


def main(argv: list[str]) -> None:
    if len(argv) in (2, 3) and argv[0] == "create" and argv[2:] in ([], ["stub"]):
        create(socket.socket(fileno=int(argv[1])), stub=argv[2:] == ["stub"])
    elif len(argv) >= 4 and argv[0] == "enter":
        enter(int(argv[1]), int(argv[2]), argv[3:])
    else:
        sys.stderr.write(
            "usage: _netns.py create FD [stub] | enter USERFD NETFD COMMAND [ARG]...\n"
        )
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
