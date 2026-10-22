"""The name and TLS stub: every other host a flow tries is named, and what
it sends there is seen.

It runs on sockets the isolated network's helper opened inside the
namespace (`isolation.jail(stub=True)`), all on 127.0.0.1:

- UDP 53: answers every name lookup for an IPv4 address with 127.0.0.1,
  and every other lookup with no address, and counts the names asked for;
- TCP 443: TLS, with a certificate for whatever name the flow asks for,
  signed by a certificate authority made for this run only;
- TCP 80: plain HTTP.

A request that arrives on 443 or 80 is on its way to another host: the
mock's `InterceptHandler` records it in the request capture as `refused`,
by that host, and refuses it. Nothing is forwarded, opened or resolved
outside the namespace. The flow trusts the authority only if it is told
to, through the certificate file `Stub.ca_file`; the authority's key never
leaves this process.
"""

from __future__ import annotations

import ipaddress
import re
import select
import socket
import ssl
import struct
import threading
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from weir_run.mock.server import InterceptHandler, Mock

# Fixed dates: the runner never reads the clock, and the authority and its
# certificates exist for one run only.
NOT_BEFORE = datetime(2020, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2100, 1, 1, tzinfo=UTC)
LOOPBACK = bytes([127, 0, 0, 1])
DNS_TYPE_A = 1
DNS_CLASS_IN = 1
DNS_TTL = 1
_NAME = re.compile(r"[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*\.?")
MAX_NAME = 253
POLL_SECONDS = 0.2


def _host_name(name: str) -> str | None:
    """name, lower case, if it is a plain host name a certificate can name."""
    lowered = name.lower()
    if len(lowered) > MAX_NAME or not _NAME.fullmatch(lowered):
        return None
    return lowered.rstrip(".")


class Authority:
    """A certificate authority for one run, and a TLS context per name."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weir-run stub, one run")])
        self._name = subject
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self._leaf_key = ec.generate_private_key(ec.SECP256R1())
        self._key_file = directory / "leaf.key"
        self._key_file.write_bytes(
            self._leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._count = 0

    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def context(self, name: str) -> ssl.SSLContext:
        """A server context whose certificate names name, signed by this
        authority."""
        with self._lock:
            found = self._contexts.get(name)
            if found is not None:
                return found
            self._count += 1
            path = self._directory / f"leaf-{self._count}.pem"
            path.write_bytes(self._leaf(name).public_bytes(serialization.Encoding.PEM))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(path, self._key_file)
            self._contexts[name] = context
            return context

    def _leaf(self, name: str) -> x509.Certificate:
        try:
            alternative: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(name))
        except ValueError:
            alternative = x509.DNSName(name)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(self._name)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )


def question(query: bytes) -> tuple[str, int, int, int] | None:
    """A DNS query's (name, type, class, end of the question), or None when
    query is not a standard query for one plain name."""
    if len(query) < 12 or query[2] & 0xF8 or int.from_bytes(query[4:6]) != 1:
        return None
    labels: list[str] = []
    i = 12
    while i < len(query):
        length = query[i]
        i += 1
        if length == 0:
            if i + 4 > len(query):
                return None
            kind, klass = struct.unpack("!HH", query[i : i + 4])
            name = ".".join(labels)
            return (name, kind, klass, i + 4) if 0 < len(name) <= MAX_NAME else None
        if length > 63:
            return None
        label = query[i : i + length]
        if len(label) != length:
            return None
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return None
        i += length
    return None


def answer(query: bytes) -> tuple[str, bytes] | None:
    """The name asked for and the stub's reply: 127.0.0.1 for an IPv4
    address lookup, no address for any other."""
    parsed = question(query)
    if parsed is None:
        return None
    name, kind, klass, end = parsed
    address = kind == DNS_TYPE_A and klass == DNS_CLASS_IN
    # QR, the query's opcode and RD, RA; no error.
    flags = 0x8000 | (int.from_bytes(query[2:4]) & 0x7900) | 0x0080
    header = query[:2] + struct.pack("!HHHHH", flags, 1, 1 if address else 0, 0, 0)
    reply = header + query[12:end]
    if address:
        # A pointer to the name in the question, then type A, class IN.
        reply += struct.pack("!HHHIH", 0xC00C, DNS_TYPE_A, DNS_CLASS_IN, DNS_TTL, 4) + LOOPBACK
    return name.lower(), reply


class _TlsServer(ThreadingHTTPServer):
    """Serves TLS with a certificate for the name each connection asks for
    (its SNI), or for 127.0.0.1 when it names none."""

    authority: Authority

    def server_context(self) -> ssl.SSLContext:
        authority = self.authority

        def pick(sock: ssl.SSLObject | ssl.SSLSocket, name: str | None, _: ssl.SSLContext) -> None:
            host = None if name is None else _host_name(name)
            if host is not None:
                # Read back by InterceptHandler: the host the flow asked for.
                setattr(sock, "weir_sni", host)  # noqa: B010
                sock.context = authority.context(host)

        context = authority.context("127.0.0.1")
        context.sni_callback = pick
        return context

    def get_request(self) -> tuple[Any, Any]:
        connection, address = self.socket.accept()
        # The handshake runs in the request's own thread, not the accept loop.
        wrapped = self.server_context().wrap_socket(
            connection, server_side=True, do_handshake_on_connect=False
        )
        return wrapped, address


class Stub:
    """The DNS, TLS and HTTP stub, alive while the mock is."""

    def __init__(self, mock: Mock, sockets: Sequence[socket.socket], directory: Path) -> None:
        if len(sockets) != 3:
            raise ValueError("the stub takes its DNS, TLS and HTTP sockets")
        self._dns, tls, http = sockets
        self.authority = Authority(directory)
        self.ca_file = directory / "ca.pem"
        self.ca_file.write_bytes(self.authority.pem())
        self.names: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._servers: list[ThreadingHTTPServer] = []
        for listener, port, server_class in (
            (tls, 443, _TlsServer),
            (http, 80, ThreadingHTTPServer),
        ):

            class Handler(InterceptHandler):
                owner = mock

            Handler.port = port
            server = server_class(listener.getsockname(), Handler, bind_and_activate=False)
            server.socket.close()
            server.socket = listener
            server.daemon_threads = True
            server.block_on_close = False
            if isinstance(server, _TlsServer):
                server.authority = self.authority
            self._servers.append(server)
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._threads = [
            threading.Thread(target=s.serve_forever, daemon=True) for s in self._servers
        ]
        self._threads.append(threading.Thread(target=self._serve_dns, daemon=True))
        for thread in self._threads:
            thread.start()

    def _serve_dns(self) -> None:
        while not self._stopping.is_set():
            ready, _, _ = select.select([self._dns], [], [], POLL_SECONDS)
            if not ready:
                continue
            try:
                query, client = self._dns.recvfrom(4096)
            except OSError:
                continue
            replied = answer(query)
            if replied is None:
                continue
            name, reply = replied
            with self._lock:
                self.names[name] += 1
            try:
                self._dns.sendto(reply, client)
            except OSError:
                continue

    def stop(self) -> None:
        self._stopping.set()
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join()
