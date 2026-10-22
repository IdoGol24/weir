"""The mock: one HTTP server on 127.0.0.1, alive for one check run.

It is every endpoint a flow is pointed at (the model API, the OAuth
endpoints, the OTLP/HTTP receiver and the program's own configured APIs)
and the HTTP(S) proxy for everything else. As a proxy it refuses: a
`CONNECT host:port` or an absolute-form request for any other host gets a
403 and nothing is forwarded, opened or resolved. The refused host is
logged, and a placement whose `provider_host` it is gets `egress`
evidence.

Before any mocked endpoint handles a request, the credential-field rules
run (docs/canary.md, "Runtime values"): each credential field either holds
a needle of a ledger value (`request` evidence for each such placement) or
is recorded as `unexpected` by endpoint and field name only. The mock
writes no request content anywhere else, and logs nothing about a request
but its method, a value-free path and a refused host.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import socket
import threading
import zlib
from collections import Counter
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock import otlp
from weir_run.mock.model import ModelApi
from weir_run.mock.oauth import CREDENTIAL_FORM_FIELDS, OAuth, parse_form
from weir_run.shapes import ByteSource
from weir_run.spec import CredentialField, EndpointSpec, MockSpec, PlacementSpec

HOST = "127.0.0.1"
MAX_BODY = 64 * 1024 * 1024
ALWAYS_INSPECTED = ("authorization", "proxy-authorization")
ENDPOINT_PREFIX = "/ep/"

type Reply = tuple[int, bytes, str, dict[str, str]]


def _decompress(raw: bytes, encoding: str) -> bytes | None:
    encoding = encoding.strip().lower()
    try:
        if encoding in ("", "identity"):
            return raw
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(raw)
        if encoding == "deflate":
            return zlib.decompress(raw)
    except (OSError, EOFError, zlib.error):
        return None
    return None


class Mock:
    def __init__(
        self,
        spec: MockSpec,
        ledger: Ledger,
        capture: Capture,
        placements: Sequence[PlacementSpec],
        source: ByteSource,
    ) -> None:
        self.spec = spec
        self.ledger = ledger
        self.capture = capture
        self.model = ModelApi(spec.model_reply, spec.tool_calls)
        self.oauth = OAuth(ledger, source) if spec.oauth else None
        self.endpoints = {e.id: e for e in spec.endpoints}
        self._provider_hosts: dict[str, list[str]] = {}
        for p in placements:
            if p.provider_host:
                self._provider_hosts.setdefault(p.provider_host.lower(), []).append(p.id)
        self._lock = threading.Lock()
        self.egress: Counter[str] = Counter()
        self.unmocked: Counter[str] = Counter()
        self.errors = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("the mock is not running")
        return self._server.server_port

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"

    def start(self, listener: socket.socket | None = None) -> None:
        """Serve on a fresh 127.0.0.1 port, or on listener: a socket already
        listening on 127.0.0.1 inside the isolated network."""
        mock = self

        class Handler(_Handler):
            owner = mock

        if listener is None:
            # Port 0: the OS picks a free loopback port. The address is fixed
            # to 127.0.0.1; there is no option to bind anything else.
            self._server = ThreadingHTTPServer((HOST, 0), Handler)
        else:
            if listener.getsockname()[0] != HOST:
                raise ValueError("the mock listens on 127.0.0.1 only")
            self._server = ThreadingHTTPServer(
                listener.getsockname(), Handler, bind_and_activate=False
            )
            self._server.socket.close()
            self._server.socket = listener
            self._server.server_address = listener.getsockname()
            self._server.server_name, self._server.server_port = HOST, listener.getsockname()[1]
        self._server.daemon_threads = True
        self._server.block_on_close = False
        if self.oauth is not None:
            self.oauth.base_url = self.url
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join()

    # -- egress and bookkeeping ----------------------------------------

    def refuse(self, host: str) -> None:
        host = host.lower()
        with self._lock:
            self.egress[host] += 1
        for placement_id in self._provider_hosts.get(host, []):
            self.ledger.exercised(placement_id, "egress")

    def note_unmocked(self, method: str, path: str) -> None:
        with self._lock:
            self.unmocked[f"{method} {path}"] += 1

    def note_error(self) -> None:
        with self._lock:
            self.errors += 1

    # -- the credential-field rules ------------------------------------

    def inspect(self, endpoint: str, fields: list[tuple[str, str]]) -> None:
        for name, value in fields:
            if not value:
                continue
            holders = self.ledger.holders(value.encode("utf-8", "surrogateescape"))
            if holders:
                for placement_id in holders:
                    self.ledger.exercised(placement_id, "request")
            else:
                self.ledger.unexpected(endpoint, name)


def _body_fields(body: bytes, content_type: str) -> dict[str, list[str]]:
    kind = content_type.split(";")[0].strip().lower()
    if kind == "application/x-www-form-urlencoded":
        return parse_form(body)
    if kind.endswith("json"):
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        if isinstance(doc, dict):
            out: dict[str, list[str]] = {}
            for key, value in cast(dict[str, Any], doc).items():
                out[key] = [value if isinstance(value, str) else json.dumps(value)]
            return out
    return {}


class _Handler(BaseHTTPRequestHandler):
    owner: Mock
    protocol_version = "HTTP/1.1"
    timeout = 60
    server_version = "canary-mock"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # The default handler logs the request line, which can hold a value.
        return

    # -- plumbing ------------------------------------------------------

    def _read_body(self) -> bytes:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            chunks: list[bytes] = []
            total = 0
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                total += size
                if total > MAX_BODY:
                    raise ValueError("body too large")
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY:
            raise ValueError("body too large")
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, reply: Reply, close: bool = False) -> None:
        status, body, content_type, headers = reply
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _refuse(self, host: str) -> None:
        self.owner.refuse(host)
        reply: Reply = (403, b"egress refused by the canary mock\n", "text/plain", {})
        self._send(reply, close=True)

    # -- dispatch ------------------------------------------------------

    def do_CONNECT(self) -> None:  # noqa: N802
        self._refuse(self.path.rsplit(":", 1)[0].strip("[]"))

    def _dispatch(self) -> None:
        try:
            target = self.path
            if "://" in target.split("?", 1)[0]:
                parts = urlsplit(target)
                own = parts.hostname in (HOST, "localhost") and parts.port == self.owner.port
                if not own:
                    self._refuse(parts.hostname or "")
                    return
                target = parts.path + (f"?{parts.query}" if parts.query else "")
            raw = self._read_body()
            self._send(self._route(target, raw))
        except Exception:  # noqa: BLE001 - never echo a request; count and fail it
            self.owner.note_error()
            self._send((500, b"canary mock error\n", "text/plain", {}), close=True)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _dispatch  # noqa: N815

    def _fields(
        self,
        declared: Sequence[CredentialField],
        query: dict[str, list[str]],
        body: dict[str, list[str]],
    ) -> list[tuple[str, str]]:
        out = [(h, v) for h in ALWAYS_INSPECTED for v in self.headers.get_all(h) or []]
        for f in declared:
            if f.location == "header" and f.name not in ALWAYS_INSPECTED:
                out += [(f.name, v) for v in self.headers.get_all(f.name) or []]
            elif f.location == "query":
                out += [(f.name, v) for v in query.get(f.name, [])]
            elif f.location == "body":
                out += [(f.name, v) for v in body.get(f.name, [])]
        return out

    def _route(self, target: str, raw: bytes) -> Reply:
        owner = self.owner
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query, keep_blank_values=True)
        content_type = self.headers.get("Content-Type", "")
        body = _decompress(raw, self.headers.get("Content-Encoding", ""))
        method = self.command

        if path in otlp.PATHS and method == "POST":
            fields = self._fields(owner.spec.fields_for("otlp"), query, {})
            owner.inspect("otlp", fields)
            status, reply, kind = otlp.receive(
                owner.capture, otlp.PATHS[path], body, raw, content_type
            )
            return status, reply, kind, {}

        if body is None:
            return 415, b"unsupported content encoding\n", "text/plain", {}
        body_fields = _body_fields(body, content_type)

        if path.startswith("/v1/"):
            owner.inspect("model", self._fields(owner.spec.fields_for("model"), query, body_fields))
            return self._model(method, path, body)

        if owner.oauth is not None and (
            path.startswith("/oauth/") or path.startswith("/.well-known/")
        ):
            fields = self._fields(owner.spec.fields_for("oauth"), query, body_fields)
            form = parse_form(body) if "form-urlencoded" in content_type.lower() else {}
            fields += [(n, v) for n in CREDENTIAL_FORM_FIELDS for v in form.get(n, [])]
            owner.inspect("oauth", fields)
            return self._oauth(method, path, query, form)

        if path.startswith(ENDPOINT_PREFIX):
            endpoint = owner.endpoints.get(path[len(ENDPOINT_PREFIX) :].split("/", 1)[0])
            if endpoint is not None:
                fields = self._fields(endpoint.credential_fields, query, body_fields)
                owner.inspect(endpoint.id, fields)
                return self._endpoint(endpoint, body)

        owner.note_unmocked(method, path)
        return 404, b"not mocked\n", "text/plain", {}

    # -- handlers ------------------------------------------------------

    def _model(self, method: str, path: str, body: bytes) -> Reply:
        model = self.owner.model
        try:
            doc: object = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, b'{"error":{"message":"invalid JSON"}}', "application/json", {}
        request = cast(dict[str, Any], doc) if isinstance(doc, dict) else {}
        routes = {
            ("POST", "/v1/chat/completions"): model.chat,
            ("POST", "/v1/responses"): model.responses,
            ("POST", "/v1/embeddings"): model.embeddings,
        }
        handler = routes.get((method, path))
        if handler is not None:
            reply, kind = handler(request)
            return 200, reply, kind, {}
        if method == "GET" and path == "/v1/models":
            return 200, *model.models(), {}
        if method == "GET" and path.startswith("/v1/models/"):
            return 200, *model.model(path.removeprefix("/v1/models/")), {}
        self.owner.note_unmocked(method, path)
        return 404, b'{"error":{"message":"not mocked"}}', "application/json", {}

    def _oauth(
        self, method: str, path: str, query: dict[str, list[str]], form: dict[str, list[str]]
    ) -> Reply:
        oauth = self.owner.oauth
        assert oauth is not None
        if method == "GET" and path in (
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ):
            return oauth.metadata()
        if method == "GET" and path == "/oauth/authorize":
            return oauth.authorize(query)
        if method == "POST" and path == "/oauth/device_authorization":
            return oauth.device()
        if method == "POST" and path == "/oauth/token":
            return oauth.token(form, _basic_user(self.headers.get("Authorization", "")))
        self.owner.note_unmocked(method, path)
        return 404, b'{"error":"not_mocked"}', "application/json", {}

    def _endpoint(self, endpoint: EndpointSpec, body: bytes) -> Reply:
        if endpoint.capture and body:
            self.owner.capture.swept_file(f"ep-{endpoint.id}", body)
        return endpoint.status, endpoint.reply.encode("utf-8"), endpoint.content_type, {}


def _basic_user(header: str) -> str | None:
    """The client id of an HTTP Basic client authentication, if any."""
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(credentials.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return decoded.split(":", 1)[0] or None
