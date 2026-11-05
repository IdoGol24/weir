"""A fake credential-swapping target for `weir-run verify`'s tests, in fake
values only, so CI needs no real tool. It plays a sidecar proxy
(`-config FILE`): a plain-HTTP proxy that forwards only to allowed hosts and
swaps a stand-in for the key in the `x-api-key` header of requests to its
inject hosts.

Arguments: MODE SIDE_FILE, then the target's own. It writes the key it
holds to SIDE_FILE, the one way a test learns it. MODE:
  clean      swap only the x-api-key header, only on inject hosts
  log        also write the key it holds to its own log (stderr)
  fragment   also write a slice of the key to its own log
  fragmentbody  put a slice of the key in the body of each /ep/ request
  anyhost    swap the x-api-key header on every allowed host
  noinject   never swap
  drop       refuse every request to an /ep/ path
  crash      exit 7 at once
  noversion  fail the version query
"""

from __future__ import annotations

import http.client
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MODE, SIDE, ARGS = sys.argv[1], Path(sys.argv[2]), sys.argv[3:]


class Swap(BaseHTTPRequestHandler):
    allowed: set[str] = set()
    inject: set[str] = set()
    stand_in = ""
    key = ""

    def do_POST(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if url.hostname not in self.allowed or (MODE == "drop" and url.path.startswith("/ep/")):
            self._reply(403, b"")
            return
        if MODE == "fragmentbody" and url.path.startswith("/ep/"):
            body = body.replace(self.stand_in.encode(), _slice(self.key).encode())
        skip = ("host", "connection", "proxy-connection", "content-length")
        headers = {k: v for k, v in self.headers.items() if k.lower() not in skip}
        swap = url.hostname in self.inject or MODE == "anyhost"
        if swap and MODE != "noinject":
            headers = {
                k: v.replace(self.stand_in, self.key) if k.lower() == "x-api-key" else v
                for k, v in headers.items()
            }
        upstream = http.client.HTTPConnection(url.hostname or "", url.port, timeout=30)
        upstream.request("POST", url.path, body, headers)
        reply = upstream.getresponse()
        self._reply(reply.status, reply.read())

    def _reply(self, status: int, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


def _slice(key: str) -> str:
    """12 characters from the middle of the key's random part."""
    return key[-30:-18]


def sidecar(config: Any) -> None:
    transforms = {t["name"]: t["config"] for t in config["transforms"]}
    allow = transforms["allowlist"]
    Swap.allowed = {*allow["domains"], *(c.split("/")[0] for c in allow["cidrs"])}
    secret = transforms["secrets"]["secrets"][0]
    Swap.key = os.environ[secret["source"]["var"]]
    Swap.stand_in = secret["replace"]["proxy_value"]
    Swap.inject = {rule["host"] for rule in secret["rules"]}
    SIDE.write_text(Swap.key, encoding="utf-8")
    if MODE == "log":
        print(f"fake target holds {Swap.key}", file=sys.stderr, flush=True)
    if MODE == "fragment":
        print(f"fake target token slice {_slice(Swap.key)}", file=sys.stderr, flush=True)
    port = int(config["proxy"]["tunnel_listen"].rsplit(":", 1)[1])
    print("fake proxy listening", file=sys.stderr, flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Swap).serve_forever()


def main() -> int:
    if ARGS[0] in ("--version", "version"):
        if MODE == "noversion":
            return 1
        print("fake-target 1.2.3")
        return 0
    if MODE == "crash":
        return 7
    sidecar(json.loads(Path(ARGS[1]).read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
