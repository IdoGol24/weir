"""`weir-run verify`'s probe, standard library only: it exposes the key it
holds to every sink. `--sidecar PORT COMMAND...` first starts a proxy-style
target with the key and runs the probe through it (docs/verify.md)."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

VAR = "ANTHROPIC_API_KEY"
STAND_IN = "weir-verify-stand-in"
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def probe() -> int:
    held = os.environ.get(VAR, "")
    proxy = urlsplit(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy", ""))
    port = urlsplit(os.environ["CANARY_MOCK_URL"]).port
    span = {"name": "probe", "attributes": [{"key": "probe.held", "value": {"stringValue": held}}]}
    sends = [
        (
            f"http://127.0.0.1:{port}/v1/messages",
            {"model": "probe", "max_tokens": 16, "messages": [{"role": "user", "content": held}]},
        ),
        (
            f"http://localhost:{port}/v1/traces",
            {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]},
        ),
        (f"http://localhost:{port}/ep/outbound", {"held": held}),
    ]
    headers = {"content-type": "application/json", "x-api-key": held}
    failed = 0
    for url, doc in sends:
        conn = http.client.HTTPConnection(proxy.hostname or "", proxy.port, timeout=30)
        try:
            conn.request("POST", url, json.dumps(doc).encode(), headers)
            response = conn.getresponse()
            response.read()
            problem = None if 200 <= response.status < 300 else f"HTTP {response.status}"
        except OSError as exc:
            problem = type(exc).__name__
        finally:
            conn.close()
        if problem:
            failed += 1
            print(f"probe: {urlsplit(url).path} failed ({problem})", file=sys.stderr)
    print(f"probe holds {held}", flush=True)
    print(f"probe holds {held}", file=sys.stderr, flush=True)
    return 1 if failed else 0


def launch(port: int, command: list[str]) -> int:
    env = {k: v for k, v in os.environ.items() if k.upper() not in PROXY_VARIABLES}
    sidecar = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL)
    try:
        for _ in range(300):
            if sidecar.poll() is not None:
                print("probe: the sidecar exited before it listened", file=sys.stderr)
                return 1
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            print("probe: the sidecar never listened", file=sys.stderr)
            return 1
        proxy = f"http://127.0.0.1:{port}"
        env.update({VAR: STAND_IN, "HTTP_PROXY": proxy, "http_proxy": proxy})
        return subprocess.call([sys.executable, __file__], env=env, stdin=subprocess.DEVNULL)
    finally:
        sidecar.terminate()
        try:
            sidecar.wait(timeout=10)
        except subprocess.TimeoutExpired:
            sidecar.kill()
            sidecar.wait()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--sidecar"]:
        sys.exit(launch(int(sys.argv[2]), sys.argv[3:]))
    sys.exit(probe())
