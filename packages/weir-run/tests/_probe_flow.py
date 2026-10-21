"""A probe flow for the runner's tests: plain urllib, talks to the mock only.

It sends its canary APP_KEY to the mock's model API as a bearer token,
exports one span over OTLP/JSON, and writes the canary to SIDE_FILE so the
test can check the runner's output against it. MODE changes what it does:
`leak` puts the canary in the span name, `print` prints it raw on stdout
and inside a base64 Basic credential on stderr, `crash` exits 5.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.request


def post(url: str, body: bytes, headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def main() -> None:
    key = os.environ["APP_KEY"]
    with open(os.environ["SIDE_FILE"], "w", encoding="utf-8") as side:
        side.write(key)
    mode = os.environ.get("MODE", "")
    post(
        os.environ["CANARY_MOCK_URL"] + "/v1/chat/completions",
        b"{}",
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    name = f"leaky span {key}" if mode == "leak" else "clean span"
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": name}]}]}]}
    post(
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
        json.dumps(doc).encode(),
        {"Content-Type": "application/json"},
    )
    if mode == "print":
        print("raw", key)
        print("b64", base64.b64encode(f"u:{key}".encode()).decode(), file=sys.stderr)
    if mode == "crash":
        sys.exit(5)


if __name__ == "__main__":
    main()
