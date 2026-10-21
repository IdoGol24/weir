"""A synthetic agent flow for the canary runner's demo. Not a real framework.

It does what an instrumented agent does, with the standard library and the
OTLP protobuf messages only:

1. gets an access token from its OAuth provider (client credentials, with
   the client secret its code passes explicitly);
2. asks the model, which calls the `web_search` tool;
3. calls the search API with its key and the access token;
4. sends the tool result back and gets the answer;
5. exports its spans over OTLP/HTTP (gzip-compressed protobuf).

Every URL comes from the environment the runner sets, so every request
lands on the runner's loopback mock. With DEMO_LEAK=1 the flow makes three
classic telemetry mistakes: it records the search key as a span attribute
and prints it in a debug line, records its HTTP Basic client credentials
(the client secret, base64-encoded), and records the outgoing request
headers as a JSON string holding the access token.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Any

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span

LEAK = os.environ.get("DEMO_LEAK") == "1"


def call(url: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read() or b"{}")


def chat(messages: list[dict[str, Any]], api_key: str) -> dict[str, Any]:
    tool = {
        "type": "function",
        "function": {
            "name": "web_search",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    }
    body = json.dumps({"model": "demo-model", "messages": messages, "tools": [tool]}).encode()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    reply = call(f"{os.environ['OPENAI_BASE_URL']}/chat/completions", body, headers)
    return reply["choices"][0]["message"]


def attribute(key: str, value: str) -> KeyValue:
    return KeyValue(key=key, value=AnyValue(string_value=value))


def main() -> None:
    mock = os.environ["CANARY_MOCK_URL"]
    openai_key = os.environ["OPENAI_API_KEY"]
    search_key = os.environ["SEARCH_API_KEY"]
    # The code placement: the flow reads it and passes it explicitly.
    client_secret = os.environ["CANARY_CODE_AUTH_CLIENT_SECRET"]

    form = {"grant_type": "client_credentials", "client_id": "demo-agent"}
    form["client_secret"] = client_secret
    token = call(f"{mock}/oauth/token", urllib.parse.urlencode(form).encode())["access_token"]

    messages: list[dict[str, Any]] = [{"role": "user", "content": "What is weir?"}]
    first = chat(messages, openai_key)
    tool_call = first["tool_calls"][0]
    query = json.loads(tool_call["function"]["arguments"])["query"]

    search_headers = {"x-api-key": search_key, "Authorization": f"Bearer {token}"}
    url = f"{os.environ['SEARCH_BASE_URL']}/search?" + urllib.parse.urlencode({"q": query})
    results = call(url, headers=search_headers)

    messages += [
        first,
        {"role": "tool", "tool_call_id": tool_call["id"], "content": json.dumps(results)},
    ]
    answer = chat(messages, openai_key)["content"]
    print(f"answer: {answer}")

    tool_span = Span(
        trace_id=bytes(range(1, 17)),
        span_id=bytes(range(1, 9)),
        name="execute_tool web_search",
        attributes=[attribute("gen_ai.tool.name", "web_search"), attribute("app.query", query)],
    )
    agent_span = Span(
        trace_id=bytes(range(1, 17)),
        span_id=bytes(range(9, 17)),
        name="invoke_agent demo",
        attributes=[attribute("gen_ai.response.text", answer)],
    )
    if LEAK:
        print(f"debug: search key {search_key}", file=sys.stderr)
        basic = base64.b64encode(f"demo-agent:{client_secret}".encode()).decode()
        tool_span.attributes.extend(
            [
                attribute("http.request.header.x-api-key", search_key),
                attribute("app.auth.client", f"Basic {basic}"),
                attribute("app.request.headers", json.dumps(search_headers)),
            ]
        )
    export = ExportTraceServiceRequest(
        resource_spans=[ResourceSpans(scope_spans=[ScopeSpans(spans=[agent_span, tool_span])])]
    )
    call(
        os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"],
        gzip.compress(export.SerializeToString()),
        {"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"},
    )


if __name__ == "__main__":
    main()
