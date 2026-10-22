"""The loopback mock against docs/canary.md ("The boundary", "Runtime
values", "The capture", "The request capture") and the OpenAI and OTLP wire
formats it stands in for. Requests are real HTTP over 127.0.0.1; the
conftest guard refuses any other destination and records the attempt.

The mock records requests; it does not judge them. Whether a value in a
request was exercised or leaked is the judge's call, tested against the
real judge in test_runner_requests.py and packages/weir/tests.
"""

from __future__ import annotations

import base64
import gzip
import http.client
import json
import re
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from _network import NetworkLog
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord, ResourceLogs, ScopeLogs
from opentelemetry.proto.metrics.v1.metrics_pb2 import (
    Gauge,
    Metric,
    NumberDataPoint,
    ResourceMetrics,
    ScopeMetrics,
)
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span

from weir_run.capture import Capture
from weir_run.ledger import Ledger
from weir_run.mock import HOST, Mock
from weir_run.mock.oauth import CREDENTIAL_FORM_FIELDS
from weir_run.shapes import ByteSource, shaped
from weir_run.spec import CredentialField, EndpointSpec, MockSpec, PlacementSpec


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class Rig:
    mock: Mock
    ledger: Ledger
    capture: Capture
    key: str
    search_key: str

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Reply:
        port = int(self.mock.url.rsplit(":", 1)[1])
        conn = http.client.HTTPConnection(HOST, port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return Reply(response.status, dict(response.getheaders()), response.read())
        finally:
            conn.close()

    def post_json(self, path: str, doc: object, headers: dict[str, str] | None = None) -> Reply:
        return self.request(
            "POST",
            path,
            json.dumps(doc).encode(),
            {"Content-Type": "application/json", **(headers or {})},
        )

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.ledger.path.read_text().splitlines()[1:]]

    def evidence(self, placement: str) -> set[str]:
        return {
            r["evidence"]
            for r in self.records()
            if r["type"] == "exercised" and r["placement"] == placement
        }

    def unexpected(self) -> list[str]:
        return [r["id"] for r in self.records() if r["type"] == "unexpected"]

    def requests(self) -> list[dict[str, Any]]:
        """The request capture's records, header checked and dropped."""
        lines = self.capture.requests.read_text(encoding="utf-8").splitlines()
        assert json.loads(lines[0]) == {"schema": "canary-requests/1"}
        return [json.loads(line) for line in lines[1:]]

    def body(self, record: dict[str, Any]) -> bytes:
        return base64.b64decode(record["body"])


PLACEMENTS = (
    PlacementSpec("env.MODEL_KEY", "env", "MODEL_KEY"),
    PlacementSpec("env.SEARCH_KEY", "env", "SEARCH_KEY", provider_host="search.invalid"),
)
SPEC = MockSpec(
    oauth=True,
    model_reply="scripted answer",
    endpoints=(
        EndpointSpec(
            "search",
            (CredentialField("header", "x-api-key"), CredentialField("query", "key")),
            reply='{"results": []}',
            capture=True,
        ),
    ),
)


@pytest.fixture
def rig(tmp_path: Path) -> Generator[Rig]:
    source = ByteSource()
    ledger = Ledger(tmp_path / "ledger.jsonl", source)
    key = ledger.plant("env.MODEL_KEY", "env", shaped(source, "generic")).value
    search_key = ledger.plant("env.SEARCH_KEY", "env", shaped(source, "generic")).value
    capture = Capture(tmp_path / "capture")
    mock = Mock(SPEC, ledger, capture, source)
    mock.start()
    try:
        yield Rig(mock, ledger, capture, key, search_key)
    finally:
        mock.stop()
        ledger.close()


def _all_bytes(tmp_path: Path) -> bytes:
    """Everything the run wrote except the ledger: capture files."""
    return b"".join(
        p.read_bytes() for p in sorted((tmp_path / "capture").rglob("*")) if p.is_file()
    )


# -- the boundary ------------------------------------------------------


def test_the_mock_binds_loopback_only(rig: Rig) -> None:
    assert urlsplit(rig.mock.url).hostname == "127.0.0.1"


def test_connect_to_any_other_host_is_refused_and_recorded(
    rig: Rig, network_log: NetworkLog
) -> None:
    reply = rig.request("CONNECT", "search.invalid:443")
    assert reply.status == 403
    assert rig.mock.egress == {"search.invalid": 1}
    [record] = rig.requests()
    assert {k: record[k] for k in ("outcome", "endpoint", "host", "port", "method")} == {
        "outcome": "connect",
        "endpoint": None,
        "host": "search.invalid",
        "port": 443,
        "method": "CONNECT",
    }
    assert record["path"] is None and record["query"] is None and record["body"] is None
    # Evidence is the judge's to derive from the record, not the mock's.
    assert rig.evidence("env.SEARCH_KEY") == set()
    # The mock never tried to reach, or even resolve, the refused host.
    assert network_log.refused == []


def test_an_absolute_form_request_for_another_host_is_refused(
    rig: Rig, network_log: NetworkLog
) -> None:
    reply = rig.request(
        "POST", "http://api.other.invalid/v1/x", b"{}", {"Authorization": f"Bearer {rig.key}"}
    )
    assert reply.status == 403
    assert rig.mock.egress == {"api.other.invalid": 1}
    assert network_log.refused == []
    # Refused before any endpoint saw it, but recorded whole, body included.
    [record] = rig.requests()
    assert (record["outcome"], record["host"], record["port"]) == (
        "refused",
        "api.other.invalid",
        80,
    )
    assert (record["method"], record["endpoint"]) == ("POST", None)
    assert record["path"] == "http://api.other.invalid/v1/x"
    assert ["Authorization", f"Bearer {rig.key}"] in record["headers"]
    assert rig.body(record) == b"{}"
    assert rig.unexpected() == []


def test_a_refused_request_keeps_its_target_as_received(rig: Rig) -> None:
    # A value can ride in the userinfo or the host itself: both are kept.
    rig.request("GET", "http://user:pw@Exfil.Other.invalid:8080/p%2Fq?x=1")
    rig.request("CONNECT", "[2001:db8::1]:8443")
    refused, connect = rig.requests()
    assert (refused["host"], refused["port"]) == ("Exfil.Other.invalid", 8080)
    assert (refused["path"], refused["query"]) == (
        "http://user:pw@Exfil.Other.invalid:8080/p%2Fq",
        "x=1",
    )
    assert (connect["host"], connect["port"]) == ("2001:db8::1", 8443)


def test_an_absolute_form_request_for_the_mock_itself_is_served(rig: Rig) -> None:
    reply = rig.request("GET", f"{rig.mock.url}/v1/models")
    assert reply.status == 200


def test_unmocked_paths_are_404_and_counted(rig: Rig) -> None:
    assert rig.request("GET", "/nowhere/at/all").status == 404
    assert rig.mock.unmocked == {"GET /nowhere/at/all": 1}
    [record] = rig.requests()
    assert (record["outcome"], record["endpoint"]) == ("served", None)


# -- the request capture -----------------------------------------------


def test_every_served_request_is_recorded_whole(rig: Rig) -> None:
    doc = {"messages": [{"role": "user", "content": "hi"}]}
    rig.post_json("/v1/chat/completions?api-version=1", doc, {"X-Trace": "t1"})
    [record] = rig.requests()
    assert {k: record[k] for k in ("outcome", "endpoint", "host", "port", "method")} == {
        "outcome": "served",
        "endpoint": "model",
        "host": HOST,
        "port": rig.mock.port,
        "method": "POST",
    }
    assert (record["path"], record["query"]) == ("/v1/chat/completions", "api-version=1")
    assert ["X-Trace", "t1"] in record["headers"]
    assert json.loads(rig.body(record)) == doc
    assert record["unread"] is None


@pytest.mark.parametrize(
    ("path", "endpoint"),
    [
        ("/v1/embeddings", "model"),
        ("/v1/traces", "otlp"),
        ("/oauth/token", "oauth"),
        ("/.well-known/openid-configuration", "oauth"),
        ("/ep/search/q", "search"),
        ("/ep/elsewhere/q", None),
    ],
)
def test_each_record_names_the_endpoint_that_answered(
    rig: Rig, path: str, endpoint: str | None
) -> None:
    rig.request("POST", path, b"", {"Content-Type": "application/x-www-form-urlencoded"})
    assert [r["endpoint"] for r in rig.requests()] == [endpoint]


@pytest.mark.parametrize(
    ("target", "declared"),
    [
        ("/v1/embeddings", ()),
        ("/ep/search/q", SPEC.endpoints[0].credential_fields),
        ("/oauth/token", tuple(CredentialField("body", n) for n in CREDENTIAL_FORM_FIELDS)),
        ("/ep/elsewhere/q", ()),
        ("http://collector.other.invalid/x", ()),
    ],
)
def test_each_record_names_the_credential_fields_of_its_destination(
    rig: Rig, target: str, declared: tuple[CredentialField, ...]
) -> None:
    rig.request("POST", target, b"", {"Content-Type": "application/x-www-form-urlencoded"})
    [record] = rig.requests()
    # docs/canary.md, "Runtime values": the auth headers of every request,
    # then what the destination declares.
    auth = [["header", "authorization"], ["header", "proxy-authorization"]]
    assert record["credential_fields"] == auth + [[f.location, f.name] for f in declared]


@pytest.mark.parametrize(
    ("method", "target"),
    [("GET", "http://Search.Host.invalid/q?key={key}"), ("CONNECT", "search.host.invalid:443")],
)
def test_a_refused_request_to_a_provider_host_names_its_endpoints_fields(
    rig: Rig, method: str, target: str
) -> None:
    host_key = rig.ledger.plant(
        "env.HOST_KEY",
        "env",
        shaped(rig.ledger.source, "generic"),
        providers=("search",),
        provider_host="search.HOST.invalid",
    ).value
    assert rig.request(method, target.format(key=host_key)).status == 403
    [record] = rig.requests()
    auth = [["header", "authorization"], ["header", "proxy-authorization"]]
    declared = [[f.location, f.name] for f in SPEC.endpoints[0].credential_fields]
    assert record["credential_fields"] == auth + declared


def test_a_compressed_body_is_recorded_decompressed(rig: Rig) -> None:
    body = json.dumps({"input": "hi"}).encode()
    headers = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    rig.request("POST", "/v1/embeddings", gzip.compress(body), headers)
    [record] = rig.requests()
    assert rig.body(record) == body and record["unread"] is None


def test_a_body_in_an_unknown_encoding_is_recorded_as_received_and_unread(rig: Rig) -> None:
    headers = {"Content-Type": "application/json", "Content-Encoding": "br"}
    assert rig.request("POST", "/v1/embeddings", b"\x0bopaque", headers).status == 415
    [record] = rig.requests()
    assert rig.body(record) == b"\x0bopaque" and record["unread"] == "encoding"


def test_a_body_over_the_limit_is_recorded_unread(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("weir_run.mock.server.MAX_BODY", 8)
    reply = rig.request("POST", "/v1/embeddings", b'{"input": "too long"}')
    assert reply.status == 413
    [record] = rig.requests()
    assert record["body"] is None and record["unread"] == "too_large"


@pytest.mark.parametrize("target", ["/v1/embeddings", "http://collector.other.invalid/x"])
def test_a_request_the_mock_fails_on_is_still_recorded_unread(rig: Rig, target: str) -> None:
    reply = rig.request("POST", target, b"{}", {"Content-Length": "two"})
    assert reply.status == 500 and rig.mock.errors == 1
    [record] = rig.requests()
    assert record["body"] is None and record["unread"] == "error"
    assert record["outcome"] == ("served" if target.startswith("/") else "refused")


def test_bodies_judged_elsewhere_are_not_repeated(rig: Rig) -> None:
    rig.request("POST", "/v1/traces", b"", {"Content-Type": "application/x-protobuf"})
    rig.post_json("/ep/search/runs", {"run": "telemetry body"})
    assert [r["body"] for r in rig.requests()] == [None, None]


# -- credential fields -------------------------------------------------


def test_a_bearer_canary_is_accounted_for(rig: Rig) -> None:
    rig.post_json("/v1/chat/completions", {"messages": []}, {"Authorization": f"Bearer {rig.key}"})
    assert rig.unexpected() == []
    # The mock records the request; the judge attributes the value.
    assert rig.evidence("env.MODEL_KEY") == set()
    assert ["Authorization", f"Bearer {rig.key}"] in rig.requests()[0]["headers"]


def test_a_basic_credential_holding_a_canary_is_accounted_for(rig: Rig) -> None:
    basic = base64.b64encode(f"client:{rig.key}".encode()).decode()
    rig.post_json("/v1/chat/completions", {"messages": []}, {"Authorization": f"Basic {basic}"})
    assert rig.unexpected() == []


def test_an_unaccounted_credential_is_recorded_without_its_value(rig: Rig, tmp_path: Path) -> None:
    stranger = "Zq8RealLookingKey0000000000000000"
    rig.post_json("/v1/chat/completions", {"messages": []}, {"Authorization": f"Bearer {stranger}"})
    assert rig.unexpected() == ["unexpected.model.authorization#1"]
    assert stranger not in rig.ledger.path.read_text()
    # Only the request capture, which holds what the program sent and is
    # deleted with the rest of the capture, has it.
    rig.capture.requests.unlink()
    assert stranger.encode() not in _all_bytes(tmp_path)


def test_declared_fields_are_inspected_and_others_are_not(rig: Rig) -> None:
    reply = rig.request(
        "GET",
        "/ep/search/q?" + urlencode({"key": rig.search_key, "other": "not-a-credential"}),
        headers={"x-api-key": "unaccounted-value-1234", "x-other": "also-not-a-credential"},
    )
    assert reply.status == 200 and reply.json() == {"results": []}
    assert rig.unexpected() == ["unexpected.search.x-api-key#1"]
    assert rig.requests()[0]["query"] == urlencode(
        {"key": rig.search_key, "other": "not-a-credential"}
    )


def test_a_captured_endpoint_body_is_a_swept_file(rig: Rig) -> None:
    rig.post_json("/ep/search/runs", {"run": "telemetry body"})
    files = sorted(p.name for p in rig.capture.swept.iterdir())
    assert len(files) == 1
    assert (rig.capture.swept / files[0]).read_bytes() == json.dumps(
        {"run": "telemetry body"}
    ).encode()


# -- the model API -----------------------------------------------------

WEATHER: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "parameters": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "days": {"type": "integer", "minimum": 1},
                "unit": {"enum": ["c", "f"]},
                "where": {"$ref": "#/$defs/Place"},
                "optional": {"type": "string"},
            },
            "required": ["city", "days", "unit", "where"],
            "$defs": {
                "Place": {
                    "type": "object",
                    "properties": {"lat": {"type": "number"}},
                    "required": ["lat"],
                }
            },
        },
    },
}
LOOKUP: dict[str, Any] = {
    "type": "function",
    "function": {"name": "lookup", "parameters": {"type": "object"}},
}


def _valid(value: Any, schema: dict[str, Any], defs: dict[str, Any]) -> bool:
    """A small JSON Schema check, enough for the shapes the mock fills."""
    if "$ref" in schema:
        return _valid(value, defs[schema["$ref"].rsplit("/", 1)[-1]], defs)
    if "enum" in schema:
        return value in schema["enum"]
    kind = schema.get("type", "object" if "properties" in schema else None)
    if kind == "object":
        if not isinstance(value, dict):
            return False
        obj = cast(dict[str, Any], value)
        props: dict[str, Any] = schema.get("properties", {})
        return all(k in obj for k in schema.get("required", [])) and all(
            _valid(v, props.get(k, {}), defs) for k, v in obj.items()
        )
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and value >= schema.get("minimum", value)
    if kind == "number":
        return isinstance(value, int | float)
    return kind is None


def test_turn_one_calls_every_offered_tool_with_schema_valid_arguments(rig: Rig) -> None:
    reply = rig.post_json(
        "/v1/chat/completions",
        {"model": "m", "messages": [{"role": "user", "content": "hi"}], "tools": [WEATHER, LOOKUP]},
    ).json()
    choice = reply["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    calls = choice["message"]["tool_calls"]
    assert [c["function"]["name"] for c in calls] == ["get_weather", "lookup"]
    for call, tool in zip(calls, [WEATHER, LOOKUP], strict=True):
        params = tool["function"]["parameters"]
        assert _valid(json.loads(call["function"]["arguments"]), params, params.get("$defs", {}))


def test_turn_two_answers_with_the_scripted_reply(rig: Rig) -> None:
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "tool_calls": [{"id": "c1"}]},
        {"role": "tool", "tool_call_id": "c1", "content": "{}"},
    ]
    reply = rig.post_json("/v1/chat/completions", {"messages": messages, "tools": [LOOKUP]}).json()
    assert reply["choices"][0]["message"]["content"] == SPEC.model_reply
    assert reply["choices"][0]["finish_reason"] == "stop"


def _sse(body: bytes) -> list[Any]:
    data = [line[6:] for line in body.decode().splitlines() if line.startswith("data: ")]
    return [json.loads(d) if d != "[DONE]" else d for d in data]


def test_chat_streaming_follows_the_chunk_protocol(rig: Rig) -> None:
    reply = rig.post_json(
        "/v1/chat/completions",
        {
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
            "stream_options": {"include_usage": True},
        },
    )
    assert reply.headers["Content-Type"] == "text/event-stream"
    events = _sse(reply.body)
    assert events[-1] == "[DONE]"
    chunks = events[:-1]
    text = "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks if c["choices"])
    assert text == SPEC.model_reply
    assert chunks[-1]["choices"] == [] and chunks[-1]["usage"]["total_tokens"] > 0


def test_chat_streaming_tool_calls(rig: Rig) -> None:
    reply = rig.post_json(
        "/v1/chat/completions",
        {"messages": [{"role": "user", "content": "hi"}], "tools": [LOOKUP], "stream": True},
    )
    deltas = [e["choices"][0]["delta"] for e in _sse(reply.body)[:-1] if e["choices"]]
    names = [tc["function"]["name"] for d in deltas for tc in d.get("tool_calls", [])]
    assert names == ["lookup"]


def test_responses_api_calls_tools_then_answers(rig: Rig) -> None:
    tool = {"type": "function", "name": "lookup", "parameters": {"type": "object"}}
    first = rig.post_json("/v1/responses", {"input": "hi", "tools": [tool]}).json()
    assert [o["type"] for o in first["output"]] == ["function_call"]
    call_id = first["output"][0]["call_id"]
    second = rig.post_json(
        "/v1/responses",
        {
            "input": [
                {"role": "user", "content": "hi"},
                first["output"][0],
                {"type": "function_call_output", "call_id": call_id, "output": "{}"},
            ],
            "tools": [tool],
        },
    ).json()
    assert second["output"][0]["content"][0]["text"] == SPEC.model_reply


def test_responses_streaming_ends_with_the_completed_response(rig: Rig) -> None:
    body = rig.post_json("/v1/responses", {"input": "hi", "stream": True}).body
    events = _sse(body)
    names = re.findall(r"^event: (\S+)$", body.decode(), re.MULTILINE)
    assert names == [e["type"] for e in events]
    assert [e["sequence_number"] for e in events] == list(range(len(events)))
    deltas = "".join(e["delta"] for e in events if e["type"] == "response.output_text.delta")
    assert deltas == SPEC.model_reply
    assert events[-1]["type"] == "response.completed"


@pytest.mark.parametrize("encoding", ["float", "base64"])
def test_embeddings_one_vector_per_input(rig: Rig, encoding: str) -> None:
    reply = rig.post_json(
        "/v1/embeddings", {"input": ["a", "b"], "encoding_format": encoding}
    ).json()
    assert [d["index"] for d in reply["data"]] == [0, 1]


def test_models(rig: Rig) -> None:
    listed = rig.request("GET", "/v1/models").json()["data"]
    assert listed and rig.request("GET", f"/v1/models/{listed[0]['id']}").status == 200


# -- OAuth -------------------------------------------------------------


def _form(
    rig: Rig, path: str, fields: dict[str, str], headers: dict[str, str] | None = None
) -> Reply:
    return rig.request(
        "POST",
        path,
        urlencode(fields).encode(),
        {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
    )


def _placement_values(rig: Rig) -> dict[str, str]:
    return {r["id"]: r["value"] for r in rig.records() if r["type"] == "placement"}


def test_every_issued_token_is_ledgered_before_the_reply(rig: Rig) -> None:
    reply = _form(
        rig,
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": "", "scope": "openid x"},
    ).json()
    values = _placement_values(rig)
    issued = {k: v for k, v in reply.items() if k in ("access_token", "refresh_token", "id_token")}
    assert set(issued) == {"access_token", "refresh_token", "id_token"}
    for token, value in issued.items():
        assert values[f"runtime.oauth.{token}#1"] == value
        assert rig.evidence(f"runtime.oauth.{token}#1") == {"minted"}
    # Non-credential reply fields are never ledgered, and an empty
    # credential field is no credential at all.
    assert reply["token_type"] not in values.values()
    assert rig.unexpected() == []


def test_the_id_token_is_a_jwt_for_the_client(rig: Rig) -> None:
    reply = _form(
        rig,
        "/oauth/token",
        {"grant_type": "client_credentials", "client_id": "app", "scope": "openid"},
    ).json()
    header, payload, _ = reply["id_token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["aud"] == "app" and claims["iss"] == rig.mock.url
    assert json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["typ"] == "JWT"


def test_authorization_code_flow(rig: Rig) -> None:
    redirect = rig.request(
        "GET",
        "/oauth/authorize?"
        + urlencode({"redirect_uri": "http://127.0.0.1:9/cb?a=1", "state": "s1"}),
    )
    assert redirect.status == 302
    query = parse_qs(urlsplit(redirect.headers["Location"]).query)
    assert query["state"] == ["s1"] and query["a"] == ["1"]
    code = query["code"][0]
    assert _placement_values(rig)["runtime.oauth.code#1"] == code
    tokens = _form(rig, "/oauth/token", {"grant_type": "authorization_code", "code": code}).json()
    # Redeeming the code is a request carrying a ledger value: accounted for.
    assert rig.evidence("runtime.oauth.code#1") == {"minted"}
    assert "refresh_token" in tokens and rig.unexpected() == []


def test_device_flow(rig: Rig) -> None:
    device = _form(rig, "/oauth/device_authorization", {"client_id": "app"}).json()
    assert _placement_values(rig)["runtime.oauth.device_code#1"] == device["device_code"]
    assert device["user_code"] not in _placement_values(rig).values()
    grant = "urn:ietf:params:oauth:grant-type:device_code"
    tokens = _form(rig, "/oauth/token", {"grant_type": grant, "device_code": device["device_code"]})
    assert tokens.status == 200
    assert rig.evidence("runtime.oauth.device_code#1") == {"minted"}
    assert rig.unexpected() == []


@pytest.mark.parametrize("field", CREDENTIAL_FORM_FIELDS)
def test_oauth_form_credential_fields(rig: Rig, field: str) -> None:
    _form(rig, "/oauth/token", {"grant_type": "client_credentials", field: rig.key})
    assert rig.unexpected() == []
    _form(rig, "/oauth/token", {"grant_type": "client_credentials", field: "unknown-credential-1"})
    assert rig.unexpected() == [f"unexpected.oauth.{field}#1"]


def test_pkce_verifier_is_not_a_credential_field(rig: Rig) -> None:
    _form(rig, "/oauth/token", {"grant_type": "client_credentials", "code_verifier": "v" * 43})
    assert rig.unexpected() == []


def test_client_secret_basic_auth_holding_a_canary(rig: Rig) -> None:
    basic = base64.b64encode(f"app:{rig.key}".encode()).decode()
    reply = _form(
        rig,
        "/oauth/token",
        {"grant_type": "client_credentials"},
        {"Authorization": f"Basic {basic}"},
    )
    assert reply.status == 200 and rig.unexpected() == []


def test_discovery_metadata_points_at_the_mock(rig: Rig) -> None:
    meta = rig.request("GET", "/.well-known/openid-configuration").json()
    assert meta["token_endpoint"] == rig.mock.url + "/oauth/token"


def test_unknown_grant_is_refused(rig: Rig) -> None:
    assert _form(rig, "/oauth/token", {"grant_type": "magic"}).status == 400


# -- the OTLP receiver -------------------------------------------------


def _span_export() -> ExportTraceServiceRequest:
    span = Span(
        trace_id=bytes(range(16)),
        span_id=bytes(range(8)),
        parent_span_id=bytes(range(8, 16)),
        name="execute_tool lookup",
        attributes=[KeyValue(key="traceId", value=AnyValue(string_value="attribute, not an id"))],
    )
    return ExportTraceServiceRequest(
        resource_spans=[ResourceSpans(scope_spans=[ScopeSpans(spans=[span])])]
    )


def _lines(rig: Rig, signal: str) -> list[dict[str, Any]]:
    path = rig.capture.otlp / f"{signal}.jsonl"
    data = path.read_bytes()
    assert data.endswith(b"\n")
    return [json.loads(line) for line in data.splitlines()]


@pytest.mark.parametrize("compress", [False, True])
def test_protobuf_spans_become_one_otlp_json_line(rig: Rig, compress: bool) -> None:
    export = _span_export()
    body = export.SerializeToString()
    headers = {"Content-Type": "application/x-protobuf"}
    if compress:
        body, headers["Content-Encoding"] = gzip.compress(body), "gzip"
    reply = rig.request("POST", "/v1/traces", body, headers)
    assert reply.status == 200
    [line] = _lines(rig, "traces")
    span = line["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    source = export.resource_spans[0].scope_spans[0].spans[0]
    assert span["traceId"] == source.trace_id.hex()
    assert span["spanId"] == source.span_id.hex()
    assert span["parentSpanId"] == source.parent_span_id.hex()
    assert span["name"] == source.name
    # An attribute named like an id field is content, not an id.
    assert span["attributes"][0] == {
        "key": "traceId",
        "value": {"stringValue": "attribute, not an id"},
    }


def test_json_bodies_are_written_as_one_line(rig: Rig) -> None:
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "a\nb"}]}]}]}
    reply = rig.request(
        "POST",
        "/v1/traces",
        json.dumps(doc, indent=2).encode(),
        {"Content-Type": "application/json"},
    )
    assert reply.status == 200 and reply.body == b"{}"
    assert _lines(rig, "traces") == [doc]


def test_logs_and_metrics_are_received(rig: Rig) -> None:
    logs = ExportLogsServiceRequest(
        resource_logs=[
            ResourceLogs(
                scope_logs=[ScopeLogs(log_records=[LogRecord(body=AnyValue(string_value="hello"))])]
            )
        ]
    )
    point = NumberDataPoint(as_double=1.0)
    metrics = ExportMetricsServiceRequest(
        resource_metrics=[
            ResourceMetrics(
                scope_metrics=[
                    ScopeMetrics(metrics=[Metric(name="m", gauge=Gauge(data_points=[point]))])
                ]
            )
        ]
    )
    headers = {"Content-Type": "application/x-protobuf"}
    assert rig.request("POST", "/v1/logs", logs.SerializeToString(), headers).status == 200
    assert rig.request("POST", "/v1/metrics", metrics.SerializeToString(), headers).status == 200
    log_line = _lines(rig, "logs")[0]
    assert log_line["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"] == {
        "stringValue": "hello"
    }
    assert (
        _lines(rig, "metrics")[0]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["name"]
        == "m"
    )


def test_an_empty_export_still_names_its_signal(rig: Rig) -> None:
    rig.request("POST", "/v1/traces", b"", {"Content-Type": "application/x-protobuf"})
    assert _lines(rig, "traces") == [{"resourceSpans": []}]


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b"\xff\xff\xff not protobuf", {"Content-Type": "application/x-protobuf"}),
        (
            b"not gzip at all",
            {"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"},
        ),
        (b"{not json", {"Content-Type": "application/json"}),
    ],
)
def test_an_undecodable_body_is_swept_and_marks_the_run_incomplete(
    rig: Rig, body: bytes, headers: dict[str, str]
) -> None:
    assert rig.request("POST", "/v1/traces", body, headers).status == 400
    [marker] = _lines(rig, "traces")
    assert not {"resourceSpans", "resourceLogs", "resourceMetrics"} & set(marker)
    assert (rig.capture.swept / marker["undecodable"]).read_bytes() == body


def test_otlp_request_headers_go_to_the_request_capture_only(rig: Rig, tmp_path: Path) -> None:
    rig.request(
        "POST",
        "/v1/traces",
        _span_export().SerializeToString(),
        {"Content-Type": "application/x-protobuf", "Authorization": f"Bearer {rig.key}"},
    )
    assert rig.unexpected() == []
    [record] = rig.requests()
    assert ["Authorization", f"Bearer {rig.key}"] in record["headers"]
    rig.capture.requests.unlink()
    assert rig.key.encode() not in _all_bytes(tmp_path)
