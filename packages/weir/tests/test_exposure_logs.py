"""The exposure scan reads OTLP log records as well as spans: a key in a log
record's attributes, its body or the resource and scope around it is found,
graded and printed under the same rules as one in a span, and named as a log
record. Every value here is fake."""

import base64
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from weir._text_safety import plural
from weir.adapters.otel import REMEDIATION, decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG, class_prefix
from weir.cli.main import main
from weir.exposure import classify_exposure
from weir.gauge import exposure_gauge_lines

_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"


def _attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def _logs(records, resource=None, scope=None, *, keys=("resourceLogs", "scopeLogs", "logRecords")):
    resource_list, scope_list, record_list = keys
    return {resource_list: [{
        "resource": {"attributes": resource or []},
        scope_list: [{"scope": {"name": "app", "attributes": scope or []},
                      record_list: records}],
    }]}


def _spans(spans):
    return {"resourceSpans": [{"scopeSpans": [{"scope": {"name": "app"}, "spans": spans}]}]}


def _scan(document) -> list:
    return classify_exposure(
        scan_surface(decode_input(json.dumps(document).encode())), DEFAULT_CATALOG
    ).hits


def _run(args, body: str):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(body, encoding="utf-8")
        return runner.invoke(main, [*args, "export.json"])


def _assert_value_not_printed(output: str, value: str) -> None:
    # The printing rule: the class head and the last four characters at most,
    # so no 6 characters of the value past its class head ever appear.
    body = value[len(class_prefix(value)):]
    for start in range(len(body) - 5):
        assert body[start:start + 6] not in output, body[start:start + 6]


_PLACES = {
    "attribute": (
        _logs([{"attributes": [_attr("acme.client", f"Client(api_key='{_KEY}')")]}]),
        "attributes.acme.client",
    ),
    "string body": (
        _logs([{"body": {"stringValue": f"calling the model with {_KEY}"}}]),
        "body",
    ),
    "structured body": (
        _logs([{"body": {"kvlistValue": {"values": [_attr("api_key", _KEY)]}}}]),
        "body.api_key",
    ),
    "nested body": (
        _logs([{"body": {"kvlistValue": {"values": [{"key": "request", "value": {
            "arrayValue": {"values": [{"stringValue": "ok"}, {"stringValue": _KEY}]}}}]}}}]),
        "body.request[1]",
    ),
    "resource attribute": (
        _logs([{"body": {"stringValue": "started"}}], resource=[_attr("acme.boot", _KEY)]),
        "resource.attributes.acme.boot",
    ),
    "scope attribute": (
        _logs([{"body": {"stringValue": "started"}}], scope=[_attr("acme.cfg", _KEY)]),
        "scope.attributes.acme.cfg",
    ),
}


@pytest.mark.parametrize("place", sorted(_PLACES))
def test_a_key_in_a_log_record_fails_the_scan_and_names_the_log_record(place: str) -> None:
    document, location = _PLACES[place]
    result = _run(["scan"], json.dumps(document))
    assert result.exit_code == 1, result.output
    assert "in 1 location across 1 log record" in result.output
    assert f"  log record 0  {location}  " in result.output
    assert " span" not in result.output.split("\n0 verdict-grade")[0]
    _assert_value_not_printed(result.output, _KEY)


@pytest.mark.parametrize("place", sorted(_PLACES))
def test_a_log_record_hit_carries_its_index_and_no_span(place: str) -> None:
    document, location = _PLACES[place]
    [hit] = [h for h in _scan(document) if h.eligible]
    assert (hit.log_record, hit.span_ref, hit.span_name, hit.location) == (0, "", "", location)


def test_log_records_are_numbered_in_input_order_across_batches() -> None:
    first = _logs([{"body": {"stringValue": "a"}}, {"body": {"stringValue": _KEY}}])
    second = _logs([{"attributes": [_attr("k", _KEY)]}])
    data = json.dumps(first) + "\n" + json.dumps(second) + "\n"
    surface = scan_surface(decode_input(data.encode()))
    assert surface.log_records_scanned == 3
    hits = classify_exposure(surface, DEFAULT_CATALOG).hits
    assert [(h.log_record, h.location) for h in hits] == [(1, "body"), (2, "attributes.k")]


def test_snake_case_log_keys_are_read() -> None:
    document = _logs([{"body": {"stringValue": _KEY}}],
                     keys=("resource_logs", "scope_logs", "log_records"))
    assert [h.location for h in _scan(document)] == ["body"]


def test_an_authorization_header_attribute_on_a_log_record_is_read_as_a_header() -> None:
    token = "Bearer " + "Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4Qh7Rk2"
    document = _logs([{"attributes": [_attr("http.request.header.authorization", token)]}])
    [hit] = _scan(document)
    assert (hit.source_class, hit.eligible) == ("bearer_token", True)


def test_a_clean_logs_payload_stays_clean() -> None:
    records = [
        {"severityText": "INFO", "body": {"stringValue": "request served"},
         "attributes": [_attr("http.route", "/v1/chat")]},
        {"body": {"kvlistValue": {"values": [_attr("user", "u-1")]}}},
    ]
    body = json.dumps(_logs(records, resource=[_attr("service.name", "agent")]))
    scan = _run(["scan"], body)
    assert scan.exit_code == 0, scan.output
    assert scan.output == "0 verdict-grade findings\n"
    gauge = _run(["gauge"], body)
    assert gauge.exit_code == 0, gauge.output
    # Every string the payload holds, each value, each key, the scope name
    # and the severityText, is on the surface, read off the payload.
    strings = sum(body.count(f'"{field}"') for field in ("stringValue", "key", "name",
                                                          "severityText"))
    assert len(scan_surface(decode_input(body.encode())).strings) == strings
    assert (f"exposure scan: 0 spans, {len(records)} log records, {strings} strings"
            " - no credential-shaped values") in gauge.output


def test_a_mixed_export_reads_both_signals() -> None:
    span = {"spanId": "aa" * 8, "name": "crew.agent",
            "attributes": [_attr("acme.agent.llm", _KEY)]}
    log = {"attributes": [_attr("acme.client", _KEY)]}
    jsonl = json.dumps(_spans([span])) + "\n" + json.dumps(_logs([log])) + "\n"
    one_document = json.dumps({**_spans([span]), **_logs([log])})
    for body in (jsonl, one_document):
        result = _run(["scan"], body)
        assert result.exit_code == 1, result.output
        assert "in 2 locations across 1 span and 1 log record" in result.output
        assert f"  crew.agent ({'aa' * 4})  attributes.acme.agent.llm  " in result.output
        assert "  log record 0  attributes.acme.client  " in result.output
        _assert_value_not_printed(result.output, _KEY)


def test_a_key_name_match_in_a_log_record_goes_to_the_review_queue() -> None:
    body = json.dumps(_logs([{"body": {"stringValue": "password='hunter2-hunter2'"}}]))
    result = _run(["scan"], body)
    assert result.exit_code == 0, result.output
    assert "review queue: 1 credential-shaped match (credential_field)" in result.output
    assert re.search(r"^  log record 0  body  password$", result.output, re.MULTILINE)


def test_the_html_report_names_the_log_record() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(json.dumps(_PLACES["string body"][0]), encoding="utf-8")
        result = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        html = Path("r.html").read_text(encoding="utf-8")
    assert result.exit_code == 1
    assert "openai_api_key present in body of log record 0" in html
    _assert_value_not_printed(html, _KEY)


_METRICS = {"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "m"}]}]}]}


@pytest.mark.parametrize("shape", ["separate line", "same document"])
def test_a_payload_weir_cannot_read_is_reported_as_not_scanned(shape: str) -> None:
    logs = _logs([{"body": {"stringValue": "fine"}}])
    if shape == "separate line":
        body = json.dumps(logs) + "\n" + json.dumps(_METRICS) + "\n"
    else:
        body = json.dumps({**logs, **_METRICS})
    surface = scan_surface(decode_input(body.encode()))
    assert surface.batches_not_scanned == 1
    line = ("exposure scan: data in 1 batch not scanned - only spans and log records"
            " are read, not metrics or other data")
    # Unread data never passes clean: scan is incomplete, gauge just says so.
    for command, code in (("scan", 3), ("gauge", 0)):
        result = _run([command], body)
        assert result.exit_code == code, result.output
        assert line in result.output.splitlines(), result.output


def test_a_traces_only_export_reports_nothing_unscanned() -> None:
    body = json.dumps(_spans([{"spanId": "aa" * 8, "attributes": [_attr("k", "v")]}]))
    assert scan_surface(decode_input(body.encode())).batches_not_scanned == 0
    assert "not scanned" not in _run(["gauge"], body).output


def _report(body: str, code: int = 0) -> tuple[str, str]:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(body, encoding="utf-8")
        result = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        assert result.exit_code == code, result.output
        return result.output, Path("r.html").read_text(encoding="utf-8")


_CLEAN_SPANS = _spans([{"spanId": "aa" * 8, "attributes": [_attr("k", "v")]}])


@pytest.mark.parametrize("shape", ["separate line", "same document"])
def test_the_html_report_says_what_was_not_scanned(shape: str) -> None:
    if shape == "separate line":
        body = json.dumps(_CLEAN_SPANS) + "\n" + json.dumps(_METRICS) + "\n"
    else:
        body = json.dumps({**_CLEAN_SPANS, **_METRICS})
    output, html = _report(body, code=3)
    printed = [line for line in output.splitlines() if "not scanned" in line]
    assert len(printed) == 1, output
    assert f"<div>{printed[0]}</div>" in html


def test_a_traces_only_html_report_says_nothing_unscanned() -> None:
    _, html = _report(json.dumps(_CLEAN_SPANS))
    assert "not scanned" not in html
    assert "0 verdict-grade findings" in html


def test_the_same_key_at_the_same_path_in_a_span_and_a_log_record_is_two_locations() -> None:
    span = {"spanId": "aa" * 8, "name": "crew.agent", "attributes": [_attr("cfg", _KEY)]}
    body = json.dumps({**_spans([span]), **_logs([{"attributes": [_attr("cfg", _KEY)]}])})
    result = _run(["scan"], body)
    assert result.exit_code == 1, result.output
    assert "in 2 locations across 1 span and 1 log record" in result.output
    assert f"  crew.agent ({'aa' * 4})  attributes.cfg  " in result.output
    assert "  log record 0  attributes.cfg  " in result.output


def _snake(key, value):
    return {"key": key, "value": {"string_value": value}}


_SNAKE_BODIES = {
    "string_value": ({"string_value": _KEY}, "body"),
    "kvlist_value": ({"kvlist_value": {"values": [_snake("api_key", _KEY)]}}, "body.api_key"),
    "array_value": ({"array_value": {"values": [{"string_value": _KEY}]}}, "body[0]"),
}


@pytest.mark.parametrize("wrapper", sorted(_SNAKE_BODIES))
def test_a_proto_name_logs_export_is_read_wrappers_and_structure_alike(wrapper: str) -> None:
    # Protojson written with proto field names: snake_case all the way down.
    body, location = _SNAKE_BODIES[wrapper]
    document = {"resource_logs": [{
        "resource": {"attributes": [_snake("acme.boot", _KEY)]},
        "scope_logs": [{"scope": {"name": "app"}, "log_records": [{
            "time_unix_nano": "1767225600000000000", "severity_text": "INFO",
            "body": body, "attributes": [_snake("acme.client", _KEY)]}]}],
    }]}
    hits = _scan(document)
    assert sorted((h.log_record, h.location) for h in hits if h.eligible) == sorted(
        [(0, "attributes.acme.client"), (0, location), (0, "resource.attributes.acme.boot")])
    result = _run(["scan"], json.dumps(document))
    assert result.exit_code == 1, result.output
    _assert_value_not_printed(result.output, _KEY)


def _b64(data: bytes, *, urlsafe: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(data) if urlsafe else base64.b64encode(data)
    return encoded.decode("ascii").rstrip("=") if urlsafe else encoded.decode("ascii")


@pytest.mark.parametrize(
    ("record", "location"),
    [
        ({"body": {"bytesValue": _b64(f"key={_KEY}".encode())}}, "body"),
        ({"attributes": [{"key": "raw", "value": {
            "bytes_value": _b64(_KEY.encode(), urlsafe=True)}}]}, "attributes.raw"),
    ],
    ids=["body", "attribute"],
)
def test_a_utf8_bytes_value_is_decoded_and_scanned(record, location) -> None:
    [hit] = _scan(_logs([record]))
    assert (hit.location, hit.eligible) == (location, True)


_NOT_SCANNED_LINE = "exposure scan: 1 value not scanned - not in a shape the scan reads"


def _nested_body(depth: int) -> dict:
    value: dict = {"stringValue": _KEY}
    for _ in range(depth):
        value = {"kvlistValue": {"values": [{"key": "n", "value": value}]}}
    return value


# Each holds exactly one value the scan cannot read, and nothing it can.
_UNREADABLE = {
    "bytes that are not UTF-8": _logs([{"body": {"bytesValue": _b64(b"\xff\xfe\xfa" * 8)}}]),
    "bytes that are not base64": _logs([{"body": {"bytesValue": "not base64 at all!"}}]),
    "a body that is a plain map": _logs([{"body": {"text": _KEY}}]),
    "attributes given as a map": _logs([{"attributes": {"acme.client": _KEY}}]),
    "a kvlist given as a list": _logs([{"body": {"kvlistValue": [_attr("api_key", _KEY)]}}]),
    "a log record that is a string": _logs([f"calling with {_KEY}"]),
    "log records given as an object": _logs({"0": {"body": {"stringValue": _KEY}}}),
    "scope logs given as an object": {"resourceLogs": [{"scopeLogs": {"logRecords": []}}]},
    "a body nested past the depth cap": _logs([{"body": _nested_body(300)}]),
    "a resource that is not an object": {"resourceLogs": [{
        "resource": f"service {_KEY}", "scopeLogs": [{"logRecords": []}]}]},
    "resource attributes given as a map": {"resourceLogs": [{
        "resource": {"attributes": {"acme.boot": _KEY}}, "scopeLogs": [{"logRecords": []}]}]},
}


@pytest.mark.parametrize("shape", sorted(_UNREADABLE))
def test_a_value_the_scan_cannot_read_is_reported_as_not_scanned(shape: str) -> None:
    body = json.dumps(_UNREADABLE[shape])
    assert scan_surface(decode_input(body.encode())).values_not_scanned == 1
    for command, code in (("scan", 3), ("gauge", 0)):
        result = _run([command], body)
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            result.exception)
        assert result.exit_code == code, result.output
        assert _NOT_SCANNED_LINE in result.output.splitlines(), result.output
    _, html = _report(body, code=3)
    assert f"<div>{_NOT_SCANNED_LINE}</div>" in html


def test_a_plain_string_body_is_read_as_the_body() -> None:
    [hit] = _scan(_logs([{"body": f"calling the model with {_KEY}"}]))
    assert (hit.log_record, hit.location, hit.eligible) == (0, "body", True)


def test_a_deep_body_within_the_cap_is_still_found() -> None:
    hits = _scan(_logs([{"body": _nested_body(40)}]))
    assert [h.location for h in hits] == ["body" + ".n" * 40]


# Span reading is unchanged by log support: each of these shapes, put in a
# span-only export, reads exactly the values the same export without it
# reads. What it holds is counted as not scanned, so `weir scan` exits 3.
_SPAN_SHAPES = {
    "a snake_case value wrapper": {"attributes": [_snake("acme.agent.llm", _KEY)]},
    "a bytes value": {"attributes": [
        {"key": "raw", "value": {"bytesValue": _b64(_KEY.encode())}}]},
    "an attribute value that is a string": {"attributes": [{"key": "k", "value": _KEY}]},
    "a malformed event and status": {"events": ["x", {"attributes": "y"}], "status": "z"},
    "a span that fails to decode": {"attributes": f"bogus {_KEY}"},
    "a scope that fails to decode": {"scope": {"name": 7}},
}


@pytest.mark.parametrize("shape", sorted(_SPAN_SHAPES))
def test_a_span_only_export_reads_as_it_did_before_log_support(shape: str) -> None:
    clean = {"spanId": "bb" * 8, "name": "crew.tool", "attributes": [_attr("k", "v")]}
    plain = _spans([clean])
    fields = dict(_SPAN_SHAPES[shape])
    scope = fields.pop("scope", {"name": "app"})
    shaped = {"resourceSpans": [{"scopeSpans": [{"scope": scope, "spans": [
        clean, {"spanId": "aa" * 8, "name": "crew.agent", **fields}]}]}]}
    surface = scan_surface(decode_input(json.dumps(shaped).encode()))
    expected = scan_surface(decode_input(json.dumps(plain).encode()))
    assert surface.values_not_scanned > expected.values_not_scanned == 0
    # The values read: the extra span's name, its scope's name and the keys
    # are strings of their own.
    names = {("name",), ("scope", "name")}
    values = [s.text for s in surface.strings if not s.key and s.path not in names]
    assert values == [s.text for s in expected.strings if not s.key and s.path not in names]
    scan, control = _run(["scan"], json.dumps(shaped)), _run(["scan"], json.dumps(plain))
    assert (scan.exit_code, control.exit_code) == (3, 0)
    unread = f"exposure scan: {plural(surface.values_not_scanned, 'value')} not scanned"
    assert [ln for ln in scan.output.splitlines() if "not scanned" in ln] == [
        f"{unread} - not in a shape the scan reads"]
    read = [ln for ln in scan.output.splitlines()
            if "not scanned" not in ln and not ln.startswith("incomplete: ")]
    assert read == control.output.splitlines()


_REPO = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "fixture",
    sorted(p.name for p in (_REPO / "fixtures" / "otlp-corrupt").glob("*.json*")
           if not p.name.startswith("reject-")),
)
def test_a_committed_traces_fixture_counts_only_its_quarantined_data(fixture: str) -> None:
    # These fixtures hold no log record, and no span value in a shape the
    # scan does not read: only a span or scope quarantined at decode, as the
    # ledger names it, is counted as not scanned.
    data = (_REPO / "fixtures" / "otlp-corrupt" / fixture).read_bytes()
    assert b"resourceLogs" not in data and b"resource_logs" not in data
    wire = decode_input(data)
    quarantined = sum(d.reason in ("undecodable_span", "undecodable_scope")
                      for d in wire.degradations)
    assert scan_surface(wire).values_not_scanned == quarantined


_FLOW_LINES = ("evidentiary coverage", "argument capture", "degraded", "provenance",
               "the trace matched no registered dialect", "non-trace")
_NO_SPANS = "flow scan: the input held no spans, so no flow trace was built"


@pytest.mark.parametrize("extra", ["nothing else", "metrics"])
def test_gauge_on_a_logs_only_export_says_no_flow_trace_was_built(extra: str) -> None:
    logs = _logs([{"body": {"stringValue": _KEY}}])
    body = json.dumps(logs if extra == "nothing else" else {**logs, **_METRICS})
    scan = classify_exposure(scan_surface(decode_input(body.encode())), DEFAULT_CATALOG)
    result = _run(["gauge"], body)
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [_NO_SPANS, *exposure_gauge_lines(scan)]
    assert not any(word in result.output for word in _FLOW_LINES), result.output


@pytest.mark.parametrize("body", ["traces", "traces and logs"])
def test_gauge_on_an_export_with_traces_prints_the_flow_lines(body: str) -> None:
    traces = _spans([{"spanId": "aa" * 8, "name": "crew.agent"}])
    document = traces if body == "traces" else {**traces, **_logs([{"body": {"stringValue": "x"}}])}
    output = _run(["gauge"], json.dumps(document)).output
    assert _NO_SPANS not in output
    assert output.startswith("evidentiary coverage: ")


def test_gauge_on_a_logs_only_export_reports_a_line_it_could_not_decode() -> None:
    clean = json.dumps(_logs([{"body": {"stringValue": "started"}}]))
    truncated = json.dumps(_logs([{"body": {"stringValue": _KEY}}]))[:-1]
    body = f"{clean}\n{truncated}\n"
    [undecodable] = [
        d for d in decode_input(body.encode()).degradations if d.subject == "line:2"
    ]
    output = _run(["gauge"], body).output
    assert REMEDIATION[undecodable.reason] in output.splitlines(), output
    assert not any(word in output for word in _FLOW_LINES), output


def test_a_log_record_is_named_by_its_position_among_the_input_records() -> None:
    document = _logs([None, {"body": {"stringValue": _KEY}}])
    [records] = [scope["logRecords"] for rs in document["resourceLogs"]
                 for scope in rs["scopeLogs"]]
    position = next(i for i, r in enumerate(records) if r and _KEY in json.dumps(r))
    [hit] = _scan(document)
    assert hit.log_record == position
    result = _run(["scan"], json.dumps(document))
    assert f"  log record {position}  body  " in result.output, result.output
