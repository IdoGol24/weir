"""An accepted export holding data the exposure scan did not read never passes
clean: `weir scan` exits 3, incomplete, unless a finding already makes it exit
1. Its stdout says what was not read, and the HTML report is not the green
page. `weir gauge` still exits 0.

Every expectation is derived from a control: the same export without the
unread part. The control must exit 0 with the green page, and every line the
two print about the data that was read must be the same. Every value here is
fake.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.cli.main import main

_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"
_INCOMPLETE = "incomplete: the export holds data the scan did not read (see above)"
_FIXTURES = Path(__file__).parents[3] / "fixtures"


def _attr(key: str, value: str) -> dict[str, object]:
    return {"key": key, "value": {"stringValue": value}}


def _spans(value: str) -> dict[str, object]:
    return {"resourceSpans": [{"scopeSpans": [{"scope": {"name": "app"}, "spans": [
        {"spanId": "aa" * 8, "name": "crew.agent", "attributes": [_attr("acme.llm", value)]}]}]}]}


def _span_batch(span: dict[str, object], resources: tuple[object, ...] = (),
                rs: dict[str, object] | None = None,
                ss: dict[str, object] | None = None) -> dict[str, object]:
    """`rs` and `ss` are fields of the span's resourceSpans and scopeSpans
    element."""
    return {"resourceSpans": [*resources, {**(rs or {}), "scopeSpans": [{
        "scope": {"name": "app"}, **(ss or {}),
        "spans": [{"spanId": "bb" * 8, "name": "crew.tool", **span}]}]}]}


def _logs(record: dict[str, object]) -> dict[str, object]:
    return {"resourceLogs": [{"scopeLogs": [{"scope": {"name": "app"}, "logRecords": [record]}]}]}


_METRICS = {"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "m"}]}]}]}
_PROFILES = {"resourceProfiles": [{"scopeProfiles": []}]}
_NOT_UTF8 = {"bytesValue": base64.b64encode(b"\xff\xfe\xfa" * 8).decode()}
_FINE = _attr("acme.tool", "fine")

# kind -> (a span holding data the scan does not read, the same span without
# it), with the resources listed before the span's own.
_SPAN_SHAPES: dict[str, tuple[dict[str, object], dict[str, object], tuple[object, ...]]] = {
    "a span value in a snake_case wrapper": (
        {"attributes": [{"key": "acme.tool", "value": {"string_value": "fine"}}]},
        {"attributes": [_FINE]}, ()),
    "a span value in bytesValue": (
        {"attributes": [{"key": "acme.tool",
                         "value": {"bytesValue": base64.b64encode(b"fine").decode()}}]},
        {"attributes": [_FINE]}, ()),
    "a span resource in a shape the scan does not read": ({}, {}, ("stray",)),
    "a span event name that is not a string": ({"events": [{"name": 7}]}, {"events": [{}]}, ()),
    "a span event that is not an object": ({"events": ["stray"]}, {"events": []}, ()),
    "span events that are not a list": ({"events": "stray"}, {}, ()),
    "a span status that is not an object": ({"status": "stray"}, {}, ()),
    "a span traceState that is not a string": ({"traceState": 7}, {}, ()),
    "a span link that is not an object": ({"links": ["stray"]}, {"links": []}, ()),
    "span links that are not a list": ({"links": "stray"}, {}, ()),
    "a link traceState that is not a string": (
        {"links": [{"traceState": 7}]}, {"links": [{}]}, ()),
    "link attributes that are not a list": (
        {"links": [{"attributes": "stray"}]}, {"links": [{}]}, ()),
}

# kind -> the resourceSpans and scopeSpans fields holding data the scan does
# not read; the control has neither.
_CONTEXT_SHAPES: dict[str, tuple[dict[str, object], dict[str, object]]] = {
    "a resource schemaUrl that is not a string": ({"schemaUrl": 7}, {}),
    "a scope schemaUrl that is not a string": ({}, {"schemaUrl": 7}),
    "resource entityRefs that are not a list": ({"resource": {"entityRefs": "stray"}}, {}),
    "an entity ref that is not an object": ({"resource": {"entityRefs": ["stray"]}}, {}),
    "an entity ref type that is not a string": (
        {"resource": {"entityRefs": [{"type": 7}]}}, {}),
    "entity ref idKeys that are not a list": (
        {"resource": {"entityRefs": [{"type": "service", "idKeys": "stray"}]}}, {}),
    "an entity ref idKey that is not a string": (
        {"resource": {"entityRefs": [{"type": "service", "idKeys": [7]}]}}, {}),
}


def _lines(*documents: dict[str, object]) -> str:
    return "".join(json.dumps(d) + "\n" for d in documents)


# kind -> (export holding the unread data, the same export without it). The
# read part is the spans of `read`, or a clean log record.
def _kinds(read: dict[str, object]) -> dict[str, tuple[str, str]]:
    clean_log = _logs({"body": {"stringValue": "fine"}})
    return {
        "a metrics batch on its own line": (_lines(read, _METRICS), _lines(read)),
        "metrics in the same document": (json.dumps({**read, **_METRICS}), json.dumps(read)),
        "another signal": (_lines(read, _PROFILES), _lines(read)),
        "a batch holding no signal": (_lines(read, {"note": "export done"}), _lines(read)),
        "a log value in a shape the scan does not read": (
            _lines(read, _logs({"body": _NOT_UTF8})), _lines(read, clean_log)),
        "a log record in a shape the scan does not read": (
            _lines(read, _logs({"body": {"text": "fine"}})), _lines(read, clean_log)),
        "a log severityText that is not a string": (
            _lines(read, _logs({"severityText": 7, "body": {"stringValue": "fine"}})),
            _lines(read, clean_log)),
        **{
            kind: (_lines(read, _span_batch(span, resources)), _lines(read, _span_batch(control)))
            for kind, (span, control, resources) in _SPAN_SHAPES.items()
        },
        **{
            kind: (_lines(read, _span_batch({}, rs=rs, ss=ss)), _lines(read, _span_batch({})))
            for kind, (rs, ss) in _CONTEXT_SHAPES.items()
        },
    }


_CLEAN = _spans("fine")


def _cli(body: str) -> tuple[int, str, str, int]:
    """scan's exit code and stdout, its HTML report, and gauge's exit code."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(body, encoding="utf-8")
        scan = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        assert scan.exception is None or isinstance(scan.exception, SystemExit), scan.output
        html = Path("r.html").read_text(encoding="utf-8")
        gauge = runner.invoke(main, ["gauge", "export.json"])
    return scan.exit_code, scan.output, html, gauge.exit_code


def _unread(body: str) -> int:
    surface = scan_surface(decode_input(body.encode()))
    return surface.batches_not_scanned + surface.values_not_scanned


def _read_lines(stdout: str) -> list[str]:
    """What stdout says about the data that was read."""
    return [ln for ln in stdout.splitlines() if "not scanned" not in ln and ln != _INCOMPLETE]


@pytest.mark.parametrize("kind", sorted(_kinds(_CLEAN)))
def test_unread_data_in_a_clean_export_exits_3_incomplete(kind: str) -> None:
    body, control = _kinds(_CLEAN)[kind]
    assert (_unread(body), _unread(control)) == (1, 0)
    code, stdout, html, gauge = _cli(body)
    control_code, control_stdout, control_html, _ = _cli(control)

    assert (control_code, code, gauge) == (0, 3, 0)
    assert 'class="green-screen"' in control_html
    assert 'class="green-screen"' not in html
    assert 'class="incomplete-screen"' in html
    not_scanned = [ln for ln in stdout.splitlines() if "not scanned" in ln]
    assert len(not_scanned) == 1, stdout
    assert f"<div>{not_scanned[0]}</div>" in html
    assert stdout.splitlines()[-1] == _INCOMPLETE
    assert _INCOMPLETE not in control_stdout
    assert _read_lines(stdout) == _read_lines(control_stdout)


@pytest.mark.parametrize("kind", sorted(_kinds(_CLEAN)))
def test_a_finding_beside_unread_data_still_exits_1(kind: str) -> None:
    body, control = _kinds(_spans(_KEY))[kind]
    assert (_unread(body), _unread(control)) == (1, 0)
    code, stdout, html, _ = _cli(body)
    control_code, control_stdout, _, _ = _cli(control)

    assert (control_code, code) == (1, 1)
    assert any("not scanned" in ln for ln in stdout.splitlines()), stdout
    assert _INCOMPLETE not in stdout
    assert 'class="incomplete-screen"' not in html
    assert _read_lines(stdout) == _read_lines(control_stdout)


def test_a_review_queue_match_beside_unread_data_is_still_incomplete() -> None:
    # A review-queue row fails nothing, so it cannot stand in for a finding.
    read = _spans("api_key=sk-proj-abc")
    body, control = _kinds(read)["a metrics batch on its own line"]
    code, stdout, html, _ = _cli(body)
    control_code, control_stdout, _, _ = _cli(control)
    assert "review queue: 1" in control_stdout
    assert (control_code, code) == (0, 3)
    assert stdout.splitlines()[-1] == _INCOMPLETE
    assert 'class="green-screen"' not in html


def test_a_flow_finding_beside_unread_data_still_exits_1() -> None:
    # The committed mixed-signal fixture holds a metrics batch and a
    # verdict-grade flow finding: the finding decides the exit.
    body = (_FIXTURES / "otlp-corrupt" / "mixed-signals.jsonl").read_text(encoding="utf-8")
    assert _unread(body) > 0
    code, stdout, html, gauge = _cli(body)
    assert "1 verdict-grade finding(s)" in stdout.splitlines()
    assert (code, gauge) == (1, 0)
    assert any("not scanned" in ln for ln in stdout.splitlines()), stdout
    assert _INCOMPLETE not in stdout
    assert 'class="incomplete-screen"' not in html


def test_a_span_that_fails_to_decode_exits_3_incomplete() -> None:
    # The span is quarantined at decode, its attributes unread.
    body = _lines(_CLEAN, _span_batch({"attributes": [_FINE, "stray"]}))
    control = _lines(_CLEAN, _span_batch({"attributes": [_FINE]}))
    assert (_unread(body), _unread(control)) == (1, 0)
    code, stdout, html, gauge = _cli(body)
    control_code, control_stdout, control_html, _ = _cli(control)

    assert (control_code, code, gauge) == (0, 3, 0)
    assert 'class="green-screen"' in control_html
    assert 'class="incomplete-screen"' in html
    assert stdout.splitlines()[-1] == _INCOMPLETE
    assert _read_lines(stdout) == _read_lines(control_stdout)


def test_a_span_that_fails_to_decode_beside_a_finding_still_exits_1() -> None:
    body = _lines(_spans(_KEY), _span_batch({"attributes": [_FINE, "stray"]}))
    code, stdout, html, _ = _cli(body)
    assert code == 1
    assert any("not scanned" in ln for ln in stdout.splitlines()), stdout
    assert _INCOMPLETE not in stdout
    assert 'class="incomplete-screen"' not in html


@pytest.mark.parametrize(
    "path", [p for p in sorted((_FIXTURES / "otlp").glob("*.json")) if "benign" in p.name],
    ids=lambda p: p.name,
)
def test_a_committed_well_formed_export_still_exits_0(path: Path) -> None:
    body = path.read_text(encoding="utf-8")
    assert _unread(body) == 0
    code, stdout, html, _ = _cli(body)
    assert code == 0, stdout
    assert _INCOMPLETE not in stdout
    assert 'class="green-screen"' in html


def test_a_well_formed_export_with_ordinary_links_still_exits_0() -> None:
    link = {"traceId": "cc" * 16, "spanId": "dd" * 8, "traceState": "rojo=00f067aa0ba902b7",
            "attributes": [_attr("messaging.batch.message_count", "3")]}
    body = _lines(_CLEAN, _span_batch({"traceState": "congo=t61rcWkgMzE", "links": [link]}))
    assert _unread(body) == 0
    code, stdout, html, gauge = _cli(body)
    assert (code, gauge) == (0, 0), stdout
    assert _INCOMPLETE not in stdout
    assert 'class="green-screen"' in html


# A member OTLP does not define, holding a credential. It is never read, so
# neither its value nor its name may be printed, and it is counted as not
# scanned.
_UNDEFINED: dict[str, object] = {"acmeVault": _KEY}


def _log_batch(record: dict[str, object], rs: dict[str, object] | None = None,
               ss: dict[str, object] | None = None) -> dict[str, object]:
    return {"resourceLogs": [{**(rs or {}), "scopeLogs": [{
        "scope": {"name": "app"}, **(ss or {}),
        "logRecords": [{"body": {"stringValue": "fine"}, **record}]}]}]}


def _value_attr(value: dict[str, object]) -> dict[str, object]:
    return {"attributes": [{"key": "acme.tool", "value": value}]}


# level -> (the export with an undefined member at that level, the same
# export without it).
_UNDEFINED_AT: dict[str, tuple[dict[str, object], dict[str, object]]] = {
    "span": (_span_batch(_UNDEFINED), _span_batch({})),
    "span event": (_span_batch({"events": [{"name": "e", **_UNDEFINED}]}),
                   _span_batch({"events": [{"name": "e"}]})),
    "span link": (_span_batch({"links": [{"spanId": "cc" * 8, **_UNDEFINED}]}),
                  _span_batch({"links": [{"spanId": "cc" * 8}]})),
    "span status": (_span_batch({"status": {"code": 1, **_UNDEFINED}}),
                    _span_batch({"status": {"code": 1}})),
    "span scope": (_span_batch({}, ss={"scope": {"name": "app", **_UNDEFINED}}),
                   _span_batch({})),
    "span resource": (_span_batch({}, rs={"resource": {**_UNDEFINED}}),
                      _span_batch({}, rs={"resource": {}})),
    "resourceSpans": (_span_batch({}, rs=_UNDEFINED), _span_batch({})),
    "scopeSpans": (_span_batch({}, ss=_UNDEFINED), _span_batch({})),
    "entity ref": (_span_batch({}, rs={"resource": {"entityRefs": [
        {"type": "service", **_UNDEFINED}]}}),
                   _span_batch({}, rs={"resource": {"entityRefs": [{"type": "service"}]}})),
    "attribute entry": (
        _span_batch({"attributes": [{**_FINE, **_UNDEFINED}]}),
        _span_batch({"attributes": [_FINE]})),
    "attribute value": (
        _span_batch(_value_attr({"stringValue": "fine", **_UNDEFINED})),
        _span_batch(_value_attr({"stringValue": "fine"}))),
    "array value": (
        _span_batch(_value_attr({"arrayValue": {"values": [], **_UNDEFINED}})),
        _span_batch(_value_attr({"arrayValue": {"values": []}}))),
    "kvlist value": (
        _span_batch(_value_attr({"kvlistValue": {"values": [], **_UNDEFINED}})),
        _span_batch(_value_attr({"kvlistValue": {"values": []}}))),
    "log record": (_log_batch(_UNDEFINED), _log_batch({})),
    "log scope": (_log_batch({}, ss={"scope": {"name": "app", **_UNDEFINED}}), _log_batch({})),
    "log resource": (_log_batch({}, rs={"resource": {**_UNDEFINED}}),
                     _log_batch({}, rs={"resource": {}})),
    "resourceLogs": (_log_batch({}, rs=_UNDEFINED), _log_batch({})),
    "scopeLogs": (_log_batch({}, ss=_UNDEFINED), _log_batch({})),
    "log body value": (_log_batch({"body": {"stringValue": "fine", "string_value": _KEY}}),
                       _log_batch({})),
}


@pytest.mark.parametrize("level", sorted(_UNDEFINED_AT))
def test_a_member_otlp_does_not_define_is_not_read_and_exits_3(level: str) -> None:
    export, control = _UNDEFINED_AT[level]
    body, control_body = _lines(_CLEAN, export), _lines(_CLEAN, control)
    assert (_unread(body), _unread(control_body)) == (1, 0)
    code, stdout, html, gauge = _cli(body)
    control_code, control_stdout, control_html, _ = _cli(control_body)

    assert (control_code, code, gauge) == (0, 3, 0)
    assert 'class="green-screen"' in control_html
    assert 'class="incomplete-screen"' in html
    assert stdout.splitlines()[-1] == _INCOMPLETE
    assert _read_lines(stdout) == _read_lines(control_stdout)
    for printed in (stdout, html):
        assert _KEY not in printed
        assert _KEY[:12] not in printed
        assert "acmeVault" not in printed


@pytest.mark.parametrize("empty", [None, "", [], {}], ids=repr)
def test_an_undefined_member_holding_nothing_is_not_counted(empty: object) -> None:
    body = _lines(_CLEAN, _span_batch({"acmeVault": empty}))
    assert _unread(body) == 0
    assert _cli(body)[0] == 0


# Every member OTLP defines (opentelemetry-proto trace/v1, logs/v1,
# resource/v1 and common/v1) that the scan does not read as text, at each
# level, as the OTLP/JSON camelCase name and the protojson snake_case one.
_DEFINED_UNREAD: dict[str, dict[str, object]] = {
    "resource": {"droppedAttributesCount": 1},
    "scope": {"droppedAttributesCount": 1},
    "span": {"traceId": "ab" * 16, "parentSpanId": "cd" * 8, "flags": 1, "kind": 2,
             "startTimeUnixNano": "1", "endTimeUnixNano": "2", "droppedAttributesCount": 1,
             "droppedEventsCount": 1, "droppedLinksCount": 1},
    "event": {"timeUnixNano": "1", "droppedAttributesCount": 1},
    "link": {"traceId": "ab" * 16, "spanId": "cd" * 8, "flags": 1, "droppedAttributesCount": 1},
    "status": {"code": 2},
    "logRecord": {"timeUnixNano": "1", "observedTimeUnixNano": "1", "severityNumber": 9,
                  "droppedAttributesCount": 1, "flags": 1, "traceId": "ab" * 16,
                  "spanId": "cd" * 8},
}


def _snake(fields: dict[str, object]) -> dict[str, object]:
    return {"".join(f"_{c.lower()}" if c.isupper() else c for c in k): v
            for k, v in fields.items()}


@pytest.mark.parametrize("spell", [dict, _snake], ids=["camelCase", "snake_case"])
def test_every_field_otlp_defines_still_exits_0(
    spell: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    def f(level: str) -> dict[str, object]:
        return spell(_DEFINED_UNREAD[level])

    span = {**f("span"), "events": [{"name": "e", **f("event")}], "links": [f("link")],
            "status": {"message": "ok", **f("status")}}
    traces = _span_batch(span, rs={"resource": f("resource")},
                         ss={"scope": {"name": "app", **f("scope")}})
    logs = _log_batch(f("logRecord"), rs={"resource": f("resource")},
                      ss={"scope": {"name": "app", **f("scope")}})
    body = _lines(_CLEAN, traces, logs)
    assert _unread(body) == 0
    code, stdout, html, _ = _cli(body)
    assert code == 0, stdout
    assert 'class="green-screen"' in html
