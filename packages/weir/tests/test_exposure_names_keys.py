"""A credential held only in a name or a key is found: a span name, a span
event name, a log record's eventName, and every attribute key (span, event,
resource, scope and log record attributes, and kvlist keys at any depth) is
scanned as text, the same as an attribute value.

Every expectation is derived from a control export that holds the same fake
key as a plain attribute value in the same record: the class, grade,
fingerprint, last 4 and exit code the new place gives must be the control's.
Each hit is reported at its own location, and nothing printed holds the key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.canary.text import WITHHELD
from weir.catalog import DEFAULT_CATALOG
from weir.cli.main import main
from weir.exposure import ExposureHit, classify_exposure

# A fake value, shaped like the class it is matched as.
_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"
_RUN = 6


def _attr(key: str, value: str) -> dict[str, object]:
    return {"key": key, "value": {"stringValue": value}}


def _kv(key: str, entries: list[dict[str, object]]) -> dict[str, object]:
    return {"key": key, "value": {"kvlistValue": {"values": entries}}}


def _spans(span: dict[str, object], resource=(), scope=(), *, rs=None, ss=None,
           **scope_fields) -> dict[str, object]:
    """`rs` and `ss` are fields of the resourceSpans and scopeSpans element."""
    return {"resourceSpans": [{
        "resource": {"attributes": list(resource)}, **(rs or {}),
        "scopeSpans": [{"scope": {"name": "app", **scope_fields, "attributes": list(scope)},
                        **(ss or {}),
                        "spans": [{"spanId": "aa" * 8, "name": "crew.agent", **span}]}],
    }]}


def _logs(record: dict[str, object], resource=(), scope=(), *, rs=None, ss=None,
          **scope_fields) -> dict[str, object]:
    return {"resourceLogs": [{
        "resource": {"attributes": list(resource)}, **(rs or {}),
        "scopeLogs": [{"scope": {"name": "app", **scope_fields, "attributes": list(scope)},
                       **(ss or {}), "logRecords": [record]}],
    }]}


def _link(**fields: object) -> dict[str, object]:
    return {"traceId": "cc" * 16, "spanId": "dd" * 8, **fields}


_SPAN_CONTROL = _spans({"attributes": [_attr("acme.llm", _KEY)]})
_LOG_CONTROL = _logs({"attributes": [_attr("acme.llm", _KEY)]})

# place -> (export holding the key only there, its control, the location
# the hit is reported at). A key's location is its attribute path marked
# ` (key)`; the path still ends in the key, which prints as [withheld].
_PLACES: dict[str, tuple[dict[str, object], dict[str, object], str]] = {
    "span name": (
        _spans({"name": f"GET https://api.provider.invalid/v1/models?api_key={_KEY}"}),
        _SPAN_CONTROL, "name",
    ),
    "span event name": (
        _spans({"events": [{"name": "ok"}, {"name": f"retry with {_KEY}"}]}),
        _SPAN_CONTROL, "events[1].name",
    ),
    "span attribute key": (
        _spans({"attributes": [_attr(f"app.cred.{_KEY}", "present")]}),
        _SPAN_CONTROL, f"attributes.app.cred.{_KEY} (key)",
    ),
    "nested kvlist key in a span attribute": (
        _spans({"attributes": [_kv("app.cfg", [_kv("clients", [_attr(_KEY, "on")])])]}),
        _SPAN_CONTROL, f"attributes.app.cfg.clients.{_KEY} (key)",
    ),
    "span event attribute key": (
        _spans({"events": [{"name": "ok", "attributes": [_attr(_KEY, "x")]}]}),
        _SPAN_CONTROL, f"events[0].attributes.{_KEY} (key)",
    ),
    "span resource attribute key": (
        _spans({}, resource=[_attr(f"boot.{_KEY}", "x")]),
        _SPAN_CONTROL, f"resource.attributes.boot.{_KEY} (key)",
    ),
    "span scope attribute key": (
        _spans({}, scope=[_attr(f"cfg.{_KEY}", "x")]),
        _SPAN_CONTROL, f"scope.attributes.cfg.{_KEY} (key)",
    ),
    "span link attribute value": (
        _spans({"links": [_link(), _link(attributes=[_attr("peer.cfg", f"token={_KEY}")])]}),
        _SPAN_CONTROL, "links[1].attributes.peer.cfg",
    ),
    "span link attribute key": (
        _spans({"links": [_link(attributes=[_kv("peer", [_attr(f"cred.{_KEY}", "x")])])]}),
        _SPAN_CONTROL, f"links[0].attributes.peer.cred.{_KEY} (key)",
    ),
    "span link traceState": (
        _spans({"links": [_link(traceState=f"vendor={_KEY}")]}),
        _SPAN_CONTROL, "links[0].traceState",
    ),
    "span traceState": (
        _spans({"traceState": f"vendor={_KEY}"}), _SPAN_CONTROL, "traceState",
    ),
    "span scope name": (_spans({}, name=f"app {_KEY}"), _SPAN_CONTROL, "scope.name"),
    "span scope version": (_spans({}, version=f"build {_KEY}"), _SPAN_CONTROL, "scope.version"),
    "log scope name": (
        _logs({"body": {"stringValue": "ok"}}, name=f"app {_KEY}"), _LOG_CONTROL, "scope.name",
    ),
    "span resource schemaUrl": (
        _spans({}, rs={"schemaUrl": f"https://schemas.invalid/1.0?t={_KEY}"}),
        _SPAN_CONTROL, "resource.schemaUrl",
    ),
    "span scope schemaUrl": (
        _spans({}, ss={"schemaUrl": f"https://schemas.invalid/1.0?t={_KEY}"}),
        _SPAN_CONTROL, "scope.schemaUrl",
    ),
    "log resource schemaUrl": (
        _logs({"body": {"stringValue": "ok"}},
              rs={"schemaUrl": f"https://schemas.invalid/1.0?t={_KEY}"}),
        _LOG_CONTROL, "resource.schemaUrl",
    ),
    "log scope schemaUrl": (
        _logs({"body": {"stringValue": "ok"}},
              ss={"schemaUrl": f"https://schemas.invalid/1.0?t={_KEY}"}),
        _LOG_CONTROL, "scope.schemaUrl",
    ),
    "resource entity ref schemaUrl": (
        _spans({}, rs={"resource": {"entityRefs": [
            {"type": "service", "schemaUrl": f"https://schemas.invalid/?t={_KEY}"}]}}),
        _SPAN_CONTROL, "resource.entityRefs[0].schemaUrl",
    ),
    "resource entity ref type": (
        _logs({"body": {"stringValue": "ok"}},
              rs={"resource": {"entityRefs": [{"type": f"svc {_KEY}"}]}}),
        _LOG_CONTROL, "resource.entityRefs[0].type",
    ),
    "resource entity ref idKeys": (
        _spans({}, rs={"resource": {"entityRefs": [
            {"type": "service", "idKeys": ["service.name", f"cred.{_KEY}"]}]}}),
        _SPAN_CONTROL, "resource.entityRefs[0].idKeys[1]",
    ),
    "resource entity ref descriptionKeys": (
        _spans({}, rs={"resource": {"entityRefs": [
            {"type": "service", "descriptionKeys": [f"cred.{_KEY}"]}]}}),
        _SPAN_CONTROL, "resource.entityRefs[0].descriptionKeys[0]",
    ),
    "log record severityText": (
        _logs({"severityText": f"WARN {_KEY}", "body": {"stringValue": "ok"}}),
        _LOG_CONTROL, "severityText",
    ),
    "log record eventName": (
        _logs({"eventName": f"auth.{_KEY}", "body": {"stringValue": "ok"}}),
        _LOG_CONTROL, "eventName",
    ),
    "log record attribute key": (
        _logs({"attributes": [_attr(f"app.cred.{_KEY}", "present")]}),
        _LOG_CONTROL, f"attributes.app.cred.{_KEY} (key)",
    ),
    "nested kvlist key in a log attribute": (
        _logs({"attributes": [_kv("app.cfg", [_kv("clients", [_attr(_KEY, "on")])])]}),
        _LOG_CONTROL, f"attributes.app.cfg.clients.{_KEY} (key)",
    ),
    "kvlist key in a log body": (
        _logs({"body": {"kvlistValue": {"values": [_attr(_KEY, "on")]}}}),
        _LOG_CONTROL, f"body.{_KEY} (key)",
    ),
    "log resource attribute key": (
        _logs({"body": {"stringValue": "ok"}}, resource=[_attr(f"boot.{_KEY}", "x")]),
        _LOG_CONTROL, f"resource.attributes.boot.{_KEY} (key)",
    ),
    "log scope attribute key": (
        _logs({"body": {"stringValue": "ok"}}, scope=[_attr(f"cfg.{_KEY}", "x")]),
        _LOG_CONTROL, f"scope.attributes.cfg.{_KEY} (key)",
    ),
}


def _surface_hits(document: dict[str, object]) -> tuple[list[str], list[ExposureHit]]:
    """The raw locations the walk emitted, and the classified hits."""
    surface = scan_surface(decode_input(json.dumps(document).encode()))
    return ([s.location for s in surface.strings],
            classify_exposure(surface, DEFAULT_CATALOG).hits)


def _cli(document: dict[str, object]) -> tuple[int, str, str, str]:
    """scan's exit code and stdout, its HTML report, and gauge's stdout."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(json.dumps(document), encoding="utf-8")
        scan = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        assert scan.exception is None or isinstance(scan.exception, SystemExit), scan.output
        html = Path("r.html").read_text(encoding="utf-8")
        gauge = runner.invoke(main, ["gauge", "export.json"])
        assert gauge.exit_code == 0, gauge.output
    return scan.exit_code, scan.output, html, gauge.output


def _printed(document: dict[str, object], location: str) -> str:
    """`location` with each attribute key in `document` that holds the key
    written as [withheld], longest first, as the scan prints it."""
    keys: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            key = node.get("key")
            if isinstance(key, str) and _KEY in key:
                keys.add(key)
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(document)
    for key in sorted(keys, key=len, reverse=True):
        location = location.replace(key, WITHHELD)
    return location.replace(_KEY, WITHHELD)


def _grade(hit: ExposureHit) -> tuple[object, ...]:
    return (hit.source_class, hit.eligible, hit.prefix, hit.last4, hit.fingerprint,
            hit.value_len, hit.log_record)


def _assert_never_printed(text: str, value: str) -> None:
    """No run of 6 characters of the value past its class head is printed."""
    body = value[len("sk-proj-"):]
    for start in range(len(body) - _RUN + 1):
        assert body[start:start + _RUN] not in text, body[start:start + _RUN]


@pytest.mark.parametrize("place", sorted(_PLACES))
def test_a_key_held_only_there_is_found_as_in_an_attribute_value(place: str) -> None:
    document, control, location = _PLACES[place]
    locations, hits = _surface_hits(document)
    assert location in locations, locations
    [hit] = hits
    [expected] = _surface_hits(control)[1]
    assert _grade(hit) == _grade(expected)
    # The location it prints at: the one segment that holds the key, a
    # whole attribute key such as `app.cred.<key>`, is withheld.
    printed = _printed(document, location)
    assert hit.location == printed

    code, stdout, html, gauge = _cli(document)
    control_code, control_stdout, _, control_gauge = _cli(control)
    assert (code, control_code) == (1, 1)
    assert f"  {printed}  " in stdout, stdout
    assert f"in {printed} of " in html
    # One credential in one location across one record, as the control.
    assert [ln for ln in stdout.splitlines() if ln.startswith("1 credential")] == [
        ln for ln in control_stdout.splitlines() if ln.startswith("1 credential")]
    assert [ln for ln in gauge.splitlines() if "credentials:" in ln] == [
        ln for ln in control_gauge.splitlines() if "credentials:" in ln]
    for text in (stdout, html, gauge):
        _assert_never_printed(text, _KEY)


def test_a_key_in_both_an_attribute_key_and_its_value_is_two_locations() -> None:
    document = _spans({"attributes": [_attr(f"app.cred.{_KEY}", f"token={_KEY}")]})
    _, hits = _surface_hits(document)
    # The whole attribute key `app.cred.<key>` is the one segment withheld.
    assert sorted(h.location for h in hits if h.eligible) == [
        f"attributes.{WITHHELD}", f"attributes.{WITHHELD} (key)"]
    code, stdout, html, gauge = _cli(document)
    assert code == 1
    assert "1 credential (openai_api_key) in 2 locations across 1 span" in stdout
    for text in (stdout, html, gauge):
        _assert_never_printed(text, _KEY)


def test_a_span_name_hit_withholds_the_name_on_every_row_of_its_span() -> None:
    url = f"GET https://api.provider.invalid/v1/models?api_key={_KEY}"
    code, stdout, html, _ = _cli(_spans({"name": url, "attributes": [_attr("url.full", url)]}))
    assert code == 1
    rows = [ln for ln in stdout.splitlines() if ln.startswith(f"  {WITHHELD} (")]
    assert sorted(row.split("  ")[2] for row in rows) == ["attributes.url.full", "name"]
    assert f"present in name of span {WITHHELD} (" in html
    _assert_never_printed(stdout + html, _KEY)


def test_names_and_keys_that_hold_no_credential_add_no_hit() -> None:
    # Each name and key is one more scanned string, and nothing else.
    document = _spans({"name": "crew.agent", "events": [{"name": "exception"}],
                       "attributes": [_attr("api_key", "present"), _attr("acme.llm", _KEY)]})
    locations, hits = _surface_hits(document)
    assert {"name", "events[0].name", "attributes.api_key (key)",
            "attributes.acme.llm (key)"} <= set(locations)
    assert [h.location for h in hits] == ["attributes.acme.llm"]


def test_a_log_record_eventname_that_is_not_a_string_is_not_scanned() -> None:
    surface = scan_surface(decode_input(json.dumps(_logs({"eventName": 7})).encode()))
    assert surface.values_not_scanned == 1


def test_snake_case_event_name_is_read() -> None:
    document = _logs({"event_name": f"auth.{_KEY}"})
    [hit] = _surface_hits(document)[1]
    assert hit.location == "eventName"


@pytest.mark.parametrize("document, control", [
    (_logs({"eventName": "", "body": {"stringValue": "ok"}}),
     _logs({"body": {"stringValue": "ok"}})),
    (_logs({"attributes": [{"key": "", "value": {"stringValue": "ok"}}]}),
     _logs({"body": {"stringValue": "ok"}})),
    (_spans({"attributes": [_kv("app.cfg", [{"key": "", "value": {"stringValue": "ok"}}])]}),
     _spans({"attributes": [_kv("app.cfg", [])], "status": {"message": "ok"}})),
], ids=["empty log eventName", "empty attribute key", "empty kvlist key"])
def test_an_empty_name_or_key_is_not_a_scanned_string(
    document: dict[str, object], control: dict[str, object]
) -> None:
    # The control holds the same "ok" value without the empty name or key.
    surface = scan_surface(decode_input(json.dumps(document).encode()))
    expected = scan_surface(decode_input(json.dumps(control).encode()))
    assert sorted(s.text for s in surface.strings) == sorted(s.text for s in expected.strings)
    assert surface.values_not_scanned == expected.values_not_scanned == 0


def test_snake_case_severity_text_schema_url_and_entity_refs_are_read() -> None:
    document = {"resource_logs": [{
        "resource": {"entity_refs": [{"type": "service", "id_keys": [f"cred.{_KEY}"],
                                      "description_keys": [f"note.{_KEY}"],
                                      "schema_url": f"https://schemas.invalid/?t={_KEY}"}]},
        "schema_url": f"https://schemas.invalid/?t={_KEY}",
        "scope_logs": [{"scope": {"name": "app"}, "schema_url": f"https://schemas.invalid/?t={_KEY}",
                        "log_records": [{"severity_text": f"WARN {_KEY}"}]}],
    }]}
    assert sorted(h.location for h in _surface_hits(document)[1]) == sorted([
        "severityText", "resource.schemaUrl", "scope.schemaUrl",
        "resource.entityRefs[0].schemaUrl", "resource.entityRefs[0].idKeys[0]",
        "resource.entityRefs[0].descriptionKeys[0]"])
