"""A span name, span id or location segment that holds a matched value is
printed as `[withheld]`, in every `weir scan` output and in `weir gauge`.

Every expectation here is derived from the input: the planted value is the
thing that must not appear, and a control export that differs only in where
the value sits gives the counts, exit code and grade the withheld run must
reproduce exactly. Withholding changes what is printed, never what was found.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from click.testing import CliRunner, Result

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.canary import needles
from weir.canary.text import WITHHELD, Display
from weir.catalog import DEFAULT_CATALOG
from weir.cli.main import main
from weir.exposure import classify_exposure

# Fake values, shaped like the classes they are matched as.
_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"
_PLACEHOLDER = "sk-proj-abc"


def _export(spans: list[dict[str, object]]) -> str:
    return json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]})


def _span(name: str, attrs: list[tuple[str, str]], span_id: str = "aa" * 8) -> dict[str, object]:
    return {
        "spanId": span_id,
        "name": name,
        "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs],
    }


class _Run:
    def __init__(self, scan: Result, html: str, gauge: Result) -> None:
        self.scan = scan
        self.html = html
        self.gauge = gauge

    def outputs(self) -> dict[str, str]:
        return {"scan stdout": self.scan.output, "html": self.html, "gauge": self.gauge.output}


def _run(body: str) -> _Run:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("export.json").write_text(body, encoding="utf-8")
        scan = runner.invoke(main, ["scan", "export.json", "--report", "r.html"])
        html = Path("r.html").read_text(encoding="utf-8")
        gauge = runner.invoke(main, ["gauge", "export.json"])
    assert scan.exception is None or isinstance(scan.exception, SystemExit), scan.output
    assert gauge.exit_code == 0, gauge.output
    return _Run(scan, html, gauge)


def _assert_never_printed(run: _Run, value: str) -> None:
    for label, text in run.outputs().items():
        assert value not in text, f"{label} printed the planted value"


def _summary(text: str) -> list[str]:
    """The lines that state what was found, without the rows that name where."""
    return [
        line for line in text.splitlines()
        if not line.startswith("  ") or line.startswith(("  rule:", "  to demote:"))
    ]


def _same_findings(withheld: _Run, control: _Run) -> None:
    assert withheld.scan.exit_code == control.scan.exit_code
    assert _summary(withheld.scan.output) == _summary(control.scan.output)
    assert withheld.gauge.output == control.gauge.output
    assert ('class="green-screen"' in withheld.html) == ('class="green-screen"' in control.html)


def test_a_key_in_the_span_name_is_withheld_everywhere() -> None:
    url = f"GET https://api.provider.invalid/v1/models?api_key={_KEY}"
    run = _run(_export([_span(url, [("url.full", url)])]))
    control = _run(_export([_span("crew.agent", [("url.full", url)])]))

    _assert_never_printed(run, _KEY)
    _same_findings(run, control)
    assert run.scan.exit_code == 1
    row = next(line for line in run.scan.output.splitlines() if "attributes.url.full" in line)
    assert row.startswith(f"  {WITHHELD} (")
    assert f"of span {WITHHELD} (" in run.html


def test_a_key_in_an_attribute_key_is_withheld_everywhere() -> None:
    run = _run(_export([_span("crew.agent", [(f"app.cred.{_KEY}", f"token={_KEY}")])]))
    control = _run(_export([_span("crew.agent", [("app.cred.x", f"token={_KEY}")])]))

    _assert_never_printed(run, _KEY)
    _same_findings(run, control)
    assert f"attributes.{WITHHELD}" in run.scan.output
    assert f"in attributes.{WITHHELD} of span crew.agent" in run.html


def test_a_run_with_only_review_queue_rows_prints_no_matched_value() -> None:
    # Exit 0 and a green report: nothing here fails the build, so nothing
    # else on the screen would make a reader look twice at a printed key.
    name = f"call {_PLACEHOLDER}"
    run = _run(_export([_span(name, [("app.config", f"api_key={_PLACEHOLDER}")])]))
    control = _run(_export([_span("crew.agent", [("app.config", f"api_key={_PLACEHOLDER}")])]))

    _assert_never_printed(run, _PLACEHOLDER)
    _same_findings(run, control)
    assert run.scan.exit_code == 0
    assert "review queue: 1" in run.scan.output
    row = next(line for line in run.scan.output.splitlines() if "attributes.app.config" in line)
    assert row.startswith(f"  {WITHHELD}  ")


def test_a_span_id_holding_the_key_is_withheld_in_the_row() -> None:
    run = _run(_export([_span("crew.agent", [("acme.llm", _KEY)], span_id=_KEY)]))
    control = _run(_export([_span("crew.agent", [("acme.llm", _KEY)])]))

    _same_findings(run, control)
    assert f"crew.agent ({WITHHELD})" in run.scan.output
    # The id is lowercased off the wire, so a planted id must not print in
    # any letter case beyond the masked value's own class prefix.
    assert _KEY[8:14].lower() not in run.scan.output.lower()


def test_a_span_id_is_withheld_in_the_letter_case_it_prints_in() -> None:
    # An all-capitals key shares no run of 6 with its own lowercased form,
    # which is the form a span id prints in.
    key = "AKIAQZ7XWV3UTS5RPN2M"
    run = _run(_export([_span("crew.agent", [("acme.llm", key)], span_id=key)]))
    control = _run(_export([_span("crew.agent", [("acme.llm", key)])]))

    _same_findings(run, control)
    assert f"crew.agent ({WITHHELD})" in run.scan.output
    assert key[4:12].lower() not in run.scan.output.lower()


def test_a_name_is_withheld_only_for_a_matched_value_in_its_own_letter_case() -> None:
    # The canary judge's rule is case-exact. `openai` is a run of 6 of this
    # placeholder only once it is lowercased, which is how a span id prints,
    # not a span name or an attribute key.
    placeholder = "YOUR_OPENAI_KEY"
    attrs = [("llm.openai.model", f"api_key={placeholder}")]
    run = _run(_export([_span("openai.chat", attrs)]))
    assert "review queue: 1" in run.scan.output
    assert "  openai.chat  attributes.llm.openai.model  " in run.scan.output
    for label, text in run.outputs().items():
        assert WITHHELD not in text, label

    held = _run(_export([_span(f"call {placeholder}", attrs)]))
    _assert_never_printed(held, placeholder)
    assert f"  {WITHHELD}  attributes.llm.openai.model  " in held.scan.output


def test_two_withheld_locations_still_count_as_two() -> None:
    # Both rows print as `attributes.[withheld]`; the count is of where the
    # value was found, not of how the rows look.
    attrs = [(f"a.{_KEY}", f"token={_KEY}"), (f"b.{_KEY}", f"token={_KEY}")]
    run = _run(_export([_span("crew.agent", attrs)]))
    control = _run(_export([_span("crew.agent", [("a.x", f"token={_KEY}"),
                                                 ("b.x", f"token={_KEY}")])]))

    _assert_never_printed(run, _KEY)
    _same_findings(run, control)
    rows = [line for line in run.scan.output.splitlines() if f"attributes.{WITHHELD}" in line]
    assert len(rows) == 2


def test_two_spans_with_withheld_ids_still_count_as_two() -> None:
    other = _KEY[:-4] + "Zz99"
    spans = [_span("crew.agent", [("acme.llm", _KEY)], span_id=_KEY),
             _span("crew.agent", [("acme.llm", _KEY)], span_id=other + _KEY)]
    control = [_span("crew.agent", [("acme.llm", _KEY)], span_id="aa" * 8),
               _span("crew.agent", [("acme.llm", _KEY)], span_id="bb" * 8)]
    _same_findings(_run(_export(spans)), _run(_export(control)))


def test_a_name_that_holds_no_matched_value_still_prints() -> None:
    run = _run(_export([_span("crew.agent", [("acme.agent.llm", _KEY)])]))
    assert WITHHELD not in run.scan.output
    assert "crew.agent (aaaaaaaa)  attributes.acme.agent.llm" in run.scan.output


def _matched_values(text: str) -> set[str]:
    out: set[str] = set()
    for spec in DEFAULT_CATALOG.sources:
        if spec.exposure:
            for m in re.finditer(spec.content_pattern, text):
                out.add((m.group(1) if m.re.groups else m.group(0)) or "")
    return out


def test_no_hit_carries_a_display_field_that_holds_a_matched_value() -> None:
    # The withholding is applied once, where hits are made, so this holds
    # for every renderer downstream. The values are matched afresh from the
    # export's own strings, not taken from the code under test.
    body = _export([
        _span(f"GET /v1?api_key={_KEY}", [(f"app.{_KEY}", f"token={_KEY}")], span_id=_KEY),
        _span(f"call {_KEY}", [("app.config", f"api_key={_PLACEHOLDER}")], span_id="bb" * 8),
        _span(base64.b64encode(_KEY.encode()).decode(), [(f"app.{_KEY.encode().hex()}", _KEY)],
              span_id="cc" * 8),
    ])
    surface = scan_surface(decode_input(body.encode()))
    values = {v for s in surface.strings for v in _matched_values(s.text)}
    assert _KEY in values and _PLACEHOLDER in values
    # A span id is lowercased off the wire, so its lowercased form counts.
    values |= {v.lower() for v in values}
    display = Display([n for v in values for n, _ in needles(v)], values)

    hits = classify_exposure(surface, DEFAULT_CATALOG).hits
    assert hits
    for hit in hits:
        for field in (hit.span_ref, hit.span_name, *hit.location.split(".")):
            assert field == WITHHELD or not display.holds_value(field), hit
