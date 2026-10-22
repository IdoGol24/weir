"""The judge against docs/canary.md itself.

Every expectation here is read out of the contract: its tables name the
forms, kinds, evidence types, flow statuses, coverage states, incomplete
reasons, exit codes and report fields, its locations table names where a
hit is placed, and its text-report example is rebuilt as a fixture and
must print byte for byte. Where the code and the text disagree, one of them
is a bug, and these tests say which line of the doc moved.
"""

from __future__ import annotations

import base64
import json
import re
import typing
from pathlib import Path

import canary_fixtures as fx
import msgspec
import pytest

from weir.canary import (
    EXIT_CODES,
    Coverage,
    Direct,
    DirectEntry,
    Exercised,
    Flow,
    Form,
    Hit,
    IncompleteReason,
    Network,
    NetworkState,
    Placement,
    PlacementState,
    Report,
    State,
    Unexpected,
)

_DOC = (Path(__file__).parents[3] / "docs" / "canary.md").read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """The text under a markdown heading, up to the next heading of the
    same or a higher level."""
    match = re.search(rf"^(#+) {re.escape(heading)}\n", _DOC, re.MULTILINE)
    assert match, f"docs/canary.md has no heading {heading!r}"
    level = len(match.group(1))
    rest = _DOC[match.end() :]
    end = re.search(rf"^#{{1,{level}}} ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def _table(text: str, index: int = 0) -> list[list[str]]:
    """Rows of the `index`th markdown table in `text`, header and rule dropped."""
    tables: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("|"):
            current.append([cell.strip() for cell in line.strip().strip("|").split("|")])
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables[index][2:]


def _ticked(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def _first_ticked(rows: list[list[str]]) -> list[str]:
    return [_ticked(row[0])[0] for row in rows]


def _literal_args(cls: type[msgspec.Struct], field: str) -> set[str]:
    hints = typing.get_type_hints(cls, include_extras=True)
    return set(typing.get_args(hints[field]))


# --- tables -----------------------------------------------------------------


def test_forms_match_the_contract_table_in_order() -> None:
    assert _first_ticked(_table(_section("The encoded forms"))) == [f.value for f in Form]


def test_kinds_match_the_contract_table() -> None:
    kinds = _first_ticked(_table(_section("Placements and kinds")))
    assert set(kinds) == _literal_args(Placement, "kind")


def _ledger_rows() -> dict[str, list[tuple[str, str]]]:
    rows: dict[str, list[tuple[str, str]]] = {}
    record = ""
    for row in _table(_section("The ledger (`canary-ledger/1`)")):
        record = (_ticked(row[0]) or [row[0]])[0] if row[0] else record
        rows.setdefault(record, []).append((_ticked(row[1])[0], row[3]))
    return rows


def test_ledger_record_fields_match_the_contract_table() -> None:
    rows = _ledger_rows()
    structs: dict[str, type[msgspec.Struct]] = {
        "placement": Placement,
        "exercised": Exercised,
        "flow": Flow,
        "unexpected": Unexpected,
        "network": Network,
        "direct": Direct,
    }
    assert set(rows) == {"header", *structs}
    for record, cls in structs.items():
        assert [name for name, _ in rows[record]] == [
            f.name for f in msgspec.structs.fields(cls)
        ], record


def test_ledger_enumerations_match_the_contract_table() -> None:
    rows = dict(_ledger_rows()["exercised"]) | {f"flow.{k}": v for k, v in _ledger_rows()["flow"]}
    rows |= {f"direct.{k}": v for k, v in _ledger_rows()["direct"]}
    assert set(_ticked(rows["evidence"])) == _literal_args(Exercised, "evidence")
    assert set(_ticked(rows["flow.status"])) == _literal_args(Flow, "status")
    assert set(_ticked(rows["direct.protocol"])) == _literal_args(Direct, "protocol")


def test_coverage_states_and_incomplete_reasons_match_the_contract() -> None:
    section = _section("Coverage states")
    assert _first_ticked(_table(section, 0)) == [s.value for s in State]
    assert set(_first_ticked(_table(section, 1))) == {r.value for r in IncompleteReason}


def test_exit_code_table_matches_the_report_results() -> None:
    rows = _table(_section("Exit codes"))
    by_result = {_ticked(row[1])[0]: int(_ticked(row[0])[0]) for row in rows if row[1] != "none"}
    assert by_result == {result.value: code for result, code in EXIT_CODES.items()}
    report_row = dict((r[0], r[2]) for r in _table(_section("The JSON report (`canary-report/1`)")))
    assert [int(c) for c in _ticked(report_row["`exit_code`"])] == sorted(by_result.values())


def test_report_fields_are_in_the_contract_schema_order() -> None:
    section = _section("The JSON report (`canary-report/1`)")
    top = _table(section, 0)
    assert _first_ticked(top) == [f.name for f in msgspec.structs.fields(Report)]
    meaning = {_ticked(row[0])[0]: row[2] for row in top}
    placement_fields = re.search(r"`\{([^}]*)\}`", meaning["placements"])
    assert placement_fields
    assert [f.strip() for f in placement_fields.group(1).split(",")] == [
        f.name for f in msgspec.structs.fields(PlacementState)
    ]
    assert _ticked(meaning["coverage"]) == [f.name for f in msgspec.structs.fields(Coverage)]
    network_fields = _ticked(meaning["network"])
    assert network_fields[:3] == [f.name for f in msgspec.structs.fields(NetworkState)]
    direct_fields = re.search(r"`\{([^}]*)\}`", meaning["network"])
    assert direct_fields
    assert [f.strip() for f in direct_fields.group(1).split(",")] == [
        f.name for f in msgspec.structs.fields(DirectEntry)
    ]
    assert _first_ticked(_table(section, 1)) == [f.name for f in msgspec.structs.fields(Hit)]
    hit_forms = dict((_ticked(r[0])[0], r[2]) for r in _table(section, 1))["form"]
    assert _ticked(hit_forms) == [f.value for f in Form]


def test_reserved_kinds_are_rejected_as_unknown(tmp_path: Path) -> None:
    paragraph = _section("Placements and kinds").split("**Reserved for a later release.**")[1]
    reserved = _ticked(paragraph.split("\n\n")[0])
    assert "tool-field" in reserved and "registered" in reserved
    for kind in reserved:
        ledger = fx.write_ledger(
            tmp_path / "ledger.jsonl", [fx.placement("p.one", fx.fake_value(kind), kind=kind)]
        )
        fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("s")) + "\n")
        run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
        assert run.exit_code == 2, kind
        assert run.stdout == ""
        assert "line 2" in run.stderr


# --- locations ----------------------------------------------------------------

_KV_LISTS = {"attributes", "filteredAttributes", "metadata"}


def _tokens(location: str) -> list[str | int]:
    tokens: list[str | int] = []
    for part in location.split("."):
        match = re.fullmatch(r"(\w+)((?:\[\d+\])*)", part)
        assert match, location
        tokens.append(match.group(1))
        tokens += [int(i) for i in re.findall(r"\[(\d+)\]", match.group(2))]
    return tokens


def _build(tokens: list[str | int], value: str, signal: str) -> dict[str, object]:
    """The OTLP/JSON members that put `value` at `tokens` within a record."""
    name = tokens[0]
    assert isinstance(name, str)
    if name in _KV_LISTS:
        assert len(tokens) == 2, tokens
        return {name: [fx.kv(str(tokens[1]), value)]}
    if len(tokens) > 1 and isinstance(tokens[1], int):
        index = tokens[1]
        items = [{} for _ in range(index)] + [_build(tokens[2:], value, signal)]
        if name == "dataPoints":
            return {"gauge": {"dataPoints": items}}
        return {name: items}
    if len(tokens) == 1:
        return {name: {"stringValue": value} if name == "body" else value}
    return {name: _build(tokens[1:], value, signal)}


def _location_rows() -> list[tuple[str, list[str]]]:
    rows = _table(_section("Locations"))
    out: list[tuple[str, list[str]]] = []
    for row in rows:
        signal = _ticked(row[0])[0]
        if signal != "raw":
            out.append((signal, _ticked(row[2])))
    return out


@pytest.mark.parametrize(
    ("signal", "location"),
    [(signal, loc) for signal, locs in _location_rows() for loc in locs],
)
def test_every_location_in_the_contract_table_is_reported_there(
    tmp_path: Path, signal: str, location: str
) -> None:
    concrete = location.replace("<key>", "k1").replace("<i>", "1").replace("<j>", "1")
    value = fx.fake_value(location)
    members = _build(_tokens(concrete), value, signal)
    if signal == "traces":
        line = fx.traces({**fx.span("record"), **members})
    elif signal == "logs":
        line = fx.logs({"severityNumber": 9, **members})
    else:
        line = fx.metrics({"name": "record", **members} if "name" not in members else members)
    fx.write((tmp_path / "otlp.jsonl"), line + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], as_json=True)
    fx.assert_value_free(run.stdout, [value])
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    assert [(h["signal"], h["location"], h["form"]) for h in hits] == [(signal, concrete, "raw")]
    record = {"traces": "span", "logs": "log_record", "metrics": "metric"}[signal]
    assert hits[0][record] is not None


def test_strings_outside_any_record_are_located_under_resource_or_scope(tmp_path: Path) -> None:
    found = re.search(r"Strings\s+outside\s+any\s+record(.*?)\n\n", _section("Locations"), re.S)
    assert found
    paragraph = found.group(1)
    assert "`resource.`" in paragraph and "`scope.`" in paragraph
    values = {
        loc: fx.fake_value(loc)
        for loc in (
            "resource.attributes.k1",
            "resource.schemaUrl",
            "scope.name",
            "scope.version",
            "scope.attributes.k1",
            "scope.schemaUrl",
        )
    }
    request = {
        "resourceSpans": [
            {
                "resource": {"attributes": [fx.kv("k1", values["resource.attributes.k1"])]},
                "schemaUrl": values["resource.schemaUrl"],
                "scopeSpans": [
                    {
                        "scope": {
                            "name": values["scope.name"],
                            "version": values["scope.version"],
                            "attributes": [fx.kv("k1", values["scope.attributes.k1"])],
                        },
                        "schemaUrl": values["scope.schemaUrl"],
                        "spans": [fx.span("record")],
                    }
                ],
            }
        ]
    }
    fx.write((tmp_path / "otlp.jsonl"), json.dumps(request) + "\n")
    ledger = fx.write_ledger(
        tmp_path / "ledger.jsonl", [fx.placement(f"p.{loc}", v) for loc, v in values.items()]
    )
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"], as_json=True)
    fx.assert_value_free(run.stdout, values.values())
    hits = typing.cast(list[dict[str, object]], run.report["hits"])
    assert {(h["placement"], h["location"]) for h in hits} == {(f"p.{loc}", loc) for loc in values}
    assert all(h["span"] is None and h["span_id"] is None for h in hits)


def test_a_nested_value_extends_the_location_as_the_contract_shows(tmp_path: Path) -> None:
    example = re.search(r"Nested values extend the location as in\s+`([^`]+)`", _DOC)
    assert example
    location = example.group(1)  # attributes.app.config.headers[0]
    match = re.fullmatch(r"attributes\.(.+)\.(\w+)\[(\d+)\]", location)
    assert match
    key, inner, index = match.group(1), match.group(2), int(match.group(3))
    value = fx.fake_value(location)
    array = [{"stringValue": "other"}] * index + [{"stringValue": f"Bearer {value}"}]
    attribute = {
        "key": key,
        "value": {
            "kvlistValue": {"values": [{"key": inner, "value": {"arrayValue": {"values": array}}}]}
        },
    }
    fx.write((tmp_path / "otlp.jsonl"), fx.traces(fx.span("s", attributes=[attribute])) + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("p.one", value)])
    run = fx.judge(ledger, [tmp_path / "otlp.jsonl"])
    assert fx.leak_lines(run) == [
        f'LEAK p.one file={tmp_path / "otlp.jsonl"}:1 signal=traces span="s" at={location} form=raw'
    ]


# --- the text-report example, rebuilt -------------------------------------------

_LEAK = re.compile(
    r"LEAK (?P<placement>\S+) file=(?P<file>\S+):(?P<line>\d+) signal=(?P<signal>\w+)"
    r"(?: span=(?P<span>\"[^\"]*\"))?(?: at=(?P<at>\S+))? form=(?P<form>\w+)"
)
_COVERAGE = re.compile(
    r"coverage: (?P<P>\d+) placements \((?P<L>\d+) leaked, (?P<E>\d+) exercised, (?P<N>\d+) not"
    r" exercised, (?P<R>\d+) required\), (?P<F>\d+) flows \((?P<K>\d+) ok\), (?P<files>\d+) files,"
    r" (?P<S>\d+) spans, (?P<G>\d+) log records, (?P<M>\d+) metric data points, (?P<T>\d+)"
    r" strings, (?P<B>\d+) bytes swept"
)


def _example_block() -> str:
    block = re.search(r"```text\n(.*?)```", _section("The text report"), re.DOTALL)
    assert block
    return block.group(1)


def _count_strings(node: object) -> int:
    """Every JSON string in a request: the contract's 'every string field
    and every stringValue' (no bytesValue in this fixture)."""
    if isinstance(node, str):
        return 1
    if isinstance(node, list):
        return sum(_count_strings(item) for item in typing.cast(list[object], node))
    if isinstance(node, dict):
        return sum(_count_strings(v) for v in typing.cast(dict[str, object], node).values())
    return 0


def _encode(form: str, value: str) -> str:
    if form == "raw":
        return f"cfg {value} end"
    if form == "base64":
        return "Basic " + base64.b64encode(b"svc-user:" + value.encode()).decode()
    raise AssertionError(f"the example uses form {form}; teach _encode to build it")


def _kind_of(placement: str) -> str:
    for prefix, kind in (("env.", "env"), ("code.", "code"), ("runtime.oauth.", "mock-oauth")):
        if placement.startswith(prefix):
            return kind
    raise AssertionError(placement)


def _build_example(root: Path, seed: str) -> tuple[Path, list[str], list[str], list[str]]:
    """Rebuild the doc's text-report example as a capture under `root`.

    Returns the ledger, the --otlp paths, the swept paths and the values.
    """
    lines = _example_block().splitlines()
    leaks = [m.groupdict() for m in map(_LEAK.fullmatch, lines) if m]
    assert leaks, "the example has no LEAK lines"
    not_exercised = [
        ln.removeprefix("not exercised: ") for ln in lines if ln.startswith("not exercised: ")
    ]
    coverage = _COVERAGE.fullmatch(next(ln for ln in lines if ln.startswith("coverage: ")))
    assert coverage
    want = {k: int(v) for k, v in coverage.groupdict().items()}
    assert not any(ln.startswith(("incomplete: ", "not scanned: ")) for ln in lines)

    ids = sorted({leak["placement"] for leak in leaks} | set(not_exercised))
    assert len(ids) == want["P"] and want["E"] == 0 and want["G"] == 0
    values = {pid: fx.fake_value(f"{seed}:{pid}") for pid in ids}
    leaked = sorted({leak["placement"] for leak in leaks})
    assert want["R"] <= len(leaked), "a required placement left unexercised would be incomplete"
    required = set(leaked[: want["R"]])
    records: list[dict[str, object]] = [
        fx.placement(pid, values[pid], kind=_kind_of(pid), required=pid in required) for pid in ids
    ]
    assert want["K"] == want["F"]
    records += [{"type": "flow", "id": f"flow{i}", "status": "ok"} for i in range(want["F"])]
    ledger = fx.write_ledger(root / "ledger.jsonl", records)

    telemetry: dict[str, dict[int, list[dict[str, object]]]] = {}
    swept: dict[str, dict[int, str]] = {}
    for leak in leaks:
        text = _encode(leak["form"], values[leak["placement"]])
        line = int(leak["line"])
        if leak["signal"] == "raw":
            swept.setdefault(leak["file"], {})[line] = text
            continue
        assert leak["signal"] == "traces" and leak["span"] and leak["at"]
        located = re.fullmatch(r"(?:events\[(\d+)\]\.)?attributes\.(.+)", leak["at"])
        assert located, leak["at"]
        attributes = [fx.kv(located.group(2), text)]
        if located.group(1) is None:
            record = fx.span(json.loads(leak["span"]), attributes=attributes)
        else:
            events = [{"name": "e"} for _ in range(int(located.group(1)))]
            events.append({"name": "e", "attributes": attributes})
            record = fx.span(json.loads(leak["span"]), events=events)
        telemetry.setdefault(leak["file"], {}).setdefault(line, []).append(record)

    otlp_paths = sorted(telemetry)
    hit_spans = sum(len(spans) for by_line in telemetry.values() for spans in by_line.values())
    filler_spans = want["S"] - hit_spans
    assert filler_spans >= 1
    files = len(telemetry) + len(swept)
    metrics_file = None
    if want["M"] or files < want["files"]:
        metrics_file = str(Path(otlp_paths[0]).parent / "metrics.jsonl")
        otlp_paths.append(metrics_file)
        files += 1
    assert files == want["files"]

    def telemetry_text(pad: int, odd: bool) -> dict[str, str]:
        out: dict[str, str] = {}
        first = otlp_paths[0]
        for path in sorted(telemetry):
            by_line = telemetry[path]
            body: list[str] = []
            for number in range(1, max(by_line) + 1):
                spans = list(by_line.get(number, []))
                if path == first and number == 1:
                    fill = [fx.span(f"filler {i}") for i in range(filler_spans)]
                    fill[0]["attributes"] = [fx.kv(f"pad{i}", "x") for i in range(pad)]
                    if odd:
                        fill[0]["traceState"] = "x"
                    spans = fill + spans
                body.append(fx.traces(*spans))
            out[path] = "".join(line + "\n" for line in body)
        if metrics_file:
            out[metrics_file] = fx.metrics(fx.gauge("filler", points=want["M"])) + "\n"
        return out

    base = sum(
        _count_strings(json.loads(line))
        for text in telemetry_text(0, False).values()
        for line in text.splitlines()
    )
    extra = want["T"] - base
    assert extra >= 0
    texts = telemetry_text(extra // 2, bool(extra % 2))
    for path, text in texts.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        fx.write((root / path), text, encoding="utf-8")

    swept_bytes = want["B"] - sum(len(t.encode()) for t in texts.values())
    for index, (path, by_line) in enumerate(sorted(swept.items())):
        body = "".join(
            by_line.get(n, f"filler line {n}") + "\n" for n in range(1, max(by_line) + 1)
        )
        if index == len(swept) - 1:
            body += "." * (swept_bytes - len(body.encode()) - 1) + "\n"
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        fx.write((root / path), body, encoding="utf-8")
        swept_bytes -= len(body.encode())
    return ledger, otlp_paths, sorted(swept), list(values.values())


def test_the_contract_text_report_example_prints_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    ledger, otlp, swept, values = _build_example(tmp_path, "example")
    run = fx.judge(ledger.relative_to(tmp_path), otlp, swept)
    assert run.stdout == _example_block()
    assert run.exit_code == 1
    fx.assert_value_free(run.stdout, values)


def test_the_example_json_report_agrees_with_its_text_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    ledger, otlp, swept, values = _build_example(tmp_path, "example")
    report = fx.judge(ledger.relative_to(tmp_path), otlp, swept, as_json=True).report
    lines = _example_block().splitlines()
    hits = typing.cast(list[dict[str, object]], report["hits"])
    assert [(h["placement"], f"{h['file']}:{h['line']}", h["form"]) for h in hits] == [
        (m["placement"], f"{m['file']}:{m['line']}", m["form"])
        for m in (x.groupdict() for x in map(_LEAK.fullmatch, lines) if x)
    ]
    assert report["result"] == "leak" and report["exit_code"] == 1
    coverage = _COVERAGE.fullmatch(next(ln for ln in lines if ln.startswith("coverage: ")))
    assert coverage
    got = typing.cast(dict[str, int], report["coverage"])
    assert (got["placements"], got["spans"], got["strings"], got["bytes"]) == (
        int(coverage["P"]),
        int(coverage["S"]),
        int(coverage["T"]),
        int(coverage["B"]),
    )
    fx.assert_value_free(json.dumps(report), values)


def test_two_runs_with_fresh_values_print_identical_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/canary.md: the report depends on where values appear, never on
    what they are."""
    outputs: list[tuple[str, str]] = []
    for seed in ("first run", "second run"):
        root = tmp_path / seed.replace(" ", "-")
        root.mkdir()
        monkeypatch.chdir(root)
        ledger, otlp, swept, _ = _build_example(root, seed)
        text = fx.judge(ledger.relative_to(root), otlp, swept).stdout
        as_json = fx.judge(ledger.relative_to(root), otlp, swept, as_json=True).stdout
        outputs.append((text, as_json))
    assert outputs[0] == outputs[1]
