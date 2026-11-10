"""The decoded view of docs/canary.md ("The decoded view").

JSON lets a writer escape any character as `\\uXXXX`, so the judge also
matches text with its JSON escapes undone. Every escaped text here is built
with the standard library (canary_fixtures.u_escaped, json.dumps), never
with the judge's own decoder. The view's bound and the forms its hits are
named by are read from the contract, and the corpus case at the end derives
its expectation by running the judge on the same capture written plainly.
"""

from __future__ import annotations

import base64
import json
import re
import typing
from collections.abc import Callable
from pathlib import Path

import canary_fixtures as fx
import pytest

_DOC = (Path(__file__).parents[3] / "docs" / "canary.md").read_text(encoding="utf-8")


def _section(heading: str) -> str:
    match = re.search(rf"^(#+) {re.escape(heading)}\n(.*?)(?=^#{{1,3}} )", _DOC, re.M | re.S)
    assert match, heading
    return match.group(2)


def _bound() -> int:
    found = re.search(r"unescaped again, up to \*\*(\d+)\*\* times", _section("The decoded view"))
    assert found
    return int(found.group(1))


def _named() -> dict[tuple[str, int], str]:
    """(needle form, unescapings) -> the form a hit is named, from the
    contract's table; unescapings is 1, or 2 for "2 or more"."""
    rows = [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in _section("The decoded view").splitlines()
        if line.startswith("|")
    ][2:]
    named: dict[tuple[str, int], str] = {}
    for needles, once, more in rows:
        for needle in re.findall(r"`([^`]+)`", needles):
            for count, cell in ((1, once), (2, more)):
                ticked = re.findall(r"`([^`]+)`", cell)
                named[(needle, count)] = ticked[0] if ticked else needle
    return named


BOUND = _bound()
NAMED = _named()
JSON_ONCE = NAMED[("raw", 1)]
JSON_TWICE = NAMED[("raw", 2)]

# Which characters of a value are written `\uXXXX`: any subset may be.
# (index, length) -> whether that character is escaped.
_PATTERNS: dict[str, Callable[[int, int], bool]] = {
    "first": lambda i, n: i == 0,
    "every": lambda i, n: True,
    "every-fifth": lambda i, n: i % 5 == 0,
    "last": lambda i, n: i == n - 1,
}


def _value(seed: str, length: int = 24) -> str:
    """A fake value that starts and ends with a letter: `\\u0032` ends in
    the digit it escapes, so an escaped first or last digit would leave the
    value plain in the text."""
    for n in range(100):
        value = fx.fake_value(f"{seed}#{n}", length)
        if value[0].isalpha() and value[-1].isalpha():
            return value
    raise AssertionError(seed)


def _escaped(value: str, pattern: str = "first", *, upper: bool = False) -> str:
    picks = _PATTERNS[pattern]
    text = fx.u_escaped(value, lambda i: picks(i, len(value)), upper=upper)
    assert value not in text
    return text


def _otlp_with(tmp_path: Path, *attributes: dict[str, object]) -> Path:
    path = tmp_path / "otlp.jsonl"
    fx.write(path, fx.traces(fx.span("op", attributes=list(attributes))) + "\n")
    return path


def _run(
    tmp_path: Path,
    otlp: Path,
    values: dict[str, str],
    swept: list[Path] | None = None,
    *,
    requests: list[Path] | None = None,
    extra: list[dict[str, object]] | None = None,
) -> fx.Run:
    records: list[dict[str, object]] = [
        fx.placement(pid, value, providers=["model"]) for pid, value in values.items()
    ]
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [*records, *(extra or [])])
    run = fx.judge(ledger, [otlp], swept or [], as_json=True, requests=requests or [])
    fx.assert_value_free(run.stdout + run.stderr, values.values())
    text = fx.judge(ledger, [otlp], swept or [], requests=requests or [])
    fx.assert_value_free(text.stdout + text.stderr, values.values())
    return run


def _hits(run: fx.Run) -> list[dict[str, object]]:
    return typing.cast(list[dict[str, object]], run.report["hits"])


def _where(run: fx.Run) -> list[tuple[object, ...]]:
    return [(h["signal"], h["line"], h["location"], h["sink"], h["form"]) for h in _hits(run)]


# --- a structured string ----------------------------------------------------


@pytest.mark.parametrize("upper", [False, True])
@pytest.mark.parametrize("pattern", list(_PATTERNS))
def test_a_value_escaped_inside_a_json_string_attribute_is_a_json_hit(
    tmp_path: Path, pattern: str, upper: bool
) -> None:
    value = _value(f"args{pattern}{upper}")
    arguments = '{"query": "weather", "api_key": "' + _escaped(value, pattern, upper=upper) + '"}'
    otlp = _otlp_with(tmp_path, fx.kv("gen_ai.tool.call.arguments", arguments))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert run.exit_code == 1
    assert _where(run) == [("traces", 1, "attributes.gen_ai.tool.call.arguments", None, JSON_ONCE)]
    assert _hits(run)[0]["span"] == "op"


@pytest.mark.parametrize(
    "document",
    [
        lambda e: '"' + e + '"',  # a JSON string
        lambda e: "[1, null, " + '"' + e + '"]',  # an array
        lambda e: '{"' + e + '": true}',  # an object key
        lambda e: '{"a": {"b": ["' + e + '"]}}',  # nested
        lambda e: '{"k": "\\\\q \\\\x ' + e + '"}',  # other backslashes are left as they are
    ],
)
def test_every_shape_of_json_text_is_read_unescaped(
    tmp_path: Path, document: Callable[[str], str]
) -> None:
    value = _value("shape" + document(""))
    otlp = _otlp_with(tmp_path, fx.kv("payload", document(_escaped(value, "every-fifth"))))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert _where(run) == [("traces", 1, "attributes.payload", None, JSON_ONCE)]


# Text that holds no JSON: matched by its needles alone, as before the view.
_NOT_JSON: list[Callable[[str], str]] = [
    lambda e: "key=" + e,
    lambda e: '{"cut": "' + e,  # JSON cut short
    lambda e: "tool said " + e + " and stopped",
    lambda e: "\\q\\x " + e,
]


@pytest.mark.parametrize("text", _NOT_JSON)
@pytest.mark.parametrize("where", ["attribute", "stdout"])
def test_text_that_is_not_json_is_not_read_unescaped(
    tmp_path: Path, text: Callable[[str], str], where: str
) -> None:
    value = _value("notjson" + where + text(""))
    written = text(_escaped(value, "every"))
    stdout = tmp_path / "flow.stdout"
    fx.write(stdout, written + "\n" if where == "stdout" else "")
    attributes = [fx.kv("payload", written)] if where == "attribute" else []
    run = _run(tmp_path, _otlp_with(tmp_path, *attributes), {"env.KEY": value}, [stdout])
    assert _hits(run) == []
    assert run.report["incomplete"] == []


def _deep(text: str) -> str:
    """`text` as a JSON string nested in arrays past every decoder's depth
    limit."""
    depth = 100_000
    return "[" * depth + '"' + text + '"' + "]" * depth


@pytest.mark.parametrize(
    ("where", "prefix"),
    [("attribute", ""), ("stdout", ""), ("attribute", "INFO args "), ("stdout", "INFO args ")],
)
def test_json_nested_past_the_decoders_depth_limit_is_read(
    tmp_path: Path, prefix: str, where: str
) -> None:
    value = _value("deepjson" + where + prefix)
    written = prefix + _deep(_escaped(value))
    stdout = tmp_path / "flow.stdout"
    fx.write(stdout, written + "\n" if where == "stdout" else "")
    attributes = [fx.kv("payload", written)] if where == "attribute" else []
    run = _run(tmp_path, _otlp_with(tmp_path, *attributes), {"env.KEY": value}, [stdout])
    expected = ("traces", 1, "attributes.payload") if where == "attribute" else ("raw", 1, None)
    assert _where(run) == [(*expected, None, JSON_ONCE)]


def test_json_held_as_a_string_inside_json_is_a_json2_hit(tmp_path: Path) -> None:
    value = _value("twice")
    inner = '{"api_key": "' + _escaped(value) + '"}'
    outer = json.dumps({"messages": [{"role": "tool", "content": inner}]})
    otlp = _otlp_with(tmp_path, fx.kv("gen_ai.input.messages", outer))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert _where(run) == [("traces", 1, "attributes.gen_ai.input.messages", None, JSON_TWICE)]


def test_a_json_needle_found_after_one_unescaping_is_named_by_both(tmp_path: Path) -> None:
    """A mock-oauth value holding a quote: its json needle (the quote
    escaped) inside text whose letters were escaped once more."""
    value = _value("quote", 12) + '"' + _value("quote2", 12)
    content = fx.json_content(value)
    text = '"' + fx.u_escaped(content, lambda i: i == 0) + '"'
    assert fx.json_content(content) not in text and content not in text
    otlp = _otlp_with(tmp_path, fx.kv("payload", text))
    run = _run(tmp_path, otlp, {"oauth.token": value})
    assert _where(run) == [("traces", 1, "attributes.payload", None, NAMED[("json", 1)])]


def test_a_surrogate_pair_is_unescaped_as_one_character(tmp_path: Path) -> None:
    value = _value("pair", 10) + "\U0001f511" + _value("pair2", 10)
    escaped = fx.u_escaped(value, lambda i: True)
    assert "\\ud83d\\udd11" in escaped
    otlp = _otlp_with(tmp_path, fx.kv("payload", '{"t": "' + escaped + '"}'))
    run = _run(tmp_path, otlp, {"oauth.token": value})
    assert _where(run) == [("traces", 1, "attributes.payload", None, JSON_ONCE)]


def test_the_view_adds_nothing_where_the_text_already_holds_the_value(tmp_path: Path) -> None:
    value = _value("both")
    text = '{"a": "' + value + '", "b": "' + _escaped(value) + '"}'
    otlp = _otlp_with(tmp_path, fx.kv("payload", text))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert _where(run) == [("traces", 1, "attributes.payload", None, "raw")]


def test_other_forms_keep_their_name_after_unescaping(tmp_path: Path) -> None:
    """A base64 core holding a `/` written `\\/`, as some serializers do."""
    # An alphanumeric value has no `/` in its base64: `\xff` gives one.
    value, blob = "", ""
    for seed in range(200):
        value = _value(f"slash{seed}", 20) + "\xff\xff\xff"
        if "/" in _base64_core(value, 0):
            blob = fx.base64_embedded(value, 0)
            break
    assert "/" in _base64_core(value, 0)
    otlp = _otlp_with(tmp_path, fx.kv("auth", '{"basic": "' + blob.replace("/", "\\/") + '"}'))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert {h["form"] for h in _hits(run)} == {NAMED[("base64", 1)]}


def _base64_core(value: str, k: int) -> str:
    """docs/canary.md, "The base64 core": the characters whose 6 bits all
    come from the value, at byte offset `k`."""
    n = len(value.encode())
    encoded = base64.b64encode(b"\0" * k + value.encode()).decode()
    return encoded[-(-8 * k // 6) : (8 * (k + n)) // 6]


# --- the raw sweep and the request capture --------------------------------


@pytest.mark.parametrize(
    "line",
    [
        lambda e: '{"event": "tool", "args": {"api_key": "' + e + '"}}',
        lambda e: 'INFO calling tool with {"api_key": "' + e + '"}',
        lambda e: 'INFO [1] {"a": 1} then [{"args": {"api_key": "' + e + '"}}] done',
    ],
)
def test_a_swept_line_holding_an_escaped_value_is_a_json_hit(
    tmp_path: Path, line: Callable[[str], str]
) -> None:
    value = _value("swept" + line(""))
    stdout = tmp_path / "flow.stdout"
    fx.write(stdout, "start\n" + line(_escaped(value, "every")) + "\nend\n")
    otlp = _otlp_with(tmp_path)
    run = _run(tmp_path, otlp, {"env.KEY": value}, [stdout])
    assert run.exit_code == 1
    assert _where(run) == [("raw", 2, None, None, JSON_ONCE)]
    assert _hits(run)[0]["file"] == str(stdout)


def test_an_escaped_value_in_a_model_request_is_a_hit_to_the_model(tmp_path: Path) -> None:
    value = _value("request")
    arguments = '{"api_key": "' + _escaped(value) + '"}'
    body = json.dumps({"messages": [{"role": "tool", "content": arguments}]})
    record = fx.request(headers=[("Authorization", f"Bearer {value}")], body=body.encode())
    requests = fx.write_requests(tmp_path / "requests.jsonl", [record])
    run = _run(tmp_path, _otlp_with(tmp_path), {"env.KEY": value}, requests=[requests])
    assert _where(run) == [("requests", 2, "body.messages[0].content", "model", JSON_ONCE)]


# A request to the placement's own provider whose credential field holds
# the escaped spelling `e`.
_OWN_CREDENTIAL: list[Callable[[str], dict[str, object]]] = [
    lambda e: fx.request(headers=[("Authorization", "Bearer " + e)]),
    # A JSON string: still a credential field's value.
    lambda e: fx.request(headers=[("Authorization", '"' + e + '"')]),
    # A member of a JSON body, its value the escaped spelling.
    lambda e: fx.request(
        body=json.dumps({"model": "m", "api_key": e}).encode(),
        credential_fields=[("body", "api_key")],
    ),
]


@pytest.mark.parametrize("request_with", _OWN_CREDENTIAL)
def test_an_escaped_value_in_its_own_credential_field_is_not_evidence(
    tmp_path: Path, request_with: Callable[[str], dict[str, object]]
) -> None:
    """A credential field is matched as the mock matches it, wherever it
    sits: a provider would not accept the escaped spelling, so it neither
    exercises the value nor is a hit."""
    value = _value("own")
    record = request_with(_escaped(value))
    requests = fx.write_requests(tmp_path / "requests.jsonl", [record])
    run = _run(tmp_path, _otlp_with(tmp_path), {"env.KEY": value}, requests=[requests])
    assert _hits(run) == []
    placements = typing.cast(list[dict[str, object]], run.report["placements"])
    assert [(p["state"], p["evidence"]) for p in placements] == [("not_exercised", [])]


# --- the bound --------------------------------------------------------------


def _nested(value: str, unescapings: int, pattern: str = "first") -> str:
    """Text that holds `value` only after `unescapings` unescapings: some of
    its letters escaped, then the whole quoted again by stdlib json."""
    text = '"' + _escaped(value, pattern) + '"'
    for _ in range(unescapings - 1):
        text = json.dumps(text)
    return text


def test_the_bound_is_the_last_level_read_in_a_telemetry_string(tmp_path: Path) -> None:
    value = _value("deep")
    otlp = _otlp_with(tmp_path, fx.kv("payload", _nested(value, BOUND)))
    run = _run(tmp_path, otlp, {"env.KEY": value})
    assert _where(run) == [("traces", 1, "attributes.payload", None, JSON_TWICE)]
    assert run.report["incomplete"] == []


def test_a_telemetry_string_escaped_past_the_bound_is_incomplete(tmp_path: Path) -> None:
    """Two such strings on one line: the line is one unparsed record."""
    value = _value("deeper")
    deep = _nested(value, BOUND + 1)
    otlp = _otlp_with(tmp_path, fx.kv("payload", deep), fx.kv("again", deep))
    run = _run(tmp_path, otlp, {"env.KEY": value}, extra=[_exercised("env.KEY")])
    assert _hits(run) == []
    assert run.report["result"] == "incomplete"
    assert run.exit_code == 3
    assert run.report["incomplete"] == [{"reason": "unparsed_record", "subject": f"{otlp}:1"}]
    assert typing.cast(dict[str, int], run.report["coverage"])["unparsed_records"] == 1


def test_an_unread_telemetry_line_escaped_past_the_bound_is_one_unparsed_record(
    tmp_path: Path,
) -> None:
    """The walk cannot read it and the view cannot read it in full: still
    one record the judge could not search."""
    value = _value("unreaddeep")
    otlp = tmp_path / "otlp.jsonl"
    fx.write(otlp, fx.traces(fx.span("op")) + "\n[" + _nested(value, BOUND + 1) + "]\n")
    run = _run(tmp_path, otlp, {"env.KEY": value}, extra=[_exercised("env.KEY")])
    assert _hits(run) == []
    assert run.report["incomplete"] == [{"reason": "unparsed_record", "subject": f"{otlp}:2"}]
    assert typing.cast(dict[str, int], run.report["coverage"])["unparsed_records"] == 1


def test_the_bound_is_the_last_level_read_in_a_request_body_member(tmp_path: Path) -> None:
    """The body is one escaping above its member, so it holds the value one
    level deeper than the bound: its member is read, the body as a whole is
    not, so the request is read in full."""
    value = _value("bodydeep")
    body = json.dumps({"content": _nested(value, BOUND)})
    requests = fx.write_requests(tmp_path / "requests.jsonl", [fx.request(body=body.encode())])
    run = _run(tmp_path, _otlp_with(tmp_path), {"env.KEY": value}, requests=[requests])
    assert _where(run) == [("requests", 2, "body.content", "model", JSON_TWICE)]
    assert run.report["incomplete"] == []


def test_a_request_body_member_escaped_past_the_bound_is_incomplete(tmp_path: Path) -> None:
    value = _value("bodydeeper")
    body = json.dumps({"content": _nested(value, BOUND + 1)})
    requests = fx.write_requests(tmp_path / "requests.jsonl", [fx.request(body=body.encode())])
    run = _run(
        tmp_path,
        _otlp_with(tmp_path),
        {"env.KEY": value},
        requests=[requests],
        extra=[_exercised("env.KEY")],
    )
    assert _hits(run) == []
    assert run.report["incomplete"] == [{"reason": "unparsed_record", "subject": f"{requests}:2"}]


def test_a_swept_line_escaped_past_the_bound_is_incomplete(tmp_path: Path) -> None:
    """Line 3 holds two such arrays: it is one unparsed record."""
    value, shallow = _value("sweptdeep"), _value("sweptshallow")
    deep = _nested(value, BOUND + 1)
    stdout = tmp_path / "flow.stdout"
    lines = [_nested(shallow, BOUND), deep, f"INFO [{deep}] then [{deep}]"]
    fx.write(stdout, "\n".join(lines) + "\n")
    run = _run(
        tmp_path,
        _otlp_with(tmp_path),
        {"env.KEY": value, "env.SHALLOW": shallow},
        [stdout],
        extra=[_exercised("env.KEY")],
    )
    assert [(h["placement"], h["line"], h["form"]) for h in _hits(run)] == [
        ("env.SHALLOW", 1, JSON_TWICE)
    ]
    assert run.report["incomplete"] == [
        {"reason": "unparsed_record", "subject": f"{stdout}:{line}"} for line in (2, 3)
    ]
    coverage = typing.cast(dict[str, int], run.report["coverage"])
    assert coverage["unparsed_records"] == 2


def test_unparsed_lines_of_two_files_shown_alike_are_each_counted(tmp_path: Path) -> None:
    """Two telemetry files whose names hold the value both print as
    `[withheld]`: each keeps its own unparsed line in the count."""
    value = _value("twofiles")
    files = [tmp_path / f"otlp-{value}-{n}.jsonl" for n in (1, 2)]
    for path in files:
        fx.write(path, "not an export request\n" + fx.traces(fx.span("op")) + "\n")
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("env.KEY", value)])
    run = fx.judge(ledger, files, [], as_json=True)
    fx.assert_value_free(run.stdout + run.stderr, [value])
    coverage = typing.cast(dict[str, int], run.report["coverage"])
    assert coverage["unparsed_records"] == len(files)
    assert run.report["incomplete"] == [{"reason": "unparsed_record", "subject": "[withheld]:1"}]


def _exercised(pid: str) -> dict[str, object]:
    return {"type": "exercised", "placement": pid, "evidence": "request"}


# --- the printing rule ------------------------------------------------------


def test_capture_text_whose_unescaped_view_holds_a_value_is_withheld(tmp_path: Path) -> None:
    """No run of 6 of the value survives the escapes, yet the text undone
    is the value: printed, it would give the value away. A name is not
    JSON, so it is no hit itself, but it is never printed."""
    value = _value("printed")
    escaped = _escaped(value, "every-fifth")
    assert not any(value[i : i + fx.RUN] in escaped for i in range(len(value) - fx.RUN + 1))
    path = tmp_path / "otlp.jsonl"
    fx.write(path, fx.traces(fx.span(escaped, attributes=[fx.kv(escaped, value)])) + "\n")
    run = _run(tmp_path, path, {"env.KEY": value})
    assert [(h["span"], h["location"]) for h in _hits(run)] == [
        ("[withheld]", "attributes.[withheld]")
    ]


def test_capture_text_escaped_past_the_bound_is_withheld(tmp_path: Path) -> None:
    """The view cannot say what such a name holds, so it is not printed."""
    value, named = _value("plainhit"), _value("deepname")
    name = _nested(named, BOUND + 1, "every-fifth")
    assert not any(named[i : i + fx.RUN] in name for i in range(len(named) - fx.RUN + 1))
    path = tmp_path / "otlp.jsonl"
    fx.write(path, fx.traces(fx.span(name, attributes=[fx.kv("k", value)])) + "\n")
    run = _run(tmp_path, path, {"env.KEY": value, "env.NAMED": named})
    assert [(h["placement"], h["span"]) for h in _hits(run)] == [("env.KEY", "[withheld]")]


# --- the corpus case: derived by running the judge -------------------------


def _carrier(text: str) -> str:
    """A tool call's arguments as a program writes them, `text` as the
    content of one JSON string."""
    return '{"tool": "search", "args": {"api_key": "' + text + '"}}'


# How the arguments reach the capture: as the text itself, or printed in a
# log line around them.
_CARRIERS: dict[str, Callable[[str], str]] = {
    "json": _carrier,
    "log-line": lambda t: "INFO calling tool with " + _carrier(t) + " done",
}


def _rooted(node: object, root: str) -> object:
    """`node` with `root` written `<root>` in every string."""
    if isinstance(node, str):
        return node.replace(root, "<root>")
    if isinstance(node, list):
        return [_rooted(item, root) for item in typing.cast(list[object], node)]
    if isinstance(node, dict):
        items = typing.cast(dict[str, object], node).items()
        return {key: _rooted(item, root) for key, item in items}
    return node


_SPAN = fx.traces(fx.span("op"))
_CASES: dict[str, Callable[[str], tuple[str, str, str]]] = {
    # (telemetry line, swept text, model request body) holding `text` where
    # a program puts it.
    "span-attribute": lambda t: (fx.traces(fx.span("op", attributes=[fx.kv("a", t)])), "", ""),
    "span-name": lambda t: (fx.traces(fx.span(t)), "", ""),
    "event": lambda t: (
        fx.traces(fx.span("op", events=[{"name": "e", "attributes": [fx.kv("e", t)]}])),
        "",
        "",
    ),
    "log-body": lambda t: (fx.logs({"body": {"stringValue": t}}), "", ""),
    "metric": lambda t: (
        fx.metrics({"name": "m", "gauge": {"dataPoints": [{"attributes": [fx.kv("d", t)]}]}}),
        "",
        "",
    ),
    "resource": lambda t: (fx.traces(fx.span("op"), resource=[fx.kv("r", t)]), "", ""),
    "stdout": lambda t: (_SPAN, f"run 1\n{t}\n", ""),
    "model-request": lambda t: (
        _SPAN,
        "",
        json.dumps({"messages": [{"role": "tool", "content": t}]}),
    ),
}


def _report(tmp_path: Path, value: str, text: str, case: str, carrier: str) -> dict[str, object]:
    tmp_path.mkdir()
    line, swept, body = _CASES[case](_CARRIERS[carrier](text))
    otlp = tmp_path / "otlp.jsonl"
    fx.write(otlp, line + "\n")
    stdout = tmp_path / "flow.stdout"
    fx.write(stdout, swept)
    record = fx.request(body=body.encode())
    requests = [fx.write_requests(tmp_path / "requests.jsonl", [record])] if body else []
    ledger = fx.write_ledger(tmp_path / "ledger.jsonl", [fx.placement("env.KEY", value)])
    run = fx.judge(ledger, [otlp], [stdout], as_json=True, requests=requests)
    fx.assert_value_free(run.stdout, [value])
    report = run.report
    # The two captures differ in size only; every path is under its own root.
    typing.cast(dict[str, int], report["coverage"]).pop("bytes")
    return typing.cast(dict[str, object], _rooted(report, str(tmp_path)))


@pytest.mark.parametrize("carrier", list(_CARRIERS))
@pytest.mark.parametrize("pattern", list(_PATTERNS))
@pytest.mark.parametrize("case", list(_CASES))
def test_an_escaped_value_gives_the_report_the_plain_value_gives(
    tmp_path: Path, case: str, pattern: str, carrier: str
) -> None:
    """The same capture written twice, the value plain and then with some
    of its characters escaped: the judge's own report on the plain capture
    is the expectation, each hit's form renamed by the contract's table.
    The JSON is read the same whether it is the whole text or printed in a
    log line, wherever that line is written."""
    value = _value(f"corpus{case}{pattern}{carrier}")
    plain = _report(tmp_path / "plain", value, value, case, carrier)
    escaped = _report(tmp_path / "escaped", value, _escaped(value, pattern), case, carrier)
    hits = typing.cast(list[dict[str, object]], plain["hits"])
    assert hits and {h["form"] for h in hits} == {"raw"}
    for hit in hits:
        hit["form"] = NAMED[("raw", 1)]
    assert escaped == plain


def _unread_report(root: Path, value: str, text: str) -> dict[str, object]:
    """A capture whose lines no parser reads: an export request cut short
    when its writer died, its log record complete, as the last line of a
    telemetry file, and the same text as a request capture line that is
    not a request record."""
    root.mkdir()
    record = json.dumps({"body": {"stringValue": _carrier(text)}})
    cut = '{"resourceLogs": [{"scopeLogs": [{"logRecords": [' + record
    otlp = root / "otlp.jsonl"
    fx.write(otlp, fx.traces(fx.span("op")) + "\n" + cut)
    requests = root / "requests.jsonl"
    fx.write(requests, json.dumps({"schema": "canary-requests/1"}) + "\n" + cut + "\n")
    ledger = fx.write_ledger(root / "ledger.jsonl", [fx.placement("env.KEY", value)])
    run = fx.judge(ledger, [otlp], [], as_json=True, requests=[requests])
    fx.assert_value_free(run.stdout + run.stderr, [value])
    report = run.report
    typing.cast(dict[str, int], report["coverage"]).pop("bytes")
    return typing.cast(dict[str, object], _rooted(report, str(root)))


@pytest.mark.parametrize("pattern", list(_PATTERNS))
def test_an_escaped_value_on_a_line_no_parser_reads_gives_the_plain_report(
    tmp_path: Path, pattern: str
) -> None:
    """The raw sweep alone reads such a line, so its JSON gets the decoded
    view: the judge's report on the plain capture is the expectation, each
    hit's form renamed by the contract's table (the text sits in a JSON
    string, so the escaped value took two escapings)."""
    value = _value(f"unread{pattern}")
    plain = _unread_report(tmp_path / "plain", value, value)
    escaped = _unread_report(tmp_path / "escaped", value, _escaped(value, pattern))
    hits = typing.cast(list[dict[str, object]], plain["hits"])
    assert [(h["signal"], h["form"]) for h in hits] == [("raw", "raw"), ("raw", "raw")]
    assert plain["incomplete"]
    for hit in hits:
        hit["form"] = NAMED[("raw", 2)]
    assert escaped == plain
