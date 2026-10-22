"""Acceptance tests for `weir audit` (docs/audit.md), written before the
implementation.

Each test plants fake values in a fake home, inventories it with the real
`weir inventory`, writes a session or telemetry file with a value in a place
docs/audit.md classifies, and expects what the document says. Credential
ids come from the inventory report; lines and locations come from where the
fixture builders put each value.

1. A credential in a tool result entered the agent's context.
2. A credential in a tool call's input was sent out in a tool call.
3. Every encoded form is found, under that form.
4. An unrecognised format, an unparsed line, a file not scanned or a hit of
   unknown kind is "unknown" (exit 3), never a clean zero; so is a key that
   does not match the store (exit 2).
5. No output holds a value or any 6-character run of one.
"""

from __future__ import annotations

import base64
import gzip
import json
import urllib.parse
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest

# --- 1. a tool result is the agent's context --------------------------------


def _clean_session(setup: fx.Setup, path: Path) -> Path:
    session = fx.Session()
    session.prompt("list the files here")
    session.tool_use("Bash", {"command": "ls"}, "toolu_01")
    session.tool_result("toolu_01", "README.md\nsrc\n")
    return session.write(path)


def test_a_credential_in_a_claude_code_tool_result_entered_the_context(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    session = fx.Session()
    session.prompt("show me the env file")
    session.tool_use("Bash", {"command": "cat .env"}, "toolu_01")
    line, location = session.tool_result("toolu_01", f"{fx.ACME}={value}\nDEBUG=1\n")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    report = run.report
    assert report["result"] == "exposed"
    cid = setup.ids[fx.ACME]
    row = fx.credential(report, cid)
    assert (row["state"], row["context"], row["tool_call"]) == ("in_context", 1, 0)
    assert fx.hits(report, cid) == [
        {
            "credential": cid, "kind": "context", "file": str(path), "line": line,
            "format": "claude-code", "record": "user", "signal": None, "span": None,
            "span_id": None, "log_record": None, "metric": None, "tool": "Bash",
            "argument": None, "location": location, "form": "raw",
        }
    ]
    for name in (fx.SPECIAL, fx.GH, fx.AWS_ID, fx.AWS_SECRET):
        assert fx.credential(report, setup.ids[name])["state"] == "not_found"


def test_a_credential_in_an_otlp_tool_result_entered_the_context(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    path = fx.write_otlp(
        tmp_path / "otlp.jsonl",
        fx.tool_span("Bash", json.dumps({"command": "cat .env"}), f"{fx.ACME}={value}\n"),
    )

    run = setup.audit([path])

    assert run.exit_code == 1
    cid = setup.ids[fx.ACME]
    assert fx.credential(run.report, cid)["state"] == "in_context"
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["format"], hit["line"], hit["signal"], hit["span"]) == (
        "context", "otlp", 1, "traces", "execute_tool Bash",
    )
    assert (hit["tool"], hit["location"], hit["form"]) == (
        "Bash", "attributes.gen_ai.tool.call.result", "raw",
    )


# --- 2. a tool call's input was sent out ------------------------------------


def test_a_credential_in_a_claude_code_tool_use_input_was_sent_out(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    session = fx.Session()
    session.prompt("call the api")
    command = f"curl -H 'Authorization: Bearer {value}' https://api.invalid/v1"
    line = session.tool_use("Bash", {"command": command}, "toolu_01")
    session.tool_result("toolu_01", "{}")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    cid = setup.ids[fx.ACME]
    row = fx.credential(run.report, cid)
    assert (row["state"], row["tool_call"], row["context"]) == ("in_tool_call", 1, 0)
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["line"], hit["record"], hit["tool"], hit["argument"]) == (
        "tool_call", line, "assistant", "Bash", "command",
    )
    assert (hit["location"], hit["form"]) == ("message.content[0].input.command", "raw")


def test_a_credential_in_otlp_tool_call_arguments_was_sent_out(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    arguments = json.dumps({"url": "https://api.invalid/v1", "token": value})
    path = fx.write_otlp(tmp_path / "otlp.jsonl", fx.tool_span("http_get", arguments, "ok"))

    run = setup.audit([path])

    assert run.exit_code == 1
    cid = setup.ids[fx.ACME]
    assert fx.credential(run.report, cid)["state"] == "in_tool_call"
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["tool"], hit["argument"], hit["form"]) == (
        "tool_call", "http_get", "token", "raw",
    )
    assert hit["location"] == "attributes.gen_ai.tool.call.arguments.token"


def test_a_credential_in_an_otlp_output_tool_call_part_was_sent_out(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    messages = [
        {
            "role": "assistant",
            "parts": [
                {"type": "text", "content": "calling the api"},
                {
                    "type": "tool_call", "id": "call_1", "name": "http_get",
                    "arguments": {"headers": {"authorization": f"Bearer {value}"}},
                },
            ],
        }
    ]
    path = fx.write_otlp(tmp_path / "otlp.jsonl", fx.chat_span(messages))

    run = setup.audit([path])

    assert run.exit_code == 1
    (hit,) = fx.hits(run.report, setup.ids[fx.ACME])
    assert (hit["kind"], hit["tool"], hit["argument"]) == (
        "tool_call", "http_get", "headers.authorization",
    )
    assert hit["location"] == (
        "attributes.gen_ai.output.messages[0].parts[1].arguments.headers.authorization"
    )


# --- 2b. a tool call that names an environment credential sent it ------------


@pytest.mark.parametrize(
    "reference",
    ["$" + fx.GH, "${" + fx.GH + "}", "${" + fx.GH + ":-none}", "$env:" + fx.GH],
)
def test_a_tool_call_that_references_an_environment_credential_sent_it_by_name(
    tmp_path: Path, reference: str
) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt("call the api")
    command = f'curl -H "X-Token: {reference}" api.invalid'
    line = session.tool_use("Bash", {"command": command}, "t1")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    cid = setup.ids[fx.GH]
    row = fx.credential(run.report, cid)
    assert (row["state"], row["tool_call"], row["context"]) == ("in_tool_call", 1, 0)
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["form"], hit["line"], hit["tool"], hit["argument"]) == (
        "tool_call", "name", line, "Bash", "command",
    )
    assert "TOOL_CALL" in setup.audit([path], as_json=False).stdout


@pytest.mark.parametrize(
    "text",
    [
        "\\$" + fx.GH,  # escaped: the shell does not expand it
        "$" + fx.GH + "_OLD",  # another variable
        "$X" + fx.GH,  # another variable
        "$$" + fx.GH,  # the process id, then text
    ],
)
def test_text_that_only_resembles_a_reference_is_not_one(tmp_path: Path, text: str) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt("call the api")
    session.tool_use("Bash", {"command": f"echo {text}"}, "t1")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 0
    assert fx.credential(run.report, setup.ids[fx.GH])["state"] == "not_found"


def test_a_reference_outside_a_tool_call_or_to_a_file_credential_is_not_a_hit(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt(f"why is ${fx.GH} unset?")  # a prompt: no tool expands it
    session.tool_use("Bash", {"command": f"echo ${fx.AWS_SECRET}"}, "t1")  # not an env credential
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 0
    for name in (fx.GH, fx.AWS_SECRET):
        assert fx.credential(run.report, setup.ids[name])["state"] == "not_found"


def test_a_dynamic_environment_credential_is_found_by_name(tmp_path: Path) -> None:
    setup = fx.build(tmp_path, bashrc='export DYN_TOKEN="$(pass show acme/dyn)"\n')
    report = json.loads(setup.report.read_text())
    (dyn,) = [c for c in report["credentials"] if c["name"] == "DYN_TOKEN"]
    assert (dyn["source"], dyn["value_state"]) == ("environment", "dynamic")
    session = fx.Session()
    session.prompt("deploy")
    session.tool_use("Bash", {"command": "deploy --token \"$DYN_TOKEN\""}, "t1")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    row = fx.credential(run.report, dyn["id"])
    assert (row["state"], row["tool_call"]) == ("in_tool_call", 1)


# --- 3. every encoded form is found -----------------------------------------


def _base64url_with_marker(value: str) -> str:
    """`user:<value>` after a filler, URL-safe base64, with the filler's
    length chosen so the value's own characters encode to a `-` or `_` and
    so differ from standard base64 (the fixture's value holds a `~` for
    that). The decoded text is still the assignment `<filler>user:<value>`."""
    for filler in range(3):
        plain = b"u" * filler + b"user:" + value.encode()
        encoded = base64.urlsafe_b64encode(plain).decode().rstrip("=")
        core = encoded[(8 * (filler + 5) + 5) // 6 :]
        if "-" in core or "_" in core:
            return encoded
    raise AssertionError("no filler gives a URL-safe character")


_ENCODED = {
    "json": lambda v: json.dumps({"secret": v}),
    "json2": lambda v: json.dumps({"doc": json.dumps({"secret": v})}),
    "url": lambda v: f"GET https://api.invalid/v1?token={urllib.parse.quote(v, safe='')}&page=2",
    "base64": lambda v: "Authorization: Basic " + base64.b64encode(b"user:" + v.encode()).decode(),
    "base64url": lambda v: f"segment {_base64url_with_marker(v)} end",
    "hex": lambda v: f"blob {v.encode().hex()} end",
}


@pytest.mark.parametrize("form", list(_ENCODED))
def test_an_encoded_form_is_found_under_that_form(tmp_path: Path, form: str) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.SPECIAL]
    text = _ENCODED[form](value)
    assert value not in text
    session = fx.Session()
    session.prompt("read the response")
    session.tool_use("Read", {"file_path": "/fake/home/work/proj/response.txt"}, "toolu_01")
    line, location = session.tool_result("toolu_01", text)
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    cid = setup.ids[fx.SPECIAL]
    assert fx.credential(run.report, cid)["state"] == "in_context"
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["line"], hit["location"], hit["form"]) == (
        "context", line, location, form,
    )


def test_the_url_form_finds_a_value_inside_a_fully_encoded_nested_url(tmp_path: Path) -> None:
    """In `%3D<value>%26` the value is glued to `3D` and `26`, so no
    candidate of the encoded string is the value; the decoded string has
    one between its `=` and `&`."""
    setup = fx.build(tmp_path)
    value = setup.values[fx.ACME]
    nested = urllib.parse.quote(f"https://x.invalid/?token={value}&y=1", safe="")
    text = f"Location: https://login.invalid/cb?redirect={nested}"
    assert f"%3D{value}%26" in text
    session = fx.Session()
    session.prompt("follow the redirect")
    session.tool_use("Bash", {"command": "curl -sI https://login.invalid/"}, "toolu_01")
    line, location = session.tool_result("toolu_01", text)
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 1
    (hit,) = fx.hits(run.report, setup.ids[fx.ACME])
    assert (hit["kind"], hit["line"], hit["location"], hit["form"]) == (
        "context", line, location, "url",
    )


def test_the_raw_form_finds_a_value_holding_every_special_character(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    value = setup.values[fx.SPECIAL]
    session = fx.Session()
    line, location = session.assistant_text(f"The secret is {value} .")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    (hit,) = fx.hits(run.report, setup.ids[fx.SPECIAL])
    assert (hit["kind"], hit["line"], hit["location"], hit["form"]) == (
        "context", line, location, "raw",
    )


# --- 4. unknown is never a false zero ---------------------------------------


def _unknown(run: fx.Run) -> list[tuple[str, str]]:
    return [(u["reason"], u["subject"]) for u in run.report["unknown"]]  # type: ignore[index,union-attr]


def test_a_clean_recognised_session_is_clean(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    run = setup.audit([_clean_session(setup, tmp_path / "s.jsonl")])
    assert run.exit_code == 0
    assert run.report["result"] == "clean"
    assert run.report["unknown"] == []
    for cid in setup.ids.values():
        assert fx.credential(run.report, cid)["state"] == "not_found"


def test_an_unrecognised_format_is_unknown_not_zero(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = _clean_session(setup, tmp_path / "s.jsonl")
    notes = tmp_path / "notes.log"
    cfx.write(notes, "build started\nbuild finished\n")

    run = setup.audit([session, notes])

    assert run.exit_code == 3
    assert run.report["result"] == "unknown"
    assert _unknown(run) == [("unrecognised_format", str(notes))]
    (row,) = [f for f in run.report["files"] if f["file"] == str(notes)]  # type: ignore[union-attr,index]
    assert row["format"] == "unknown"


def test_a_value_in_an_unrecognised_format_is_an_unknown_hit_not_a_clean_one(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path)
    notes = tmp_path / "notes.log"
    cfx.write(notes, f"one\ntoken {setup.values[fx.ACME]} used\n")

    run = setup.audit([notes])

    assert run.exit_code == 3
    cid = setup.ids[fx.ACME]
    assert fx.credential(run.report, cid)["state"] == "unknown"
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["format"], hit["line"], hit["location"]) == (
        "unknown", "unknown", 2, None,
    )
    assert ("unknown_kind", f"{notes}:2") in _unknown(run)


def test_a_compressed_file_is_not_scanned_and_unknown(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = _clean_session(setup, tmp_path / "s.jsonl")
    packed = tmp_path / "old.jsonl.gz"
    packed.write_bytes(gzip.compress(session.read_bytes(), mtime=0))

    run = setup.audit([session, packed])

    assert run.exit_code == 3
    assert _unknown(run) == [("not_scanned", str(packed))]


def test_an_unparsed_session_line_is_unknown(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt("list the files here")
    broken = session.raw_line('{"type": "user", "message": {"role": "user", "content": "trunc')
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 3
    assert _unknown(run) == [("unparsed_line", f"{path}:{broken}")]


def test_a_value_in_an_unrecognised_record_type_is_unknown_not_clean(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt("list the files here")
    line = session.record(
        {"type": "future-record", "sessionId": fx.SESSION_ID, "data": {"blob": setup.values[fx.GH]}}
    )
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path])

    assert run.exit_code == 3
    assert run.report["result"] == "unknown"
    cid = setup.ids[fx.GH]
    assert fx.credential(run.report, cid)["state"] == "unknown"
    (hit,) = fx.hits(run.report, cid)
    assert (hit["kind"], hit["line"], hit["record"], hit["location"]) == (
        "unknown", line, "future-record", "data.blob",
    )
    assert _unknown(run) == [("unknown_kind", f"{path}:{line}")]


def test_a_key_that_does_not_match_the_store_is_an_error_not_a_clean_result(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path)
    session = _clean_session(setup, tmp_path / "s.jsonl")
    other = tmp_path / "other.key"
    cfx.write(other, "ab" * 32 + "\n")

    run = setup.audit([session], key=other)

    assert run.exit_code == 2
    assert run.stdout == ""
    assert str(other) in run.stderr


# --- 5. output never holds a value -------------------------------------------


def _everything_session(setup: fx.Setup, path: Path) -> Path:
    """Every credential, in context, in tool calls and in hostile places: a
    tool name, a JSON key and a record type that are themselves values."""
    v = setup.values
    session = fx.Session()
    session.prompt(f"use {v[fx.GH]} for github")
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_01")
    session.tool_result("toolu_01", f"{fx.AWS_ID} = {v[fx.AWS_ID]}\n")
    session.tool_use(v[fx.ACME], {v[fx.ACME]: "x", "q": json.dumps({"s": v[fx.SPECIAL]})}, "t2")
    session.tool_result("t2", base64.b64encode(f"u:{v[fx.SPECIAL]}".encode()).decode())
    session.record({"type": v[fx.GH], "sessionId": fx.SESSION_ID, "note": v[fx.ACME]})
    return session.write(path)


def test_no_output_holds_a_value_or_a_fragment_of_one(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = _everything_session(setup, tmp_path / "s.jsonl")
    named = tmp_path / f"{setup.values[fx.ACME]}.log"
    cfx.write(named, f"x {setup.values[fx.GH]}\n")
    otlp = fx.write_otlp(
        tmp_path / "otlp.jsonl",
        fx.tool_span(setup.values[fx.GH], json.dumps({"k": setup.values[fx.ACME]}), "ok"),
    )
    bad_key = tmp_path / "other.key"
    cfx.write(bad_key, "cd" * 32 + "\n")

    runs = [
        setup.audit([session, named, otlp], as_json=True),
        setup.audit([session, named, otlp], as_json=False),
        setup.audit([tmp_path], as_json=False),
        setup.audit([session], key=bad_key),
    ]

    assert [r.exit_code for r in runs] == [1, 1, 1, 2]
    for run in runs:
        cfx.assert_value_free(run.stdout + "\n" + run.stderr, setup.values.values())
    report = runs[0].report
    for name in setup.values:
        assert fx.credential(report, setup.ids[name])["state"] != "not_found", name
