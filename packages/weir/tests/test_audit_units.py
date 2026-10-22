"""`weir audit` behaviour beyond the acceptance tests (docs/audit.md): the
three inventory inputs, the Claude Code and OTLP classification tables, the
candidate rules, files and directories, the text report and determinism.

Fake data only, built by audit_fixtures under the test's temporary
directory, inventoried by the real `weir inventory`.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest

from weir.audit import inputs as audit_inputs
from weir.inventory import fingerprint as inventory_fingerprint

# --- the fingerprint and the key check agree with the inventory's -----------


@pytest.mark.parametrize("value", ["a", "é" * 3, "x\udcff y", cfx.fake_value("fp", 40)])
def test_the_audit_fingerprints_exactly_as_the_inventory_does(value: str) -> None:
    key = bytes(range(32))
    data = value.encode("utf-8", "surrogateescape")
    assert audit_inputs.fingerprint(key, data).hex() == inventory_fingerprint.fingerprint(
        key, value
    )
    assert audit_inputs.key_check(key) == inventory_fingerprint.key_check(key)
    assert audit_inputs.FINGERPRINT_VERSION == inventory_fingerprint.FINGERPRINT_VERSION


def test_the_store_carries_the_key_check_of_its_key(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    store = json.loads(setup.store.read_text())
    key = bytes.fromhex(setup.key.read_text().strip())
    assert store["key_check"] == inventory_fingerprint.key_check(key)


# --- the three inventory inputs ---------------------------------------------


def _session(setup: fx.Setup, path: Path, text: str = "README.md\n") -> Path:
    session = fx.Session()
    session.prompt("list the files here")
    session.tool_use("Bash", {"command": "ls"}, "toolu_01")
    session.tool_result("toolu_01", text)
    return session.write(path)


def _shown(given: Path | str, path: Path) -> str:
    """The name the report gives a file found under the directory `given`:
    the path as given, then the names below it joined by `/`."""
    return f"{given}/{path.relative_to(given).as_posix()}"


def _rewrite_json(path: Path, change: object) -> None:
    data = json.loads(path.read_text())
    change(data)  # type: ignore[operator]
    path.write_text(json.dumps(data))


def _error(run: fx.Run, setup: fx.Setup, *names: str) -> None:
    assert run.exit_code == 2
    assert run.stdout == ""
    assert run.stderr.startswith("error: ")
    for name in names:
        assert name in run.stderr
    cfx.assert_value_free(run.stderr, setup.values.values())


def test_a_store_without_a_key_check_is_refused(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    _rewrite_json(setup.store, lambda d: d.pop("key_check"))
    _error(setup.audit([_session(setup, tmp_path / "s.jsonl")]), setup, str(setup.store), "again")


def test_a_store_from_another_run_is_refused(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    other = fx.build(tmp_path / "other", extra_env="EXTRA_TOKEN=" + cfx.fake_value("x") + "\n")
    os.replace(other.store, setup.store)
    os.replace(other.key, setup.key)
    run = setup.audit([_session(setup, tmp_path / "s.jsonl")])
    _error(run, setup, str(setup.store), str(setup.report), "same")


def test_an_unsupported_fingerprint_version_is_refused(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    _rewrite_json(setup.store, lambda d: d["records"][0].update(fingerprint_v=2))
    _error(setup.audit([_session(setup, tmp_path / "s.jsonl")]), setup, "fingerprint_v 2")


@pytest.mark.parametrize("text", ["not hex at all", "ab" * 16, ""])
def test_a_key_that_is_not_64_hex_characters_is_refused(tmp_path: Path, text: str) -> None:
    setup = fx.build(tmp_path)
    bad = tmp_path / "bad.key"
    bad.write_text(text)
    _error(setup.audit([_session(setup, tmp_path / "s.jsonl")], key=bad), setup, str(bad))


def test_a_missing_key_is_refused_and_never_created(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    missing = tmp_path / "no.key"
    _error(setup.audit([_session(setup, tmp_path / "s.jsonl")], key=missing), setup, str(missing))
    assert not missing.exists()


def _reasons(run: fx.Run) -> list[tuple[str, str | None]]:
    return [(u["reason"], u["subject"]) for u in run.report["unknown"]]  # type: ignore[index,union-attr]


def test_an_empty_directory_is_never_clean(tmp_path: Path) -> None:
    """docs/audit.md: when no file was read, the audit is incomplete."""
    setup = fx.build(tmp_path)
    empty = tmp_path / "projects"
    empty.mkdir()
    run = setup.audit([empty])
    assert (run.report["result"], run.exit_code) == ("unknown", 3)
    assert _reasons(run) == [("no_files_read", None)]
    assert run.report["coverage"]["files"] == 0  # type: ignore[index]
    text = setup.audit([empty], as_json=False)
    assert "unknown: no_files_read" in text.lines
    assert " 0 files, 0 not scanned, " in text.lines[-2]


def test_a_missing_path_is_not_scanned_and_never_clean(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    gone = tmp_path / "no-such-config" / "projects"
    run = setup.audit([gone])
    assert (run.report["result"], run.exit_code) == ("unknown", 3)
    assert _reasons(run) == [("no_files_read", None), ("not_scanned", str(gone))]
    (row,) = run.report["files"]  # type: ignore[misc]
    assert (row["file"], row["format"], row["not_scanned"]) == (str(gone), None, "missing")
    assert f"not scanned: {gone} (missing)" in setup.audit([gone], as_json=False).lines


def test_a_missing_path_beside_a_read_file_is_only_not_scanned(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    gone = tmp_path / "gone.jsonl"
    run = setup.audit([_session(setup, tmp_path / "s.jsonl"), gone])
    assert (run.report["result"], run.exit_code) == ("unknown", 3)
    assert _reasons(run) == [("not_scanned", str(gone))]


def test_every_path_skipped_is_no_files_read(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    packed = tmp_path / "old.jsonl.gz"
    packed.write_bytes(b"\x1f\x8b" + b"\x00" * 16)
    run = setup.audit([packed])
    assert (run.report["result"], run.exit_code) == ("unknown", 3)
    assert _reasons(run) == [("no_files_read", None), ("not_scanned", str(packed))]
    assert run.report["coverage"]["files"] == 0  # type: ignore[index]


def test_a_report_that_is_not_an_inventory_report_is_refused(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    setup.report.write_text(json.dumps({"schema": "canary-report/1"}))
    _error(setup.audit([_session(setup, tmp_path / "s.jsonl")]), setup, "weir-inventory/1")


def test_paths_are_required(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    assert setup.audit([]).exit_code == 2


# --- credentials the audit can and cannot check --------------------------------


def test_a_credential_without_a_fingerprint_is_not_checkable_never_not_found(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path, bashrc="export VAULT_TOKEN=$(pass show vault)\n")
    run = setup.audit([_session(setup, tmp_path / "s.jsonl")], as_json=False)
    report = setup.audit([_session(setup, tmp_path / "s.jsonl")]).report
    row = fx.credential(report, setup.ids["VAULT_TOKEN"])
    assert (row["state"], row["value_state"]) == ("not_checkable", "dynamic")
    assert report["coverage"]["not_checkable"] == 1  # type: ignore[index]
    assert "not checkable: VAULT_TOKEN (~/.bashrc) dynamic" in run.lines
    assert run.exit_code == 0


def test_credentials_that_share_a_value_are_each_found(tmp_path: Path) -> None:
    twin = cfx.fake_value("audit-acme")
    setup = fx.build(tmp_path, extra_env=f"TWIN_TOKEN={twin}\n")
    assert twin == setup.values[fx.ACME]
    path = _session(setup, tmp_path / "s.jsonl", f"token {twin}\n")
    report = setup.audit([path]).report
    for name in (fx.ACME, "TWIN_TOKEN"):
        assert fx.credential(report, setup.ids[name])["state"] == "in_context"
        assert len(fx.hits(report, setup.ids[name])) == 1


# --- Claude Code classification (docs/audit.md, "Claude Code session files") --


def _one_record(setup: fx.Setup, tmp_path: Path, record: dict[str, object]) -> fx.Run:
    session = fx.Session()
    session.prompt("hello")
    session.record({"sessionId": fx.SESSION_ID, **record})
    return setup.audit([session.write(tmp_path / "s.jsonl")])


def _only_hit(run: fx.Run, setup: fx.Setup, name: str = fx.ACME) -> dict[str, object]:
    (hit,) = fx.hits(run.report, setup.ids[name])
    return hit


@pytest.mark.parametrize(
    ("record", "kind", "location"),
    [
        (
            {"type": "attachment", "attachment": {"type": "file", "filename": "x.env"},
             "rendered": [{"content": "<file>{v}</file>"}]},
            "context", "rendered[0].content",
        ),
        (
            {"type": "attachment", "attachment": {"type": "file", "content": "{v}"},
             "rendered": [{"content": "elided"}]},
            "stored", "attachment.content",
        ),
        (
            {"type": "attachment", "attachment": {"type": "session_context", "context": "{v}"}},
            "unknown", "attachment.context",
        ),
        ({"type": "summary", "summary": "the token is {v}"}, "context", "summary"),
        ({"type": "summary", "leafUuid": "{v}"}, "stored", "leafUuid"),
        ({"type": "last-prompt", "lastPrompt": "use {v}"}, "stored", "lastPrompt"),
        ({"type": "queue-operation", "content": "use {v}"}, "stored", "content"),
        (
            {"type": "user", "message": {"role": "user", "content": "x"},
             "toolUseResult": {"stdout": "{v}"}},
            "stored", "toolUseResult.stdout",
        ),
        (
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "maybe {v}"}]}},
            "context", "message.content[0].thinking",
        ),
        (
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "future_block", "data": "{v}"}]}},
            "unknown", "message.content[0].data",
        ),
        (
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "server_tool_use", "id": "srv_1", "name": "web_fetch",
                 "input": {"url": "https://api.invalid/?k={v}"}}]}},
            "tool_call", "message.content[0].input.url",
        ),
        (
            {"type": "assistant", "message": {"role": "assistant", "model": "{v}",
                                              "content": "x"}},
            "stored", "message.model",
        ),
        ({"type": "system", "content": "hook said {v}"}, "unknown", "content"),
    ],
)
def test_claude_code_records_are_classified_by_type_and_location(
    tmp_path: Path, record: dict[str, object], kind: str, location: str
) -> None:
    setup = fx.build(tmp_path)
    filled = json.loads(json.dumps(record).replace("{v}", setup.values[fx.ACME]))
    run = _one_record(setup, tmp_path, filled)
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["location"], hit["line"]) == (kind, location, 2)
    assert run.exit_code == {"context": 1, "tool_call": 1, "unknown": 3, "stored": 0}[kind]
    state = {"context": "in_context", "tool_call": "in_tool_call"}.get(kind, kind)
    assert fx.credential(run.report, setup.ids[fx.ACME])["state"] == state


def test_a_tool_result_names_the_tool_of_its_tool_use(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.tool_use("Grep", {"pattern": "TOKEN"}, "toolu_a")
    session.tool_use("Read", {"file_path": "/fake/.env"}, "toolu_b")
    session.tool_result("toolu_b", f"{fx.ACME}={setup.values[fx.ACME]}")
    session.tool_result("toolu_none", f"again {setup.values[fx.GH]}")
    report = setup.audit([session.write(tmp_path / "s.jsonl")]).report
    assert _only_hit(fx.Run(1, json.dumps(report), ""), setup)["tool"] == "Read"
    assert fx.hits(report, setup.ids[fx.GH])[0]["tool"] is None


def test_a_session_directory_is_read_with_its_subagents_and_tool_results(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path)
    project = tmp_path / "projects" / "-fake-home-work-proj"
    _session(setup, project / f"{fx.SESSION_ID}.jsonl")
    sub = fx.Session()
    sub_line, _ = sub.tool_result("toolu_9", f"token {setup.values[fx.GH]}")
    sub_path = sub.write(project / fx.SESSION_ID / "subagents" / "agent-1.jsonl")
    spill = project / fx.SESSION_ID / "tool-results" / "toolu_01.txt"
    spill.parent.mkdir(parents=True)
    cfx.write(spill, f"line one\n{fx.ACME}={setup.values[fx.ACME]}\n")
    os.symlink(spill, project / "linked.jsonl")

    given = tmp_path / "projects"
    run = setup.audit([given])

    report = run.report
    formats = {f["file"]: (f["format"], f["not_scanned"]) for f in report["files"]}  # type: ignore[union-attr,index]
    assert formats == {
        _shown(given, project / f"{fx.SESSION_ID}.jsonl"): ("claude-code", None),
        _shown(given, sub_path): ("claude-code", None),
        _shown(given, spill): ("claude-code-tool-results", None),
        _shown(given, project / "linked.jsonl"): (None, "symlink"),
    }
    assert _only_hit(run, setup, fx.GH)["file"] == _shown(given, sub_path)
    assert _only_hit(run, setup, fx.GH)["line"] == sub_line
    spilled = _only_hit(run, setup)
    assert (spilled["kind"], spilled["file"], spilled["line"]) == (
        "stored", _shown(given, spill), 2,
    )
    assert ("not_scanned", _shown(given, project / "linked.jsonl")) in [
        (u["reason"], u["subject"]) for u in report["unknown"]  # type: ignore[union-attr,index]
    ]
    assert run.exit_code == 1


# --- OTLP classification (docs/audit.md, "OTLP telemetry") -------------------


def test_otlp_outside_the_genai_attributes_is_unknown(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    span = cfx.span("GET", attributes=[cfx.kv("http.request.header.authorization",
                                                f"Bearer {setup.values[fx.ACME]}")])
    run = setup.audit([fx.write_otlp(tmp_path / "otlp.jsonl", span)])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["location"]) == (
        "unknown", "attributes.http.request.header.authorization",
    )
    assert run.exit_code == 3


def test_otlp_input_messages_and_a_bytes_value_are_found(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    messages = json.dumps([{"role": "user", "parts": [
        {"type": "text", "content": f"key {setup.values[fx.ACME]}"}]}])
    raw = base64.b64encode(f"gh={setup.values[fx.GH]}".encode()).decode()
    span = cfx.span("chat m", attributes=[
        cfx.kv("gen_ai.input.messages", messages),
        {"key": "gen_ai.tool.call.result", "value": {"bytesValue": raw}},
    ])
    run = setup.audit([fx.write_otlp(tmp_path / "otlp.jsonl", span)])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["location"]) == (
        "context", "attributes.gen_ai.input.messages[0].parts[0].content",
    )
    gh = _only_hit(run, setup, fx.GH)
    assert (gh["kind"], gh["location"], gh["form"]) == (
        "context", "attributes.gen_ai.tool.call.result", "raw",
    )


def test_a_pretty_printed_otlp_file_is_one_record(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    request = json.loads(cfx.traces(fx.tool_span("Bash", "{}", setup.values[fx.ACME])))
    path = tmp_path / "otlp.json"
    path.write_text(json.dumps(request, indent=2))
    run = setup.audit([path])
    (row,) = run.report["files"]  # type: ignore[misc]
    assert (row["format"], row["records"], row["unparsed_lines"]) == ("otlp", 1, 0)
    assert (_only_hit(run, setup)["kind"], _only_hit(run, setup)["line"]) == ("context", 1)


# --- candidates (docs/audit.md, "Candidates") --------------------------------


def _found_in(setup: fx.Setup, tmp_path: Path, text: str, name: str) -> list[str]:
    path = _session(setup, tmp_path / "s.jsonl", text)
    return [h["form"] for h in fx.hits(setup.audit([path]).report, setup.ids[name])]  # type: ignore[misc]


@pytest.mark.parametrize(
    "template",
    [
        "     3→{v}\n     4→next",  # Read tool line numbers
        "     3\t{v}",
        'export PLAIN_SECRET="{v}"',
        "PLAIN_SECRET: '{v}'",
        "value=`{v}`",
        "said {v} then",
        "({v})",
        "{v}.",
    ],
)
def test_a_value_holding_separators_is_found_by_the_line_and_word_rules(
    tmp_path: Path, template: str
) -> None:
    setup = fx.build(tmp_path)
    text = template.replace("{v}", setup.values[fx.SPECIAL])
    assert _found_in(setup, tmp_path, text, fx.SPECIAL) == ["raw"]


@pytest.mark.parametrize(
    "template",
    ["https://u:{v}@db.invalid/x", "a,{v};b", "k={v}&n=1", "[{v}]", "--token={v}", "{v}\\n"],
)
def test_a_plain_value_is_found_between_cut_points(tmp_path: Path, template: str) -> None:
    setup = fx.build(tmp_path)
    text = template.replace("{v}", setup.values[fx.ACME])
    assert _found_in(setup, tmp_path, text, fx.ACME) == ["raw"]


@pytest.mark.parametrize("template", ["x{v}", "{v}9", "-{v}", "{v}_"])
def test_a_value_glued_to_a_word_character_is_not_claimed(tmp_path: Path, template: str) -> None:
    """docs/audit.md, "What the audit does not claim"."""
    setup = fx.build(tmp_path)
    text = template.replace("{v}", setup.values[fx.ACME])
    assert _found_in(setup, tmp_path, text, fx.ACME) == []


def test_a_pem_private_key_is_found_whole(tmp_path: Path) -> None:
    body = "\n".join(cfx.fake_value(f"audit-pem-{i}", 64) for i in range(3))
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    setup = fx.build(tmp_path, extra_env=f'DEPLOY_KEY="{pem}"\n')
    assert _found_in(setup, tmp_path, f"$ cat key.pem\n{pem}\n$ ", "DEPLOY_KEY") == ["raw"]


def test_a_long_base64_blob_is_searched_through_its_decoding(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    blob = base64.b64encode(
        b"x" * 400 + f" {setup.values[fx.ACME]} ".encode() + b"y" * 400
    ).decode()
    assert _found_in(setup, tmp_path, f"data:{blob}", fx.ACME) == ["base64"]


# --- the report ------------------------------------------------------------------


def test_the_text_report_lays_out_hits_summaries_and_coverage(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    line = session.tool_use("Bash", {"command": f"use {setup.values[fx.ACME]}"}, "toolu_01")
    notes = tmp_path / "notes.log"
    cfx.write(notes, "nothing here\n")
    path = session.write(tmp_path / "s.jsonl")

    run = setup.audit([path, notes], as_json=False)

    acme = f"{fx.ACME} (launch env)"
    assert run.lines[0] == (
        f"TOOL_CALL {acme} file={path}:{line} record=assistant tool=\"Bash\" argument=command"
        " at=message.content[0].input.command form=raw"
    )
    assert f"{acme}: in_tool_call (1 tool call, 0 context, 0 stored, 0 unknown)" in run.lines
    assert f"not found: {fx.GH} (launch env)" in run.lines
    assert f"not found: {fx.AWS_SECRET} (~/.aws/credentials default)" in run.lines
    assert f"unknown: unrecognised_format {notes}" in run.lines
    assert run.lines[-2].startswith(
        f"coverage: {len(setup.values)} credentials ({len(setup.values)} checkable), 2 files"
        " (1 claude-code, 1 unknown), 0 not scanned, 1 record (0 unrecognised),"
        " 0 unparsed lines, "
    )
    assert run.lines[-1] == "result: exposed"


def test_the_report_depends_on_where_values_are_not_what_they_are(tmp_path: Path) -> None:
    outputs: list[tuple[str, str]] = []
    for seed in ("", "-second"):
        root = tmp_path / f"run{seed or '-first'}"
        setup = fx.build(root, seed=seed)
        session = fx.Session()
        session.prompt(f"token {setup.values[fx.GH]}")
        session.tool_use("Bash", {"command": f"x {setup.values[fx.ACME]}"}, "toolu_01")
        encoded = base64.b64encode(setup.values[fx.SPECIAL].encode()).decode()
        session.tool_result("toolu_01", encoded)
        path = session.write(tmp_path / "shared" / "s.jsonl")
        text = setup.audit([path], as_json=False).stdout
        report = setup.audit([path]).stdout
        outputs.append((text, report))
    assert outputs[0] == outputs[1]


def test_a_long_file_path_is_printed_in_full(tmp_path: Path) -> None:
    """A subagent transcript under a long home sits deep; the report must
    still name the file it found a credential in."""
    setup = fx.build(tmp_path)
    deep = tmp_path.joinpath(*(["a-rather-long-directory-name"] * 8))
    session = fx.Session()
    line, _ = session.tool_result("toolu_1", f"token {setup.values[fx.ACME]}")
    path = session.write(deep / "subagents" / "agent-a1b2c3.jsonl")
    assert len(str(path)) > 200
    run = setup.audit([path], as_json=False)
    assert run.lines[0].split(" file=")[1].startswith(f"{path}:{line} ")


def test_a_file_not_scanned_is_counted_beside_the_files_read(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    packed = tmp_path / "old.jsonl.gz"
    packed.write_bytes(b"\x1f\x8b" + b"\x00" * 16)
    session = _session(setup, tmp_path / "s.jsonl")
    run = setup.audit([session, packed], as_json=False)
    assert f"not scanned: {packed} (compressed)" in run.lines
    assert " 1 file (1 claude-code), 1 not scanned, " in run.lines[-2]
    assert run.exit_code == 3


def test_an_otlp_resource_string_names_its_signal(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    request = json.loads(cfx.traces(
        cfx.span("op"), resource=[cfx.kv("service.name", setup.values[fx.ACME])]
    ))
    path = tmp_path / "otlp.jsonl"
    cfx.write(path, json.dumps(request) + "\n")
    run = setup.audit([path])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["signal"], hit["span"], hit["location"]) == (
        "unknown", "traces", None, "resource.attributes.service.name",
    )


def test_tool_call_part_arguments_written_as_a_json_string_are_walked(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    arguments = json.dumps({"headers": {"authorization": f"Bearer {setup.values[fx.ACME]}"}})
    messages = [{"role": "assistant", "parts": [
        {"type": "tool_call", "id": "call_1", "name": "http_get", "arguments": arguments}]}]
    run = setup.audit([fx.write_otlp(tmp_path / "otlp.jsonl", fx.chat_span(messages))])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["tool"], hit["argument"], hit["form"]) == (
        "tool_call", "http_get", "headers.authorization", "raw",
    )
    assert hit["location"] == (
        "attributes.gen_ai.output.messages[0].parts[0].arguments.headers.authorization"
    )


@pytest.mark.parametrize("arguments_as", ["structured", "json_string"])
def test_a_tool_call_part_in_structured_output_messages_is_a_tool_call(
    tmp_path: Path, arguments_as: str
) -> None:
    setup = fx.build(tmp_path)
    arguments: object = {"command": f"curl -H 'x: {setup.values[fx.ACME]}'"}
    if arguments_as == "json_string":
        arguments = json.dumps(arguments)
    messages = [{"role": "assistant", "parts": [
        {"type": "text", "content": f"token {setup.values[fx.GH]}"},
        {"type": "tool_call", "id": "call_1", "name": "Bash", "arguments": arguments}]}]
    span = cfx.span("chat fake-model", attributes=[
        {"key": "gen_ai.output.messages", "value": fx.any_value(messages)},
    ])
    run = setup.audit([fx.write_otlp(tmp_path / "otlp.jsonl", span)])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["tool"], hit["argument"], hit["location"]) == (
        "tool_call", "Bash", "command",
        "attributes.gen_ai.output.messages[0].parts[1].arguments.command",
    )
    text = _only_hit(run, setup, fx.GH)
    assert (text["kind"], text["tool"], text["location"]) == (
        "context", None, "attributes.gen_ai.output.messages[0].parts[0].content",
    )
    assert fx.credential(run.report, setup.ids[fx.ACME])["state"] == "in_tool_call"


def test_claude_code_log_events_are_classified(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    parameters = json.dumps({"bash_command": f"curl -H 'x: {setup.values[fx.ACME]}'"})
    request = cfx.logs(
        fx.claude_code_event("user_prompt", prompt=f"use {setup.values[fx.GH]}"),
        fx.claude_code_event("tool_result", tool_name="Bash", tool_parameters=parameters),
        fx.claude_code_event("api_request", model=setup.values[fx.AWS_ID]),
    )
    path = tmp_path / "otlp.jsonl"
    cfx.write(path, request + "\n")
    run = setup.audit([path])
    call = _only_hit(run, setup)
    assert (call["kind"], call["signal"], call["log_record"], call["tool"], call["argument"]) == (
        "tool_call", "logs", 1, "Bash", "bash_command",
    )
    assert call["location"] == "attributes.tool_parameters.bash_command"
    prompt = _only_hit(run, setup, fx.GH)
    assert (prompt["kind"], prompt["log_record"], prompt["location"]) == (
        "context", 0, "attributes.prompt",
    )
    other = _only_hit(run, setup, fx.AWS_ID)
    assert (other["kind"], other["location"]) == ("unknown", "attributes.model")
    assert run.exit_code == 1


def test_claude_code_log_attributes_in_a_span_are_unknown(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    span = cfx.span("tool", attributes=[
        cfx.kv("tool_name", "Bash"),
        cfx.kv("tool_parameters", json.dumps({"bash_command": setup.values[fx.ACME]})),
        cfx.kv("prompt", setup.values[fx.GH]),
    ])
    run = setup.audit([fx.write_otlp(tmp_path / "otlp.jsonl", span)])
    assert [h["kind"] for h in fx.hits(run.report, setup.ids[fx.ACME])] == ["unknown"]
    assert [h["kind"] for h in fx.hits(run.report, setup.ids[fx.GH])] == ["unknown"]
    assert run.exit_code == 3


@pytest.mark.parametrize("layout", ["json_lines", "whole_file"])
def test_an_export_request_member_outside_the_signals_is_searched(
    tmp_path: Path, layout: str
) -> None:
    setup = fx.build(tmp_path)
    request = json.loads(cfx.traces(cfx.span("op")))
    request["extra"] = {"note": setup.values[fx.ACME]}
    path = tmp_path / "otlp.json"
    cfx.write(path, json.dumps(request) + "\n" if layout == "json_lines" else
              json.dumps(request, indent=2))
    run = setup.audit([path])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["format"], hit["signal"], hit["location"], hit["line"]) == (
        "unknown", "otlp", None, "extra.note", 1,
    )
    assert ("unknown_kind", f"{path}:1") in [
        (u["reason"], u["subject"]) for u in run.report["unknown"]  # type: ignore[union-attr,index]
    ]
    assert (run.report["result"], run.exit_code) == ("unknown", 3)


def _memory_tree(setup: fx.Setup, tmp_path: Path) -> dict[str, Path]:
    project = tmp_path / "claude" / "projects" / "-fake-home-work-proj"
    files = {
        "session": _session(setup, project / f"{fx.SESSION_ID}.jsonl"),
        "index": project / "memory" / "MEMORY.md",
        "topic": project / "memory" / "deploy.md",
        "claude_md": tmp_path / "claude" / "CLAUDE.md",
    }
    files["index"].parent.mkdir(parents=True)
    cfx.write(files["index"], "# Memory\n- [Deploy](deploy.md) - how to deploy\n")
    cfx.write(files["topic"], "# Deploy\nrun the deploy script\n")
    cfx.write(files["claude_md"], "# Rules\nUse plain dashes.\n")
    return files


def test_clean_claude_code_memory_and_claude_md_files_are_clean(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    files = _memory_tree(setup, tmp_path)
    given = tmp_path / "claude"
    run = setup.audit([given])
    formats = {f["file"]: f["format"] for f in run.report["files"]}  # type: ignore[union-attr,index]
    assert formats == {
        _shown(given, files["session"]): "claude-code",
        _shown(given, files["index"]): "claude-code-memory",
        _shown(given, files["topic"]): "claude-code-memory",
        _shown(given, files["claude_md"]): "claude-code-memory",
    }
    assert (run.report["result"], run.exit_code, run.report["unknown"]) == ("clean", 0, [])


@pytest.mark.parametrize("name", ["index", "topic", "claude_md"])
def test_a_value_in_a_memory_or_claude_md_file_is_in_context(tmp_path: Path, name: str) -> None:
    setup = fx.build(tmp_path)
    path = _memory_tree(setup, tmp_path)[name]
    before = path.read_text()
    cfx.write(path, before + f"token: {setup.values[fx.ACME]}\n")
    given = tmp_path / "claude"
    run = setup.audit([given])
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["file"], hit["line"], hit["format"], hit["location"]) == (
        "context", _shown(given, path), before.count("\n") + 1, "claude-code-memory", None,
    )
    assert fx.credential(run.report, setup.ids[fx.ACME])["state"] == "in_context"
    assert run.exit_code == 1


def test_memory_and_tool_results_files_are_recognised_from_a_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    setup = fx.build(tmp_path)
    files = _memory_tree(setup, tmp_path)
    project = files["index"].parent.parent
    spill = project / fx.SESSION_ID / "tool-results" / "toolu_01.txt"
    spill.parent.mkdir(parents=True)
    cfx.write(spill, "line one\n")
    cfx.write(files["index"], files["index"].read_text() + f"token: {setup.values[fx.ACME]}\n")

    monkeypatch.chdir(project.parent)
    run = setup.audit(["."])
    formats = {f["file"]: f["format"] for f in run.report["files"]}  # type: ignore[union-attr,index]
    shown = {
        _shown(".", path.relative_to(project.parent)): path
        for path in (files["session"], files["index"], files["topic"], spill)
    }
    assert formats == {
        name: {spill: "claude-code-tool-results", files["session"]: "claude-code"}.get(
            path, "claude-code-memory"
        )
        for name, path in shown.items()
    }
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["file"]) == (
        "context", _shown(".", files["index"].relative_to(project.parent)),
    )
    assert run.report["unknown"] == []

    monkeypatch.chdir(spill.parent)
    assert setup.audit([spill.name]).report["files"][0]["format"] == (  # type: ignore[index]
        "claude-code-tool-results"
    )


@pytest.mark.parametrize("where", ["projects/p/notes.md", "work/memory/MEMORY.md",
                                   "projects/p/memory/MEMORY.txt"])
def test_a_markdown_file_outside_the_memory_layout_is_unrecognised(
    tmp_path: Path, where: str
) -> None:
    setup = fx.build(tmp_path)
    path = tmp_path / "claude" / where
    path.parent.mkdir(parents=True)
    cfx.write(path, "# Notes\nnothing here\n")
    run = setup.audit([path])
    assert run.report["files"][0]["format"] == "unknown"  # type: ignore[index]
    assert (run.report["result"], run.exit_code) == ("unknown", 3)


def test_a_whole_file_request_with_a_one_line_attribute_object_is_one_record(
    tmp_path: Path,
) -> None:
    setup = fx.build(tmp_path)
    arguments = json.dumps({"command": f"curl -H 'x: {setup.values[fx.ACME]}'"})
    attributes = [
        cfx.kv("gen_ai.tool.name", "Bash"), cfx.kv("gen_ai.tool.call.arguments", arguments),
    ]
    request = json.loads(cfx.traces(cfx.span("execute_tool Bash", attributes=attributes)))
    spans = request["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans[0]["attributes"] = [f"@{i}@" for i in range(len(attributes))]
    text = json.dumps(request, indent=2)
    for i, attribute in enumerate(attributes):
        text = text.replace(f'"@{i}@"', json.dumps(attribute))
    path = tmp_path / "otlp.json"
    cfx.write(path, text + "\n")
    assert json.dumps(attributes[-1]) in [line.strip() for line in text.splitlines()]

    run = setup.audit([path])
    (row,) = run.report["files"]  # type: ignore[misc]
    assert (row["format"], row["records"], row["unparsed_lines"]) == ("otlp", 1, 0)
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["tool"], hit["argument"], hit["line"]) == (
        "tool_call", "Bash", "command", 1,
    )
    assert run.exit_code == 1


def _bookkeeping(setup: fx.Setup, kind: str) -> dict[str, object]:
    value = setup.values[fx.ACME]
    if kind == "summary":
        return {"type": "summary", "summary": f"Set token {value}", "leafUuid": "00000000-0000"}
    return {
        "type": "file-history-snapshot", "messageId": "00000000-0001",
        "snapshot": {"messageId": "00000000-0001", "trackedFileBackups": {
            "/fake/.env": {"backupFileName": f"{value}@v1", "version": 1}}},
        "isSnapshotUpdate": False,
    }


@pytest.mark.parametrize(
    ("kind", "hit_kind", "location", "exit_code"),
    [
        ("summary", "context", "summary", 1),
        ("file-history-snapshot", "stored", "snapshot.trackedFileBackups./fake/.env.backupFileName",
         0),
    ],
)
@pytest.mark.parametrize("config_dir", [None, "claude-config"])
def test_a_claude_projects_file_of_bookkeeping_records_only_is_a_session(
    tmp_path: Path, config_dir: str | None, kind: str, hit_kind: str, location: str,
    exit_code: int,
) -> None:
    setup = fx.build(tmp_path)
    claude = tmp_path / "home" / ".claude"
    extra: list[str] = []
    if config_dir is not None:
        claude = tmp_path / config_dir
        extra = ["--claude-config-dir", str(claude)]
    path = claude / "projects" / "-fake-home-work-proj" / "a.jsonl"
    path.parent.mkdir(parents=True)
    cfx.write(path, json.dumps(_bookkeeping(setup, kind)) + "\n")
    run = setup.audit([path], extra=extra)
    assert run.report["files"][0]["format"] == "claude-code"  # type: ignore[index]
    hit = _only_hit(run, setup)
    assert (hit["kind"], hit["record"], hit["location"], hit["line"]) == (
        hit_kind, kind, location, 1,
    )
    state = {"context": "in_context"}.get(hit_kind, hit_kind)
    assert fx.credential(run.report, setup.ids[fx.ACME])["state"] == state
    assert (run.report["unknown"], run.exit_code) == ([], exit_code)


@pytest.mark.parametrize(
    ("where", "extra"),
    [
        ("home/.claude/projects/p/a.jsonl", {"type": "future-record", "data": "x"}),
        ("home/.claude/projects/p/a.jsonl", {"type": "user", "content": "hello"}),
        ("home/.claude/projects/p/a.jsonl", {"type": "attachment", "rendered": "hello"}),
        ("home/projects/p/a.jsonl", None),
        ("home/.claude/notes/p/a.jsonl", None),
    ],
)
def test_bookkeeping_records_with_another_type_or_outside_claude_projects_stay_unknown(
    tmp_path: Path, where: str, extra: dict[str, object] | None
) -> None:
    setup = fx.build(tmp_path)
    path = tmp_path / where
    path.parent.mkdir(parents=True)
    records = [_bookkeeping(setup, "summary"), *([extra] if extra else [])]
    cfx.write(path, "".join(json.dumps(r) + "\n" for r in records))
    run = setup.audit([path])
    assert run.report["files"][0]["format"] == "unknown"  # type: ignore[index]
    assert _only_hit(run, setup)["kind"] == "unknown"
    assert (run.report["result"], run.exit_code) == ("unknown", 3)


def test_a_chat_log_under_a_projects_directory_is_unknown_not_a_session(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    path = tmp_path / "home" / "projects" / "chatbot" / "data" / "chat.jsonl"
    path.parent.mkdir(parents=True)
    records = [
        {"type": "user", "content": f"deploy with {setup.values[fx.ACME]}"},
        {"type": "assistant", "content": "done"},
        {"type": "summary", "summary": "a deploy"},
    ]
    cfx.write(path, "".join(json.dumps(r) + "\n" for r in records))
    run = setup.audit([path])
    assert run.report["files"][0]["format"] == "unknown"  # type: ignore[index]
    assert _only_hit(run, setup)["kind"] == "unknown"
    assert (run.report["result"], run.exit_code) == ("unknown", 3)


def test_a_type_that_is_not_a_string_is_unknown_not_a_crash(tmp_path: Path) -> None:
    setup = fx.build(tmp_path)
    session = fx.Session()
    session.prompt("hello")
    block_line = session.record({
        "type": "assistant", "sessionId": fx.SESSION_ID,
        "message": {"role": "assistant", "content": [
            {"type": ["tool_use"], "id": "toolu_1", "name": "Bash",
             "input": {"command": setup.values[fx.ACME]}}]},
    })
    record_line = session.record(
        {"type": {"kind": "user"}, "sessionId": fx.SESSION_ID, "data": setup.values[fx.GH]}
    )
    run = setup.audit([session.write(tmp_path / "s.jsonl")])
    block = _only_hit(run, setup)
    assert (block["kind"], block["line"], block["location"]) == (
        "unknown", block_line, "message.content[0].input.command",
    )
    record = _only_hit(run, setup, fx.GH)
    assert (record["kind"], record["line"], record["record"]) == ("unknown", record_line, None)
    (row,) = run.report["files"]  # type: ignore[misc]
    assert (row["records"], row["unrecognised_records"]) == (3, 1)
    assert run.exit_code == 3


def test_no_environment_variable_changes_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/audit.md: only the inputs and flags decide the output. A summary-only
    file in another Claude config directory is unknown unless that directory is
    given with --claude-config-dir; CLAUDE_CONFIG_DIR pointing at it changes
    nothing."""
    setup = fx.build(tmp_path)
    config = tmp_path / "claude-config"
    path = config / "projects" / "-fake-home-work-proj" / "a.jsonl"
    path.parent.mkdir(parents=True)
    cfx.write(path, json.dumps(_bookkeeping(setup, "summary")) + "\n")

    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    without = setup.audit([path])
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config))
    with_env = setup.audit([path])
    flagged = setup.audit([path], extra=["--claude-config-dir", str(config)])

    assert with_env.stdout == without.stdout
    assert (without.report["files"][0]["format"], without.exit_code) == ("unknown", 3)  # type: ignore[index]
    assert (flagged.report["files"][0]["format"], flagged.exit_code) == ("claude-code", 1)  # type: ignore[index]
