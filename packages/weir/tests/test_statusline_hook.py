"""Tests for the redaction hook (docs/statusline.md, "The redaction hook"),
written before the implementation.

FAKE DATA ONLY: the fake home, inventory and values of audit_fixtures. Each
hook input is the documented PostToolUse input (Claude Code hooks reference,
"PostToolUse input"), its `tool_response` in the shape Claude Code gives the
tool's output: Bash and Read as Claude Code's session files record it
(`toolUseResult`), Grep, Glob and WebFetch from the output schemas Claude Code
2.1.310 declares, as no session file or documentation page shows those three.
Every encoding is built with the standard library, and what the hook must
return is worked out from where the test put each value, never from weir.

1. Each value, raw, URL-encoded, JSON-escaped or in base64 at any byte
   offset, is replaced by `[weir: NAME removed]` in each tool's output and in
   large outputs, and everything else is kept as it was, key order included.
2. A result with no known value passes untouched: the hook prints nothing.
3. The status line and /weir count what the hook kept out beside what
   entered and what was sent, and are green only with nothing entered or
   sent and no hook failure.
4. Every way the hook can fail shows "possibly not redacted", never green.
5. Nothing the hook or the status line writes holds a value or 6 characters
   of one, decoded or not.
6. Setup offers the hook in its preview and adds it only on an exact yes;
   undo takes it out, and setup then undo leaves settings.json as it was.
7. /weir says when a key entered through a failed tool call, which runs no
   PostToolUse hook, and gives a deny rule for the file the key lives in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import signal
import string
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path, PureWindowsPath

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

from weir.audit.inputs import fingerprint
from weir.audit.matching import Matcher
from weir.statusline.segment import segment_text

TOOLS = ("Bash", "Read", "Grep", "Glob", "WebFetch")
TOOL_ID = "toolu_01HookCase"
NOT_REDACTED = "possibly not redacted"


def _label(name: str) -> str:
    return f"[weir: {name} removed]"


def _response(tool: str, text: str, like: str) -> object:
    """`tool`'s output holding `text`, its counts those of `like`, the text
    the tool returned (a replacement changes no count)."""
    lines = like.count("\n") + 1
    path = "/fake/home/work/proj/.env"
    return {
        "Bash": {"stdout": text, "stderr": "", "interrupted": False, "isImage": False,
                 "noOutputExpected": False},
        "Read": {"type": "text", "file": {"filePath": path, "content": text, "numLines": lines,
                                          "startLine": 1, "totalLines": lines}},
        "Grep": {"mode": "content", "numFiles": 1, "filenames": [path], "content": text,
                 "numLines": lines},
        "Glob": {"durationMs": 4, "numFiles": 2, "filenames": [path, text], "truncated": False},
        "WebFetch": {"bytes": len(like.encode()), "code": 200, "codeText": "OK", "result": text,
                     "durationMs": 87, "url": "https://example.invalid/config"},
    }[tool]


def _input(tool: str, response: object, tool_id: str = TOOL_ID) -> dict[str, object]:
    return {
        "session_id": fx.SESSION_ID,
        "transcript_path": "/fake/home/.claude/projects/-fake-home-work-proj/s.jsonl",
        "cwd": "/fake/home/work/proj", "permission_mode": "default",
        "hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {"x": "y"},
        "tool_response": response, "tool_use_id": tool_id,
    }


def _filler(size: int) -> str:
    lines = (f"{i:06d} INFO served /api/v1/items/{i} in {i % 97} ms\n" for i in range(size))
    out = ""
    for line in lines:
        if len(out) >= size:
            return out
        out += line
    return out


def _cases(v: dict[str, str]) -> dict[str, tuple[str, dict[str, str]]]:
    """Form -> (the tool's text, {each encoded string placed: the name it
    must be replaced by})."""
    special, acme = v[fx.SPECIAL], v[fx.ACME]
    url = urllib.parse.quote(special, safe="")
    escaped = json.dumps(special)[1:-1].replace("/", "\\/")  # PHP's json_encode
    twice = json.dumps(json.dumps(special)[1:-1])[1:-1]
    cases = {
        "raw": (f"{fx.ACME}={acme}\nDEBUG=1\n", {acme: fx.ACME}),
        "url": (f"GET /cb?token={url}&page=2 200\n", {url: fx.SPECIAL}),
        # Found only once the whole string is decoded: glued to letters.
        "url-glued": (f"q=x%20{acme}%20y\n", {acme: fx.ACME}),
        "json": ('{"token":"' + escaped + '","page":2}', {escaped: fx.SPECIAL}),
        "json2": (json.dumps({"body": json.dumps({"token": special})}), {twice: fx.SPECIAL}),
        "hex": (f"blob {special.encode().hex()} end\n", {special.encode().hex(): fx.SPECIAL}),
        "several": (
            f"{fx.GH}={v[fx.GH]}\naws_access_key_id = {v[fx.AWS_ID]}\n{fx.ACME}: {acme}\n",
            {v[fx.GH]: fx.GH, v[fx.AWS_ID]: fx.AWS_ID, acme: fx.ACME},
        ),
        "large": (sx.dense_lockfile(46_000) + f"token: {acme}\n" + _filler(900), {acme: fx.ACME}),
        "huge": (_filler(70_000) + f"key = {acme}\n" + _filler(90_000), {acme: fx.ACME}),
    }
    for offset in range(3):
        # The value at byte offset 0, 1 and 2 of what is encoded: the whole
        # base64 token is replaced, as its edge characters mix value bits in.
        token = base64.b64encode((" " * offset + special).encode()).decode()
        cases[f"base64-{offset}"] = (f"Authorization: Basic {token}\n", {token: fx.SPECIAL})
    return cases


def _markers(claude: sx.Claude, claude_dir: Path | None = None) -> Path:
    """The markers folder docs/statusline.md names for a Claude config dir
    (the fixture's own by default): `hook-` and the first 16 hex characters
    of the SHA-256 of its resolved path, in the cache."""
    resolved = os.fsencode(os.path.realpath(claude_dir or claude.config))
    return claude.state / f"hook-{hashlib.sha256(resolved).hexdigest()[:16]}"


def _hook(claude: sx.Claude, stdin: str) -> sx.Run:
    args = ["statusline", "hook", *claude.inputs(), "--markers", str(_markers(claude))]
    return claude.invoke(args, stdin=stdin)


def _marker(claude: sx.Claude, tool_id: str = TOOL_ID) -> dict[str, object]:
    return json.loads((_markers(claude) / fx.SESSION_ID / f"{tool_id}.json").read_text())


def _expected(text: str, placed: dict[str, str]) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for encoded, name in placed.items():
        counts[name] = counts.get(name, 0) + text.count(encoded)
        text = text.replace(encoded, _label(name))
    return text, counts


# --- 1 and 2. replaced in place, the shape kept --------------------------------------


_FORMS = [
    "raw", "url", "url-glued", "json", "json2", "hex", "base64-0", "base64-1", "base64-2",
    "several", "large",
]


@pytest.mark.parametrize(
    ("tool", "form"),
    [(t, f) for t in TOOLS for f in _FORMS] + [("Bash", "huge"), ("Read", "huge")],
)
def test_each_value_is_replaced_in_place_and_the_shape_kept(
    tmp_path: Path, tool: str, form: str
) -> None:
    claude = sx.build(tmp_path)
    text, placed = _cases(claude.setup.values)[form]
    redacted, counts = _expected(text, placed)

    run = _hook(claude, json.dumps(_input(tool, _response(tool, text, text))))

    assert run.exit_code == 0, run.stderr
    out = json.loads(run.stdout)
    assert list(out) == ["hookSpecificOutput"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    # Serialised, so key order counts too: the same keys, types, list
    # lengths and non-string leaves, and only the placed strings changed.
    updated = out["hookSpecificOutput"]["updatedToolOutput"]
    assert json.dumps(updated) == json.dumps(_response(tool, redacted, text))
    assert _marker(claude) == {**_marker(claude), "state": "done", "kept_out": counts}


@pytest.mark.parametrize("tool", TOOLS)
def test_a_result_with_no_known_value_passes_untouched(tmp_path: Path, tool: str) -> None:
    claude = sx.build(tmp_path)
    text = "total 0\nREADME.md\n"

    run = _hook(claude, json.dumps(_input(tool, _response(tool, text, text))))

    assert (run.exit_code, run.stdout) == (0, "")
    assert _marker(claude)["state"] == "done"
    assert _marker(claude)["kept_out"] == {}


def test_the_image_data_a_read_returns_is_left_unsearched(tmp_path: Path) -> None:
    """A Read of an image returns its bytes in base64, megabytes for a
    screenshot: the hook leaves that data as it is, as the audit does, so a
    value encoded in it is not replaced."""
    claude = sx.build(tmp_path)
    pixels = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 1_200
    data = base64.b64encode(pixels + claude.setup.values[fx.ACME].encode() + pixels).decode()
    image = {"type": "image", "file": {
        "base64": data, "type": "image/png", "originalSize": 2 * len(pixels),
        "dimensions": {"originalWidth": 1920, "originalHeight": 1080,
                       "displayWidth": 1920, "displayHeight": 1080}}}

    run = _hook(claude, json.dumps(_input("Read", image)))

    assert (run.exit_code, run.stdout) == (0, ""), run.stderr
    assert _marker(claude)["state"] == "done"
    assert _marker(claude)["kept_out"] == {}


def test_the_pdf_and_notebook_image_data_a_read_returns_are_left_unsearched(
    tmp_path: Path,
) -> None:
    """Every binary payload in Claude Code's Read output (2.1.310 schema):
    a PDF's `file.base64` and a notebook output's `image.image_data`, like
    an image's. The rest of the result is still searched."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    data = base64.b64encode(b"%PDF-1.7\n" + bytes(range(256)) * 400 + acme.encode()).decode()
    pdf = {"type": "pdf", "file": {"filePath": "/fake/home/work/proj/doc.pdf",
                                   "base64": data, "originalSize": 102_409}}
    cell = {"cellType": "code", "source": f"TOKEN = '{acme}'", "cell_id": "c1",
            "outputs": [{"output_type": "display_data", "text": "",
                         "image": {"image_data": data, "media_type": "image/png"}}]}
    notebook = {"type": "notebook", "file": {"filePath": "/fake/n.ipynb", "cells": [cell]}}

    assert _hook(claude, json.dumps(_input("Read", pdf))).stdout == ""
    assert _marker(claude)["kept_out"] == {}
    run = _hook(claude, json.dumps(_input("Read", notebook)))

    updated = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]
    redacted = {**cell, "source": f"TOKEN = '{_label(fx.ACME)}'"}
    assert json.dumps(updated) == json.dumps(
        {**notebook, "file": {**notebook["file"], "cells": [redacted]}}
    )


@pytest.mark.skipif(os.name != "posix", reason="owner and mode bits are POSIX")
def test_the_markers_and_their_folders_are_owner_only(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    assert not claude.state.exists()

    _hook(claude, json.dumps(_input("Bash", _response("Bash", "ok\n", "ok\n"))))

    marker = _markers(claude) / fx.SESSION_ID / f"{TOOL_ID}.json"
    for path in (claude.state, _markers(claude), marker.parent):
        assert path.stat().st_mode & 0o777 == 0o700, path
    assert marker.stat().st_mode & 0o777 == 0o600


def test_a_value_no_form_can_place_spans_the_whole_string() -> None:
    """The json form joins an escaped surrogate pair into one character;
    the place of a value holding one is not told, so the whole string is
    its span, never a guess that would leave part of it."""
    key = b"k" * 32
    value = "fake-\U0001f600-value-001"
    matcher = Matcher(key, {fingerprint(key, value.encode())})
    string = "x " + json.dumps({"v": value}) + " y"

    assert matcher.find(string)
    assert matcher.spans(string) == [(0, len(string), fingerprint(key, value.encode()))]


# --- 3. three kinds on the status line and in /weir -------------------------------------


def _segment(claude: sx.Claude, *, colour: bool = False, folder: str | None = None) -> str:
    """A refresh in the session's project folder `folder`, else the
    inventory's project, which records that folder for /weir."""
    payload = sx.status_json(claude.transcript(), fx.SESSION_ID, folder or claude.project())
    args = ["statusline", *claude.inputs(), "--cache", str(claude.state),
            "--markers", str(_markers(claude))]
    return claude.invoke(args, stdin=payload, env={} if colour else sx.NO_COLOR).stdout


def _report(claude: sx.Claude) -> list[str]:
    args = ["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
            "--claude-dir", str(claude.config), "--cache", str(claude.state),
            "--markers", str(_markers(claude))]
    run = claude.invoke(args)
    assert run.exit_code == 0, run.stderr
    return run.lines


def _kept_out_session(claude: sx.Claude, session: fx.Session) -> None:
    """A Bash result the hook redacted, as Claude Code records it: the
    hook's output, never the original."""
    v = claude.setup.values
    text = f"{fx.ACME}={v[fx.ACME]}\n"
    run = _hook(claude, json.dumps(_input("Bash", _response("Bash", text, text))))
    shown = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    session.tool_use("Bash", {"command": "cat .env"}, TOOL_ID)
    session.tool_result(TOOL_ID, shown)


def test_kept_out_alone_sits_beside_green(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("show me the env file")
    _kept_out_session(claude, session)
    # A failed call never runs PostToolUse: no marker, and no failure.
    session.tool_use("Bash", {"command": "false"}, "toolu_failed")
    block = {"type": "tool_result", "tool_use_id": "toolu_failed", "content": "Exit code 1",
             "is_error": True}
    session.record(session._envelope("user", message={"role": "user", "content": [block]}))  # pyright: ignore[reportPrivateUsage]
    session.write(claude.transcript())

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    assert _segment(claude) == "weir ✓ no known key seen · 1 kept out\n"
    green = f"\x1b[{sx.GREEN}m✓ no known key seen\x1b[0m"
    assert _segment(claude, colour=True) == f"weir {green} · 1 kept out\n"
    lines = _report(claude)
    assert lines[0] == "weir ✓ no known key seen · 1 kept out"
    assert f"kept out by the redaction hook: {fx.ACME} (1 time)" in lines


def test_kept_out_sits_beside_project_not_inventoried(tmp_path: Path) -> None:
    """Outside the inventory's project the line is never green, and what
    the hook kept out is still counted."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("show me the env file")
    _kept_out_session(claude, session)
    session.write(claude.transcript())
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    assert _segment(claude, folder=str(elsewhere)) == "weir project not inventoried · 1 kept out\n"
    dim = f"\x1b[{sx.DIM}mproject not inventoried\x1b[0m"
    assert _segment(claude, colour=True, folder=str(elsewhere)) == f"weir {dim} · 1 kept out\n"
    lines = _report(claude)
    assert lines[0] == "weir project not inventoried · 1 kept out"
    assert f"kept out by the redaction hook: {fx.ACME} (1 time)" in lines
    assert f"project: {elsewhere} is not the inventoried project" in "\n".join(lines)


def test_entered_and_sent_are_counted_beside_kept_out(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    session = fx.Session()
    session.prompt(f"use {v[fx.GH]} for github")  # pasted: no hook sees it
    _kept_out_session(claude, session)
    session.tool_use("Bash", {"command": f"aws --secret {v[fx.AWS_SECRET]} s3 ls"}, "toolu_02")
    session.write(claude.transcript())

    entered, sent, _ = sx.expected_counts(claude.setup, claude.audit())
    assert (entered, sent) == (2, 1)
    line = f"weir ⚠ {entered} entered · {sent} sent · 1 kept out"
    assert _segment(claude) == f"{line} → /weir\n"
    assert _report(claude)[0] == line


# --- 4. every failure shows possibly not redacted -----------------------------------------


def _ran_session(claude: sx.Claude) -> None:
    """A Bash call whose result Claude Code recorded: as the hook left it,
    or as the tool returned it when the hook failed."""
    session = fx.Session()
    session.prompt("list the files")
    session.tool_use("Bash", {"command": "ls"}, TOOL_ID)
    session.tool_result(TOOL_ID, "total 0\n")
    session.write(claude.transcript())


def _killed_mid_run(claude: sx.Claude) -> None:
    """Claude Code's timeout: the hook killed once its marker says pending."""
    big = _filler(4_000_000)
    args = [sys.executable, "-m", "weir", "statusline", "hook", *claude.inputs(),
            "--markers", str(_markers(claude))]
    env = {**os.environ, **claude.env()}
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, env=env)
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(_input("Bash", _response("Bash", big, big))).encode())
    proc.stdin.close()
    marker = _markers(claude) / fx.SESSION_ID / f"{TOOL_ID}.json"
    deadline = time.monotonic() + 60
    while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    assert _marker(claude)["state"] == "pending"


def _stdout_closed(claude: sx.Claude) -> None:
    """Claude Code gone before the replacement is written: its end of the
    hook's stdout closed while the hook reads its input."""
    text = f"{fx.ACME}={claude.setup.values[fx.ACME]}\n"
    args = [sys.executable, "-m", "weir", "statusline", "hook", *claude.inputs(),
            "--markers", str(_markers(claude))]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={**os.environ, **claude.env()})
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    proc.stdout.close()
    proc.stdin.write(json.dumps(_input("Bash", _response("Bash", text, text))).encode())
    proc.stdin.close()
    stderr = proc.stderr.read().decode()
    assert proc.wait(timeout=120) == 1, stderr
    (line,) = stderr.splitlines()
    assert NOT_REDACTED in line
    assert _marker(claude)["state"] == "pending"


def _fail(claude: sx.Claude, how: str, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(_input("Bash", _response("Bash", "total 0\n", "total 0\n")))
    if how == "killed":
        _killed_mid_run(claude)
        return
    if how == "stdout closed":
        _stdout_closed(claude)
        return
    if how == "crash":
        from weir.statusline import hook

        def crash(*_: object) -> object:
            raise RuntimeError("injected")

        monkeypatch.setattr(hook, "redact", crash)
    elif how == "key unreadable":
        claude.setup.key.chmod(0o644)
    elif how == "key mode 000":
        claude.setup.key.chmod(0)
    elif how == "inventory mode 000":
        claude.setup.report.chmod(0)
    elif how == "store missing":
        claude.setup.store.rename(tmp := claude.setup.store.with_suffix(".away"))
    elif how == "not json":
        payload = payload[:-1]
    elif how == "no tool_response":
        payload = json.dumps({k: v for k, v in json.loads(payload).items()
                              if k != "tool_response"})
    run = _hook(claude, payload)
    assert (run.exit_code, run.stdout) == (1, "")
    (line,) = run.stderr.splitlines()  # one line, never a usage text
    assert NOT_REDACTED in line
    if how != "not json":  # marked failed whenever its ids can be read
        assert _marker(claude)["state"] == "failed"
    # The status line reads the same inputs, usable again.
    claude.setup.key.chmod(0o600)
    claude.setup.report.chmod(0o600)
    if how == "store missing":
        tmp.rename(claude.setup.store)


@pytest.mark.parametrize(
    "how",
    ["crash", "killed", "stdout closed", "key unreadable", "key mode 000", "inventory mode 000",
     "store missing", "not json", "no tool_response"],
)
def test_every_hook_failure_shows_possibly_not_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    if how == "killed" and os.name != "posix":
        pytest.skip("SIGKILL is POSIX")
    if how in ("key unreadable", "key mode 000", "inventory mode 000") and os.name != "posix":
        pytest.skip("owner and mode bits are POSIX")
    claude = sx.build(tmp_path)
    _fail(claude, how, monkeypatch)
    _ran_session(claude)

    assert sx.expected_counts(claude.setup, claude.audit()) == (0, 0, False)
    line = f"weir ⚠ 0 entered · 0 sent · {NOT_REDACTED}"
    assert _segment(claude) == f"{line} → /weir\n"
    coloured = _segment(claude, colour=True)
    assert f"\x1b[{sx.AMBER}m{NOT_REDACTED}\x1b[0m" in coloured
    assert "✓" not in coloured and f"\x1b[{sx.GREEN}m" not in coloured
    lines = _report(claude)
    assert lines[0] == line
    assert any(line.startswith(f"{NOT_REDACTED}: 1 tool result") for line in lines)


_FLAGGED = [
    ({"context": 0, "sent": 0, "unknown": False},
     f"weir ⚠ 0 entered · 0 sent · {NOT_REDACTED} → /weir"),
    ({"context": 0, "sent": 0, "unknown": False, "kept": 1},
     f"weir ⚠ 0 entered · 0 sent · 1 kept out · {NOT_REDACTED} → /weir"),
    ({"context": 2, "sent": 1, "unknown": False},
     f"weir ⚠ 2 entered · 1 sent · {NOT_REDACTED} → /weir"),
    ({"context": 2, "sent": 1, "unknown": True},
     f"weir ⚠ 2 entered · 1 sent · part unknown · {NOT_REDACTED} → /weir"),
    ({"context": 0, "sent": 0, "unknown": True}, f"weir unknown · {NOT_REDACTED}"),
    ({"context": 0, "sent": 0, "unknown": False, "scanning": 40},
     f"weir scanning… 40% · {NOT_REDACTED}"),
    ({"context": 1, "sent": 0, "unknown": False, "scanning": 55},
     f"weir ⚠ 1 entered · 0 sent · scanning… 55% · {NOT_REDACTED}"),
    ({"context": 0, "sent": 0, "unknown": False, "partial": True},
     f"weir partly checked · {NOT_REDACTED} → /weir"),
    ({"context": 2, "sent": 1, "unknown": True, "partial": True},
     f"weir partly checked · {NOT_REDACTED} → /weir"),
]


@pytest.mark.parametrize("inside", [True, False])
@pytest.mark.parametrize(("args", "words"), _FLAGGED)
def test_possibly_not_redacted_keeps_each_states_words(
    args: dict[str, object], words: str, inside: bool
) -> None:
    """The flag is added to what the line says without it: unknown,
    scanning and partly checked keep their words, and counts show only as
    the line shows them, a zero only once the session is read to its end
    with nothing unknown. Never green, in the inventory's project or out
    of it."""
    args = {**args, "inventoried": inside, "unredacted": True}
    coloured = segment_text(**args, colour=True)  # type: ignore[arg-type]
    assert segment_text(**args) == words  # type: ignore[arg-type]
    assert sx.plain(coloured) == words
    assert f"\x1b[{sx.AMBER}m{NOT_REDACTED}\x1b[0m" in coloured
    assert f"\x1b[{sx.GREEN}m" not in coloured
    bare = segment_text(**args, pointer=False)  # type: ignore[arg-type]
    assert words in (bare, f"{bare} → /weir")


def test_an_unknown_session_with_a_flagged_result_stays_unknown(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    _ran_session(claude)  # a covered result with no marker
    stray = claude.session_dir() / "notes.bin"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"\x00\x01 not a session file")

    assert sx.expected_counts(claude.setup, claude.audit())[2] is True  # the audit: unknown
    assert _segment(claude) == f"weir unknown · {NOT_REDACTED}\n"
    assert _report(claude)[0] == f"weir unknown · {NOT_REDACTED}"


def test_a_pending_marker_fails_once_it_outlives_the_hook_timeout(tmp_path: Path) -> None:
    """Still running (its result not recorded yet): no failure while the
    hook may still finish, a failure once 10 seconds have passed."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("list the files")
    session.tool_use("Bash", {"command": "ls"}, TOOL_ID)
    session.write(claude.transcript())
    marker = _markers(claude) / fx.SESSION_ID / f"{TOOL_ID}.json"
    marker.parent.mkdir(parents=True)
    pending = {"schema": "weir-redaction-marker/1", "state": "pending", "kept_out": {}}

    marker.write_text(json.dumps({**pending, "at": time.time()}))
    assert _segment(claude) == "weir ✓ no known key seen\n"
    marker.write_text(json.dumps({**pending, "at": time.time() - 11}))
    assert _segment(claude) == f"weir ⚠ 0 entered · 0 sent · {NOT_REDACTED} → /weir\n"


def _age(path: Path, seconds: float) -> None:
    then = time.time() - seconds
    os.utime(path, (then, then))


def test_old_markers_are_folded_into_one_summary_without_changing_a_verdict(
    tmp_path: Path,
) -> None:
    """A refresh folds markers older than 7 days into one summary per
    session, at most once a day: kept-out names, a failed call and a done
    call's result read the same after, and a call still running is never
    touched."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("go")
    _kept_out_session(claude, session)  # done, a name kept out, its result recorded
    session.tool_use("Bash", {"command": "ls"}, "toolu_bad")
    session.tool_result("toolu_bad", "total 0\n")
    session.write(claude.transcript())
    folder = _markers(claude) / fx.SESSION_ID
    bad = {"schema": "weir-redaction-marker/1", "state": "failed", "at": 0.0, "kept_out": {}}
    (folder / "toolu_bad.json").write_text(json.dumps(bad))
    running = {**bad, "state": "pending", "at": time.time()}
    (folder / "toolu_running.json").write_text(json.dumps(running))
    before = (_segment(claude), _report(claude))
    assert "1 kept out" in before[0] and NOT_REDACTED in before[0]

    week = 7 * 24 * 3600
    for name in (f"{TOOL_ID}.json", "toolu_bad.json"):
        _age(folder / name, week + 60)
    _age(_markers(claude) / ".compacted", 24 * 3600 + 60)  # the last fold was over a day ago
    after = (_segment(claude), _report(claude))

    assert after == before
    assert sorted(p.name for p in folder.iterdir()) == [".old.json", "toolu_running.json"]
    assert json.loads((folder / "toolu_running.json").read_text()) == running


# --- 5. nothing written holds a value ------------------------------------------------------


def _decodings(text: str) -> list[str]:
    """`text` and what it reads as URL-decoded, JSON-unescaped and
    base64-decoded from each of a run's first four characters."""
    out = [text, urllib.parse.unquote(text), urllib.parse.unquote_plus(text)]
    for literal in re.findall(r'"(?:[^"\\]|\\.)*"', text):
        try:
            out.append(json.loads(literal))
        except ValueError:
            pass
    for run in re.findall(r"[A-Za-z0-9+/_-]{8,}", text):
        for start in range(4):
            part = run[start:].replace("-", "+").replace("_", "/")
            part = part[: len(part) - len(part) % 4]
            out.append(base64.b64decode(part).decode("utf-8", "replace"))
    return out


def test_nothing_the_hook_or_status_line_writes_holds_a_value(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    v = claude.setup.values
    printed: list[str] = []
    for i, (text, _) in enumerate(_cases(v).values()):
        run = _hook(claude, json.dumps(_input("Read", _response("Read", text, text), f"t{i}")))
        printed.append(run.stdout + run.stderr)
    _kept_out_session(claude, fx.Session())
    _ran_session(claude)
    printed += [_segment(claude), _segment(claude, colour=True), "\n".join(_report(claude))]

    written = [p for p in claude.state.rglob("*") if p.is_file()]
    assert any(p.parent.name == fx.SESSION_ID for p in written), "the hook writes markers"
    for text in printed + [p.name + "\n" + p.read_text() for p in written]:
        for decoded in _decodings(text):
            cfx.assert_value_free(decoded, v.values())


# --- 6. setup and undo ------------------------------------------------------------------


def _setup(claude: sx.Claude, *flags: str, answer: str | None = None) -> sx.Run:
    args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
            "--claude-dir", str(claude.config), *flags]
    return claude.invoke(args, stdin=answer)


def _hook_entries(claude: sx.Claude) -> list[object]:
    settings = json.loads(claude.settings.read_text())
    return [g for g in settings.get("hooks", {}).get("PostToolUse", [])
            if " -m weir statusline hook " in json.dumps(g)]


@sx.posix_shell
@pytest.mark.parametrize(
    "answer", ["yes\n", "yes\nno\n", "yes\ny\n", "yes\nYES\n", "yes\n yes\n", "yes\nyes please\n"]
)
def test_setup_adds_the_hook_only_on_an_exact_second_yes(tmp_path: Path, answer: str) -> None:
    claude = sx.build(tmp_path)

    run = _setup(claude, answer=answer)

    assert run.exit_code == 0, run.stderr
    settings = json.loads(claude.settings.read_text())
    assert "hooks" not in settings
    assert "--markers" not in settings["statusLine"]["command"]
    assert "--markers" not in claude.command_file.read_text()


@sx.posix_shell
def test_setup_shows_the_hook_and_adds_it_on_yes(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    dry = _setup(claude, "--dry-run")
    assert not claude.settings.exists()

    run = _setup(claude, answer="yes\nyes\n")

    assert run.exit_code == 0, run.stderr
    (entry,) = _hook_entries(claude)
    assert entry == {"matcher": "Read|Bash|Grep|Glob|WebFetch", "hooks": [
        {"type": "command", "command": entry["hooks"][0]["command"], "timeout": 10}]}  # type: ignore[index]
    command = entry["hooks"][0]["command"]  # type: ignore[index]
    # Shown before anything was written: the entry, and the commands as written.
    segment = json.loads(claude.settings.read_text())["statusLine"]["command"]
    (report,) = [line for line in claude.command_file.read_text().splitlines()
                 if line.startswith("!")]
    (allowed,) = [line for line in claude.command_file.read_text().splitlines()
                  if line.startswith("allowed-tools:")]
    for shown in (command, segment, report, allowed, "matcher Read|Bash|Grep|Glob|WebFetch",
                  "timeout 10 s"):
        assert shown in dry.stdout, shown
    marked = f"--markers {_markers(claude)}"
    assert marked in segment and marked in report
    # The preview names the question the run then asks before adding the hook.
    asked = re.search(r"\n(.+\?) Type yes to add it: ", run.stdout)
    assert asked is not None, run.stdout
    assert f'added only when you also answer yes to "{asked[1]}"' in dry.stdout

    # Claude Code runs the hook command in a shell, the input on stdin.
    text, placed = _cases(claude.setup.values)["raw"]
    shell = sx.run_shell(command, json.dumps(_input("Read", _response("Read", text, text))),
                         claude.env())
    assert shell.exit_code == 0, shell.stderr
    updated = json.loads(shell.stdout)["hookSpecificOutput"]["updatedToolOutput"]
    assert updated == _response("Read", _expected(text, placed)[0], text)


_OWN = {
    "statusLine": {"type": "command", "command": "echo mine"},
    "hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command",
                                                             "command": "echo edited"}]}]},
}


@sx.posix_shell
@pytest.mark.parametrize("before", [None, b'{"model": "fake-model"}', json.dumps(_OWN).encode()])
def test_setup_with_the_hook_then_undo_leaves_settings_as_they_were(
    tmp_path: Path, before: bytes | None
) -> None:
    claude = sx.build(tmp_path)
    if before is not None:
        claude.settings.parent.mkdir(parents=True, exist_ok=True)
        claude.settings.write_bytes(before)
    assert _setup(claude, answer="yes\nyes\n").exit_code == 0
    assert len(_hook_entries(claude)) == 1
    shown = claude.invoke(["statusline", "undo", "--dry-run"]).stdout
    assert "redaction hook" in shown

    run = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert run.exit_code == 0, run.stderr
    assert (claude.settings.read_bytes() if claude.settings.exists() else None) == before


@sx.posix_shell
@pytest.mark.parametrize("stray", [False, True])
def test_undo_removes_the_hooks_markers_and_nothing_else(tmp_path: Path, stray: bool) -> None:
    claude = sx.build(tmp_path)
    assert _setup(claude, answer="yes\nyes\n").exit_code == 0
    (entry,) = _hook_entries(claude)
    command = entry["hooks"][0]["command"]  # type: ignore[index]
    for i, text in enumerate(("ok\n", f"{fx.ACME}={claude.setup.values[fx.ACME]}\n")):
        payload = json.dumps(_input("Bash", _response("Bash", text, text), f"toolu_m{i}"))
        assert sx.run_shell(command, payload, claude.env()).exit_code == 0
    _segment(claude)  # a refresh: the status line's own files beside the markers
    folder = _markers(claude) / fx.SESSION_ID
    assert sorted(p.name for p in folder.iterdir()) == ["toolu_m0.json", "toolu_m1.json"]
    mine = [_markers(claude) / "notes.txt", folder / "notes.txt"]
    for path in mine if stray else []:
        path.write_text("not the hook's")

    shown = claude.invoke(["statusline", "undo", "--dry-run"]).stdout
    assert f"remove the redaction hook's markers in {_markers(claude)}" in shown
    assert claude.invoke(["statusline", "undo"], stdin="yes\n").exit_code == 0

    left = sorted(p.relative_to(claude.state) for p in _markers(claude).rglob("*")) if stray else []
    assert left == ([] if not stray else sorted(
        p.relative_to(claude.state) for p in [*mine, folder]))
    assert _markers(claude).exists() is stray
    assert claude.state.is_dir()  # the checkpoints stay, as undo always left them


@sx.posix_shell
def test_undo_removes_the_markers_after_the_hook_was_taken_out_by_hand(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    assert _setup(claude, answer="yes\nyes\n").exit_code == 0
    (entry,) = _hook_entries(claude)
    text = f"{fx.ACME}={claude.setup.values[fx.ACME]}\n"
    payload = json.dumps(_input("Bash", _response("Bash", text, text)))
    assert sx.run_shell(entry["hooks"][0]["command"], payload, claude.env()).exit_code == 0  # type: ignore[index]
    assert _marker(claude)["state"] == "done"
    settings = json.loads(claude.settings.read_text())
    settings["hooks"]["PostToolUse"].remove(entry)  # as /hooks would
    claude.settings.write_text(json.dumps(settings))

    shown = claude.invoke(["statusline", "undo", "--dry-run"]).stdout
    assert f"remove the redaction hook's markers in {_markers(claude)}" in shown
    assert claude.invoke(["statusline", "undo"], stdin="yes\n").exit_code == 0

    assert not _markers(claude).exists()
    assert claude.state.is_dir()


@sx.posix_shell
@pytest.mark.skipif(os.name == "posix" and os.geteuid() == 0,
                    reason="owner mode bits do not bind root")
def test_undo_stopped_after_the_settings_write_leaves_no_markers(tmp_path: Path) -> None:
    """Undo writes the settings, then cannot remove commands/weir.md: the
    settings no longer name the markers folder, so the markers must be gone
    already, and undo again finishes the rest."""
    claude = sx.build(tmp_path)
    before = b'{"model": "fake-model"}'
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)
    assert _setup(claude, answer="yes\nyes\n").exit_code == 0
    (entry,) = _hook_entries(claude)
    command = entry["hooks"][0]["command"]  # type: ignore[index]
    for i, text in enumerate(("ok\n", f"{fx.ACME}={claude.setup.values[fx.ACME]}\n")):
        payload = json.dumps(_input("Bash", _response("Bash", text, text), f"toolu_m{i}"))
        assert sx.run_shell(command, payload, claude.env()).exit_code == 0
    _segment(claude)
    folder = _markers(claude) / fx.SESSION_ID
    _age(folder / "toolu_m0.json", 7 * 24 * 3600 + 60)
    _age(_markers(claude) / ".compacted", 24 * 3600 + 60)
    _segment(claude)  # folds the old marker into .old.json
    assert sorted(p.name for p in folder.iterdir()) == [".old.json", "toolu_m1.json"]
    assert (_markers(claude) / ".compacted").is_file()

    commands = claude.command_file.parent
    commands.chmod(0o500)
    try:
        stopped = claude.invoke(["statusline", "undo"], stdin="yes\n")
    finally:
        commands.chmod(0o700)
    assert stopped.exit_code == 2, stopped.stderr
    assert str(claude.command_file) in stopped.stderr
    assert claude.settings.read_bytes() == before

    again = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert again.exit_code == 0, again.stderr
    assert not _markers(claude).exists()
    assert not claude.command_file.exists()
    assert claude.settings.read_bytes() == before


@sx.posix_shell
def test_undo_of_one_config_dir_keeps_the_markers_of_another(tmp_path: Path) -> None:
    """Two Claude config dirs set up with the hook, one cache: each hook
    writes its own markers, and undo of one leaves the other's in place."""
    claude = sx.build(tmp_path)
    work = tmp_path / "claude-work"
    text = f"{fx.ACME}={claude.setup.values[fx.ACME]}\n"
    payload = json.dumps(_input("Bash", _response("Bash", text, text)))
    commands: list[str] = []
    for claude_dir in (claude.config, work):
        args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
                "--claude-dir", str(claude_dir)]
        assert claude.invoke(args, stdin="yes\nyes\n").exit_code == 0
        settings = json.loads((claude_dir / "settings.json").read_text())
        (entry,) = settings["hooks"]["PostToolUse"]
        commands.append(entry["hooks"][0]["command"])
        assert f"--markers {_markers(claude, claude_dir)}" in commands[-1]
        assert sx.run_shell(commands[-1], payload, claude.env()).exit_code == 0
    mine, theirs = _markers(claude), _markers(claude, work)
    assert mine != theirs
    kept = sorted(p.relative_to(theirs) for p in theirs.rglob("*"))
    assert [p.name for p in kept] == [fx.SESSION_ID, f"{TOOL_ID}.json"]

    undo = claude.invoke(["statusline", "undo", "--claude-dir", str(claude.config)],
                         stdin="yes\n")

    assert undo.exit_code == 0, undo.stderr
    assert not mine.exists()
    assert sorted(p.relative_to(theirs) for p in theirs.rglob("*")) == kept
    assert json.loads((theirs / fx.SESSION_ID / f"{TOOL_ID}.json").read_text())["state"] == "done"


@sx.posix_shell
def test_undo_leaves_a_weir_hook_the_settings_held_before_setup(tmp_path: Path) -> None:
    """Settings that already run a weir redaction hook: the preview
    suggests no, and after that no, undo puts the settings back as they
    were, leaving that hook and the markers it names alone."""
    claude = sx.build(tmp_path)
    theirs = tmp_path / "their-markers"
    (theirs / fx.SESSION_ID).mkdir(parents=True)
    (theirs / fx.SESSION_ID / "toolu_theirs.json").write_text("{}")
    command = (f"{sys.executable} -m weir statusline hook {' '.join(claude.inputs())}"
               f" --markers {theirs}")
    before = json.dumps({"hooks": {"PostToolUse": [{"matcher": "Read", "hooks": [
        {"type": "command", "command": command}]}]}}).encode()
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)
    assert "redaction hook: cannot be added" in _setup(claude, "--dry-run").stdout
    assert _setup(claude, answer="yes\nno\n").exit_code == 0

    shown = claude.invoke(["statusline", "undo", "--dry-run"])
    undo = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert undo.exit_code == 0, undo.stderr
    assert claude.settings.read_bytes() == before
    assert "markers" not in shown.stdout
    assert (theirs / fx.SESSION_ID / "toolu_theirs.json").read_text() == "{}"


@sx.posix_shell
@pytest.mark.parametrize("before", [b'{"hooks": []}', b'{"hooks": {"PostToolUse": {}}}',
                                    b'{"hooks": "x"}'])
def test_malformed_hooks_refuse_the_hook_and_still_undo(tmp_path: Path, before: bytes) -> None:
    """A `hooks` value Claude Code would not read: setup refuses to add the
    hook to it, and without the hook it sets up and undoes as before."""
    claude = sx.build(tmp_path)
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)

    dry = _setup(claude, "--dry-run")
    refused = _setup(claude, answer="yes\nyes\n")
    # The suggestion names the question the run asked before adding the hook.
    asked = re.search(r"\n(.+\?) Type yes to add it: ", refused.stdout)
    assert asked is not None, refused.stdout
    suggestion = f'answer no to "{asked[1]}" to install the status line alone'
    assert "redaction hook: cannot be added" in dry.stdout and suggestion in dry.stdout
    # Before any question, nothing has changed yet: the preview does not say so.
    (cannot,) = [line for line in dry.lines if line.startswith("redaction hook: cannot be added")]
    assert not cannot.endswith("nothing changed"), cannot
    assert refused.exit_code == 2 and claude.settings.read_bytes() == before
    assert suggestion in refused.stderr and "nothing changed" in refused.stderr
    assert _setup(claude, answer="yes\nno\n").exit_code == 0
    undo = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert undo.exit_code == 0, undo.stderr
    assert claude.settings.read_bytes() == before


@sx.posix_shell
@pytest.mark.parametrize("own", [_OWN, {"permissions": {"deny": []}}])
def test_undo_takes_out_only_the_hook_after_other_settings_changed(
    tmp_path: Path, own: dict[str, object]
) -> None:
    claude = sx.build(tmp_path)
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_text(json.dumps(own))
    assert _setup(claude, answer="yes\nyes\n").exit_code == 0
    later = {**json.loads(claude.settings.read_text()), "model": "fake-model"}
    claude.settings.write_text(json.dumps(later))

    assert claude.invoke(["statusline", "undo"], stdin="yes\n").exit_code == 0

    restored = json.loads(claude.settings.read_text())
    assert restored == {k: v for k, v in {**own, "model": "fake-model"}.items()
                        if k != "statusLine" or "statusLine" in own}


# --- 7. a key that entered through a failed tool call ------------------------------------


def _failed_call(session: fx.Session, tool_id: str, text: str, failed: bool = True) -> int:
    """A call that failed, as Claude Code records it: a tool error. Claude
    Code runs PostToolUseFailure for it, never PostToolUse (hooks reference,
    "PostToolUseFailure"). With `failed` False, a success that carries
    `is_error: false`, as Claude Code writes some."""
    session.tool_use("Bash", {"command": "./deploy.sh"}, tool_id)
    block = {"type": "tool_result", "tool_use_id": tool_id, "content": text, "is_error": failed}
    envelope = session._envelope("user", message={"role": "user", "content": [block]})  # pyright: ignore[reportPrivateUsage]
    return session.record(envelope)


def _claude_code_path(path: str) -> str:
    """An absolute path as a Claude Code rule matches it: on Windows in POSIX
    form, `C:\\Users\\alice` as `/c/Users/alice` (permissions page, "How path
    patterns match")."""
    drive = PureWindowsPath(path).drive
    return f"/{drive[0].lower()}{path[len(drive):]}" if drive else path


def _credential_block(lines: list[str], name: str) -> list[str]:
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{name} ("))
    end = next(i for i in range(start + 1, len(lines)) if not lines[i].startswith("  "))
    return lines[start:end]


def test_weir_names_a_failed_call_and_gives_a_deny_rule_for_the_file(tmp_path: Path) -> None:
    startup = cfx.fake_value("hook-startup-token")
    deploy = cfx.fake_value("hook-deploy-token")
    claude = sx.build(tmp_path, bashrc=f"export STARTUP_TOKEN={startup}\n",
                      project_env=f"DEPLOY_TOKEN={deploy}\n")
    v = claude.setup.values
    session = fx.Session()
    session.prompt("deploy it")
    text = f"Exit code 1\n{fx.AWS_SECRET} = {v[fx.AWS_SECRET]}\n"
    secret = _failed_call(session, "toolu_f1", text)
    _failed_call(session, "toolu_f2", f"Exit code 1\n{fx.ACME}={v[fx.ACME]}\n")
    _failed_call(session, "toolu_f3", f"Exit code 1\ntoken {startup}\n")
    _failed_call(session, "toolu_f4", f"Exit code 1\nDEPLOY_TOKEN={deploy}\n")
    _failed_call(session, "toolu_ok", f"{fx.AWS_ID} = {v[fx.AWS_ID]}\n", failed=False)
    session.write(claude.transcript())
    report = json.loads(claude.setup.report.read_text())
    where = {c["name"]: c["location"] for c in report["credentials"]}
    # The home form of a Claude Code rule path, and a project file's `./`, which
    # Claude Code would read from the session's current directory: its absolute path.
    assert where[fx.AWS_SECRET]["display"].startswith("~/")
    assert where["DEPLOY_TOKEN"]["display"].startswith("./")

    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
                         "--claude-dir", str(claude.config)])

    assert run.exit_code == 0, run.stderr
    failed = "  entered through a failed tool call: 1 time, first at turn 1: the Bash tool result"
    names = (fx.AWS_SECRET, fx.ACME, "STARTUP_TOKEN", "DEPLOY_TOKEN", fx.AWS_ID)
    blocks = {n: _credential_block(run.lines, n) for n in names}
    assert f"{failed}, {claude.transcript()}:{secret}." in "\n".join(blocks[fx.AWS_SECRET])
    for name, path in ((fx.AWS_SECRET, where[fx.AWS_SECRET]["display"]),
                       ("DEPLOY_TOKEN", "/" + _claude_code_path(where["DEPLOY_TOKEN"]["path"]))):
        rule = json.dumps({"permissions": {"deny": [f"Read({path})"]}})
        (deny,) = [line for line in blocks[name] if line.startswith("  deny rule:")]
        assert deny.startswith(f"  deny rule: {rule}"), name
        assert "it does not stop a script or program that opens the file itself" in deny
    # In the environment, from the launch or a startup file: no file a rule could
    # name keeps it out (the startup file is not where the agent reads it).
    for name in (fx.ACME, "STARTUP_TOKEN"):
        assert any(line.startswith(failed) for line in blocks[name]), name
        assert not any(line.startswith("  deny rule:") for line in blocks[name]), name
    # A successful call is not a failed one.
    assert not any("failed tool call" in line or "deny rule" in line for line in blocks[fx.AWS_ID])

    # A project file on Windows: the inventory writes `C:/...`, and Claude Code
    # matches it as `/c/...` (permissions page, "How path patterns match").
    windows = "C:/Users/alice/proj/.env"
    for c in report["credentials"]:
        if c["name"] == "DEPLOY_TOKEN":
            c["location"]["path"] = windows
    claude.setup.report.write_text(json.dumps(report))
    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
                         "--claude-dir", str(claude.config)])
    assert run.exit_code == 0, run.stderr
    rule = json.dumps({"permissions": {"deny": [f"Read(/{_claude_code_path(windows)})"]}})
    (deny,) = [line for line in _credential_block(run.lines, "DEPLOY_TOKEN")
               if line.startswith("  deny rule:")]
    assert deny.startswith(f"  deny rule: {rule}")


@pytest.mark.parametrize("how", ["a key-shaped run", "a run of a found value", "a tab", "long"])
def test_weir_names_a_deny_rule_path_only_as_the_audit_prints_it(
    tmp_path: Path, how: str
) -> None:
    """The rule names the file's exact path, and only when the audit's
    printing rule prints that path unchanged: none for a path that holds a
    key-shaped run, a 6-character run of a found value, or a character the
    report escapes; never a cut or escaped rule."""
    deploy = cfx.fake_value("hook-deploy-token")
    claude = sx.build(tmp_path, project_env=f"DEPLOY_TOKEN={deploy}\n")
    session = fx.Session()
    session.prompt("deploy it")
    _failed_call(session, "toolu_f1", f"Exit code 1\nDEPLOY_TOKEN={deploy}\n")
    session.write(claude.transcript())
    report = json.loads(claude.setup.report.read_text())
    (location,) = [c["location"] for c in report["credentials"] if c["name"] == "DEPLOY_TOKEN"]
    home = str(claude.setup.home.absolute()).replace("\\", "/")
    secret = {"a key-shaped run": "ghp_" + cfx.fake_value("hook-path-token", 36),
              "a run of a found value": deploy[:6], "a tab": "to\tol", "long": "d" * 250}[how]
    if how == "a run of a found value":
        location["path"] = f"{home}/work/{secret}-app/.env"
    else:
        location["display"] = f"~/.config/{secret}/creds"
        location["path"] = f"{home}/.config/{secret}/creds"
    claude.setup.report.write_text(json.dumps(report))

    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
                         "--claude-dir", str(claude.config)])

    assert run.exit_code == 0, run.stderr
    block = _credential_block(run.lines, "DEPLOY_TOKEN")
    assert any(line.startswith("  entered through a failed tool call:") for line in block)
    deny = [line for line in block if line.startswith("  deny rule:")]
    if how == "long":
        rule = json.dumps({"permissions": {"deny": [f"Read({location['display']})"]}})
        (line,) = deny
        assert line.startswith(f"  deny rule: {rule}")
    else:
        assert deny == []
        assert not any(secret[:6] in line or "Read(" in line for line in run.lines)


def test_weir_reports_a_failed_call_line_nested_past_the_recursion_limit(
    tmp_path: Path,
) -> None:
    """A tool's structured result can nest deeper than Python's stack: the
    report reads the line as the audit does, unparsed, and still prints."""
    claude = sx.build(tmp_path)
    session = fx.Session()
    session.prompt("deploy it")
    depth = 200_000
    block = {"type": "tool_result", "tool_use_id": "toolu_deep", "content": "x", "is_error": True}
    envelope = json.dumps(session._envelope("user", message={"role": "user", "content": [block]}))  # pyright: ignore[reportPrivateUsage]
    deep = session.raw_line(f'{envelope[:-1]}, "toolUseResult": {"[" * depth}{"]" * depth}}}')
    session.write(claude.transcript())

    run = claude.invoke(["statusline", "report", *claude.inputs(), "--session", fx.SESSION_ID,
                         "--claude-dir", str(claude.config)])

    assert run.exit_code == 0, run.stderr
    assert f"unknown: unparsed_line {claude.transcript()}:{deep}" in run.lines


# --- 8. a large output, which Claude Code also saves whole ----------------------------------

# Claude Code cuts a large Bash output to its first 30,000 characters in the
# result, saves the whole output beside the session and names that file in
# `persistedOutputPath` (its session file records both).
_CUT = 30_000
# The largest saved output the hook rewrites (docs/statusline.md, "The redaction hook").
_SAVED_CAP = 256 * 1024


def _saved(claude: sx.Claude, text: str, *, name: str = "b7f3lhopj.txt") -> tuple[Path, str]:
    """A large Bash output as Claude Code hands it to the hook: its first
    _CUT characters, and the whole output saved in the session's
    `tool-results` folder, named by `persistedOutputPath`, byte for byte:
    on Windows too, its line ends are not translated."""
    saved = claude.session_dir() / "tool-results" / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_bytes(text.encode())
    response = {**_response("Bash", text[:_CUT], text[:_CUT]),  # type: ignore[dict-item]
                "persistedOutputPath": str(saved), "persistedOutputSize": len(text)}
    payload = {**_input("Bash", response), "transcript_path": str(claude.transcript())}
    return saved, json.dumps(payload)


@pytest.mark.parametrize("where", ["in the result too", "past the cut only"])
def test_the_saved_whole_output_is_rewritten_owner_only(tmp_path: Path, where: str) -> None:
    """The saved file holds the whole output: it is rewritten with the same
    replacements, owner-only, before the call is done, and each name is
    counted once however many copies held it."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    head = f"{fx.ACME}={acme}\n" if where == "in the result too" else ""
    text = head + _filler(_CUT + 5_000) + f"later {fx.ACME}={acme}\n"
    saved, payload = _saved(claude, text)

    run = _hook(claude, payload)

    assert run.exit_code == 0, run.stderr
    assert saved.read_text() == _expected(text, {acme: fx.ACME})[0]
    if os.name == "posix":  # owner and mode bits are POSIX
        assert saved.stat().st_mode & 0o777 == 0o600
    assert not [p.name for p in saved.parent.iterdir() if p != saved]  # no temporary left
    marker = _marker(claude)
    assert marker["state"] == "done"
    assert marker["kept_out"] == {fx.ACME: text.count(acme)}
    if head:
        stdout = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        assert stdout == _expected(text[:_CUT], {acme: fx.ACME})[0]
    else:
        assert run.stdout == ""  # nothing to replace in the result itself


def test_a_saved_output_with_no_known_value_is_left_as_it_is(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    text = _filler(_CUT + 5_000)
    saved, payload = _saved(claude, text)
    before = saved.stat()

    run = _hook(claude, payload)

    assert run.exit_code == 0 and run.stdout == "", run.stderr
    after = saved.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_mode) == (
        before.st_ino, before.st_mtime_ns, before.st_mode)
    assert _marker(claude)["state"] == "done"


def _unusable(claude: sx.Claude, how: str, saved: Path, payload: str, tmp_path: Path) -> str:
    """The saved output made one the hook must not rewrite; returns the
    hook input."""
    data = json.loads(payload)
    response = data["tool_response"]
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text(saved.read_text())
    if how == "missing":
        saved.unlink()
    elif how == "outside the session's folder":
        response["persistedOutputPath"] = str(elsewhere)
    elif how == "another session's folder":
        other = claude.session_dir("other-session") / "tool-results" / saved.name
        other.parent.mkdir(parents=True)
        other.write_text(saved.read_text())
        response["persistedOutputPath"] = str(other)
    elif how == "a dot-dot path":
        response["persistedOutputPath"] = str(saved.parent / ".." / ".." / "x.txt")
    elif how == "a symbolic link":
        saved.unlink()
        saved.symlink_to(elsewhere)
    elif how == "a linked folder":
        folder = saved.parent
        moved = tmp_path / "moved-tool-results"
        folder.rename(moved)
        folder.symlink_to(moved)
    elif how == "unreadable":
        saved.chmod(0)
    elif how == "unwritable":
        saved.parent.chmod(0o500)
    elif how == "not a path":
        response["persistedOutputPath"] = 5
    elif how == "a trailing slash":
        response["persistedOutputPath"] = f"{saved}{os.sep}"
    elif how == "a dot segment":
        response["persistedOutputPath"] = os.path.join(saved.parent, "sub", "..", saved.name)
    elif how == "a FIFO":
        saved.unlink()
        os.mkfifo(saved)
    elif how == "a directory":
        saved.unlink()
        saved.mkdir()
    return json.dumps(data)


@pytest.mark.parametrize("how", [
    "missing", "outside the session's folder", "another session's folder", "a dot-dot path",
    "a symbolic link", "a linked folder", "unreadable", "unwritable", "not a path",
    "a trailing slash", "a dot segment", "a FIFO", "a directory",
])
def test_a_saved_output_the_hook_cannot_rewrite_is_flagged(
    tmp_path: Path, how: str
) -> None:
    """Anything but a rewritten saved file leaves the call flagged, never
    done. The result itself is still redacted: an exit 1 would make Claude
    Code send the original."""
    if how in ("a symbolic link", "a linked folder", "unreadable", "unwritable", "a FIFO") and (
            os.name != "posix"):
        pytest.skip("links and mode bits are POSIX here")
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    text = f"{fx.ACME}={acme}\n" + _filler(_CUT + 5_000)
    saved, payload = _saved(claude, text)
    payload = _unusable(claude, how, saved, payload, tmp_path)
    elsewhere = tmp_path / "elsewhere.txt"

    run = _hook(claude, payload)
    for folder in (saved.parent, tmp_path / "moved-tool-results"):
        if folder.is_dir() and not folder.is_symlink():
            folder.chmod(0o700)

    assert run.exit_code == 0, run.stderr
    stdout = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert acme not in stdout and _label(fx.ACME) in stdout
    (line,) = run.stderr.splitlines()
    assert line.startswith(f"weir: {NOT_REDACTED}:") and acme not in line
    assert _marker(claude)["state"] == "failed"
    assert elsewhere.read_text() == text  # nothing outside the session's folder is touched


def test_a_saved_output_too_large_to_rewrite_is_flagged_and_left(tmp_path: Path) -> None:
    """Searching a saved output past the cap could outlast the hook's
    timeout, which would lose the replaced result too: the file is left as
    it is and the call flagged, while the result is still replaced."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    text = f"{fx.ACME}={acme}\n" + _filler(_SAVED_CAP)
    saved, payload = _saved(claude, text)
    before, data = saved.stat(), saved.read_bytes()
    assert len(data) > _SAVED_CAP

    run = _hook(claude, payload)

    assert run.exit_code == 0, run.stderr
    stdout = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert stdout == _expected(text[:_CUT], {acme: fx.ACME})[0]
    (line,) = run.stderr.splitlines()
    assert line.startswith(f"weir: {NOT_REDACTED}: its saved output is too large to rewrite"
                           " within the hook's timeout;"), line
    assert _marker(claude)["state"] == "failed"
    after = saved.stat()
    assert saved.read_bytes() == data
    assert (after.st_ino, after.st_mtime_ns, after.st_mode) == (
        before.st_ino, before.st_mtime_ns, before.st_mode)


@pytest.mark.skipif(sys.platform == "win32", reason="in process, only a fork's child is killed")
def test_a_saved_output_too_slow_to_search_is_left_and_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The search of a saved file stops at its deadline, so the replaced
    result is still printed inside Claude Code's timeout: the file is left
    as it is and the call flagged. The search of the saved file's text, the
    only one holding a line placed past the result's cut, is made to sleep
    30 s first; the deadline falls after the result's own redaction."""
    from weir.statusline import hook

    slow = "weir-test: this saved output is slow to search\n"
    search = Matcher.spans

    def spans(self: Matcher, text: str) -> list[tuple[int, int, bytes]]:
        if slow in text:
            time.sleep(30)
        return search(self, text)

    monkeypatch.setattr(Matcher, "spans", spans)
    monkeypatch.setattr(hook, "SAVED_DEADLINE_S", 1.5)
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    text = f"{fx.ACME}={acme}\n" + _filler(_CUT + 1_000) + slow + f"{fx.ACME}={acme}\n"
    saved, payload = _saved(claude, text)
    assert slow not in json.loads(payload)["tool_response"]["stdout"]

    began = time.monotonic()
    run = _hook(claude, payload)

    assert time.monotonic() - began < 10  # the slow search was left behind
    assert run.exit_code == 0, run.stderr
    stdout = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert acme not in stdout and _label(fx.ACME) in stdout
    (line,) = run.stderr.splitlines()
    assert line.startswith(f"weir: {NOT_REDACTED}:") and acme not in line
    assert saved.read_text() == text  # left as it is
    assert _marker(claude)["state"] == "failed"


def test_without_a_fork_the_hook_ends_its_process_at_the_deadline(tmp_path: Path) -> None:
    """Where there is no fork (Windows) the search runs in a thread, which
    would hold the process up after the result is printed, past Claude
    Code's timeout: the hook then ends its own process, so Claude Code takes
    the replaced result. Run in its own process, as Claude Code runs it, at
    the real deadline, on content that takes many seconds to search well
    under the size cap: one long word of mixed characters with a break after
    every character (without the end, this process ran about 10 s)."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    rng = random.Random(7)
    word = ".".join(rng.choice(string.ascii_letters + string.digits) for _ in range(110_000))
    text = f"{fx.ACME}={acme}\n" + _filler(_CUT + 1_000) + word + f"\n{fx.ACME}={acme}\n"
    assert len(text.encode()) < 256 * 1024  # under the size cap: only the deadline stops it
    saved, payload = _saved(claude, text)
    code = "\n".join([
        "import sys",
        "from weir.statusline import hook",
        "hook._spans_by = hook._spans_in_thread  # the search where there is no fork",
        "from weir.cli.main import main",
        "sys.argv = ['weir', *sys.argv[1:]]",
        "main()",
    ])
    args = [sys.executable, "-c", code, "statusline", "hook", *claude.inputs(),
            "--markers", str(_markers(claude))]

    began = time.monotonic()
    proc = subprocess.run(args, input=payload.encode(), capture_output=True, timeout=60,
                          env={**os.environ, **claude.env()}, check=False)

    assert time.monotonic() - began < 8, "the process waited for the search"
    assert proc.returncode == 0, proc.stderr
    stdout = json.loads(proc.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert acme not in stdout and _label(fx.ACME) in stdout
    (line,) = proc.stderr.decode().splitlines()
    assert line.startswith(f"weir: {NOT_REDACTED}:") and acme not in line
    assert saved.read_bytes() == text.encode()  # left as it is
    assert _marker(claude)["state"] == "failed"


def test_a_flagged_saved_output_shows_on_the_status_line(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    text = f"{fx.ACME}={acme}\n" + _filler(_CUT + 5_000)
    saved, payload = _saved(claude, text)
    saved.unlink()  # not there when the hook runs
    assert _hook(claude, payload).exit_code == 0
    session = fx.Session()
    session.prompt("print the log")
    session.tool_use("Bash", {"command": "cat big.log"}, TOOL_ID)
    session.tool_result(TOOL_ID, f"Output too large. Preview: {fx.ACME}={_label(fx.ACME)}")
    session.write(claude.transcript())

    assert NOT_REDACTED in _segment(claude)


def test_weir_flags_a_saved_copy_failure_without_claiming_the_output_went_through(
    tmp_path: Path,
) -> None:
    """A call failed over its saved copy alone: the result itself was
    replaced, so /weir's line says the output or its saved copy may hold a
    key, never that the output went to the model as it was."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    text = f"{fx.ACME}={acme}\n" + _filler(_CUT + 5_000)
    saved, payload = _saved(claude, text)
    saved.unlink()  # not there when the hook runs
    run = _hook(claude, payload)
    assert run.exit_code == 0 and _marker(claude)["state"] == "failed"
    shown = json.loads(run.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    session = fx.Session()
    session.prompt("print the log")
    session.tool_use("Bash", {"command": "cat big.log"}, TOOL_ID)
    session.tool_result(TOOL_ID, shown[:2_000])
    session.write(claude.transcript())

    lines = _report(claude)

    (flag,) = [line for line in lines if line.startswith(f"{NOT_REDACTED}:")]
    assert flag.endswith("its output, or its saved copy, may hold a key"), flag
    assert "went to the model as it was" not in flag


def test_weir_advises_deleting_a_saved_output_that_holds_a_key(tmp_path: Path) -> None:
    """With no hook, Claude Code's saved copy of a large output holds the
    key: it never entered the context, but the agent was told where it is."""
    claude = sx.build(tmp_path)
    acme = claude.setup.values[fx.ACME]
    session = fx.Session()
    session.prompt("print the log")
    session.tool_use("Bash", {"command": "cat big.log"}, TOOL_ID)
    saved = claude.session_dir() / "tool-results" / "b7f3lhopj.txt"
    session.tool_result(TOOL_ID, f"Output too large. Full output saved to: {saved}")
    session.write(claude.transcript())
    saved.parent.mkdir(parents=True)
    saved.write_text(_filler(_CUT) + f"{fx.ACME}={acme}\n")

    lines = _report(claude)

    block = _credential_block(lines, fx.ACME)
    (sits,) = [line for line in block if line.startswith("  now sits in: ")]
    assert Path(sits.removeprefix("  now sits in: ")).samefile(saved)  # as Windows spells it
    (advice,) = [line for line in block if line.startswith("  advice:")]
    assert "Claude Code saved a tool output holding it" in advice
    assert "gave the agent that file's path" in advice and "delete that file" in advice
