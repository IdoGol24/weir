"""Tests for the command guard (docs/statusline.md, "The command guard"),
written before the implementation.

FAKE DATA ONLY: the fake home, inventory and values of statusline_fixtures /
audit_fixtures. Each hook input is the documented PreToolUse input with
`tool_input.command` the Bash command string. What the guard must decide is
worked out here from the rule the design states and from where the fixture
put each credential, never from the guard's own output. The guard is a
defensive accident catcher; these tests drive the commands it must block (an
environment dump, a read of a credential file, a CLI that hands back a token)
and the ordinary commands it must leave alone, check the deny carries no
value/path/command, exercise the lexer (pipelines, substitutions, `sh -c`,
wrappers, heredoc bodies), the fail-open paths, and drift-test the rule list
in the code against docs/statusline.md.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import audit_fixtures as fx
import canary_fixtures as cfx
import pytest
import statusline_fixtures as sx

from weir.statusline import guard

# The WHAT each rule family puts in the deny reason, from the design. Restated
# here so a change to the code's wording is caught, not copied from the code.
ENV = "the environment"
VARS = "the shell's variables"
PROC = "a process's environment"
PS = "processes' environments"
VARIABLE = "a variable that holds a credential"
FILE = "a file that holds a credential"
TOKEN = "a stored credential or token"

# The exact deny reason, from the captain's intent ("tells the agent why in a
# message that holds no value") and the design. Built here, compared to the
# guard's output.
REASON = (
    "Weir blocked this command before it ran: it would print {what}, which would put a"
    " credential into this session. Do not run it in another form. Where a command needs a"
    ' credential, refer to it by name (such as "$API_TOKEN") without printing it; where the'
    " user needs to see it, ask them to run the command themselves. (weir guard {rule}; it"
    " catches common commands only and is not a security boundary.)"
)

DOCS = Path(__file__).resolve().parents[3] / "docs" / "statusline.md"

# `git commit -m "$(cat <<'EOF' ... EOF\n)"`, the way Claude Code commits,
# with a body that holds an unmatched `)` (a numbered list) and backticked
# commands, and one with an apostrophe. A heredoc body is data.
COMMIT_PAREN = (
    "git commit -m \"$(cat <<'EOF'\nfeat: add the guard\n\n1) add guard\n"
    "2) docs for `gh auth token` and `printenv`\nEOF\n)\""
)
COMMIT_APOSTROPHE = (
    "git commit -m \"$(cat <<'EOF'\nfix: Don't print `printenv`\nEOF\n)\""
)
_UNSET = object()


def _stdin(command: object, cwd: object, tool: str = "Bash",
           has_command: bool = True) -> str:
    tool_input: dict[str, object] = {"command": command} if has_command else {}
    return json.dumps({
        "session_id": fx.SESSION_ID,
        "transcript_path": "/fake/home/.claude/projects/-fake-home-work-proj/s.jsonl",
        "cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_input": tool_input, "tool_use_id": "toolu_01Guard",
    })


def _guard(claude: sx.Claude, command: object, *, cwd: object = _UNSET,
           tool: str = "Bash", report: Path | None = None, raw: str | None = None,
           has_command: bool = True) -> sx.Run:
    args = ["statusline", "guard", "--inventory", str(report or claude.setup.report)]
    stdin = raw if raw is not None else _stdin(
        command, claude.project() if cwd is _UNSET else cwd, tool, has_command)
    return claude.invoke(args, stdin=stdin)


def _reason(run: sx.Run) -> str:
    assert run.exit_code == 0, run.stderr
    out = json.loads(run.stdout)
    assert list(out) == ["hookSpecificOutput"]
    hso = out["hookSpecificOutput"]
    assert list(hso) == ["hookEventName", "permissionDecision", "permissionDecisionReason"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    return hso["permissionDecisionReason"]


def _assert_deny(run: sx.Run, rule: str, what: str) -> None:
    assert _reason(run) == REASON.format(rule=rule, what=what)


def _assert_allow(run: sx.Run) -> None:
    assert run.exit_code == 0, run.stderr
    assert run.stdout == ""


# --- 1 and 2. each rule blocks, ordinary commands run -----------------------------------


@pytest.mark.parametrize("command", [
    "env", "printenv", "/usr/bin/env", "env -i", "env -u FOO", "env PYTHONPATH=.",
])
def test_env_dump_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "env-dump", ENV)


@pytest.mark.parametrize("command", [
    "set", "export", "export -p", "declare", "declare -x", "typeset -p", "readonly",
])
def test_a_whole_variable_dump_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "shell-vars", VARS)


@pytest.mark.parametrize("command", [
    "cat /proc/self/environ", "cat /proc/1234/environ", "cat /proc/thread-self/environ",
    "head /proc/self/task/7/environ", "cat < /proc/self/environ",
    "tr '\\0' '\\n' < /proc/self/environ",
    # Any process id, written as an expansion or a glob, is a process's environment.
    "cat /proc/$$/environ", "cat /proc/$PPID/environ", "cat /proc/*/environ",
    "cat /proc/$(pgrep app)/environ", "cat /proc/self/task/*/environ",
])
def test_a_process_environment_file_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "proc-environ", PROC)


@pytest.mark.parametrize("command", [
    "ps auxe", "ps eww", "ps axe", "ps -o user e", "ps axo pid,command e", "ps eo user",
])
def test_ps_printing_environments_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "ps-environ", PS)


@pytest.mark.parametrize("command", [
    "echo $ACME_API_TOKEN", 'echo "$ACME_API_TOKEN"', "echo ${ACME_API_TOKEN}",
    'printf "%s" "$GH_TOKEN"', "printenv ACME_API_TOKEN", "declare -p GH_TOKEN",
    "typeset -p PLAIN_SECRET", 'echo "token is ${ACME_API_TOKEN:-none}"',
    # Piped into a program that prints it back, or sent to the terminal.
    'echo "$ACME_API_TOKEN" | cat', 'echo "$ACME_API_TOKEN" | tee x',
    'printf %s "$ACME_API_TOKEN" | base64', 'echo "$ACME_API_TOKEN" | sudo tee x',
    'echo "$ACME_API_TOKEN" |\n  cat', 'echo "$ACME_API_TOKEN" | (gh auth login --with-token)',
    'echo "$ACME_API_TOKEN" >&2', 'echo "$ACME_API_TOKEN" > /dev/stderr',
    'echo "$ACME_API_TOKEN" 2>/dev/null', 'echo "$ACME_API_TOKEN" 1>&2',
    'echo "$ACME_API_TOKEN" | gh auth login --with-token; echo "$GH_TOKEN"',
    'echo "$ACME_API_TOKEN"; gh auth login --with-token',
    'echo "$ACME_API_TOKEN" && gh auth login --with-token',
    'echo "$ACME_API_TOKEN" || gh auth login --with-token',
    # Captured by a substitution, then printed by the command that holds it.
    'echo "$(echo "$ACME_API_TOKEN")"', 'echo "Bearer `printf %s "$ACME_API_TOKEN"`"',
    'echo "$(echo -n "u:$ACME_API_TOKEN" | base64)"', 'printf %s "$(cat <<< x; echo $GH_TOKEN)"',
    'echo "$(echo "$ACME_API_TOKEN"; ls)"',
    # Captured or sent to a file, but also sent to a stream the agent sees.
    'x=$(echo "$ACME_API_TOKEN" >&2)', 'x=`echo "$ACME_API_TOKEN" 1>&2`',
    'x=$(echo "$ACME_API_TOKEN" > /dev/stderr)', 'x=$(echo "$ACME_API_TOKEN" | tee /dev/stderr)',
    'echo "$ACME_API_TOKEN" | tee /dev/stderr > out', 'echo "$ACME_API_TOKEN" > out >&2',
    'x=$(echo "$ACME_API_TOKEN" | tee -a /dev/tty)',
    # A redirect binds to its own command, never to the one after it.
    'ls &>/dev/null; echo "$ACME_API_TOKEN"', 'command -v gh &>/dev/null && echo "$ACME_API_TOKEN"',
    'ls &>/dev/null\necho "$ACME_API_TOKEN"', '> out.log; echo "$ACME_API_TOKEN"',
    '{ ls; } >/dev/null; echo "$ACME_API_TOKEN"', 'echo "$ACME_API_TOKEN" &> /dev/stderr',
])
def test_printing_an_inventoried_variable_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "credential-variable", VARIABLE)


@pytest.mark.parametrize("command", [
    "cat ~/.aws/credentials", "cat $HOME/.aws/credentials", "grep key ~/.aws/credentials",
    "base64 ~/.aws/credentials", "cat < ~/.aws/credentials", "sort -u ~/.aws/credentials",
    "cat ~/.aws/*",
])
def test_reading_a_credential_file_is_blocked(tmp_path: Path, command: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), "credential-file", FILE)


def test_a_project_credential_file_is_blocked_relative_to_cwd(tmp_path: Path) -> None:
    claude = sx.build(tmp_path, project_env="DEPLOY_TOKEN=" + cfx.fake_value("guard-deploy") + "\n")
    _assert_deny(_guard(claude, "cat .env", cwd=claude.project()), "credential-file", FILE)
    # The same read from another folder names no credential file: left to run.
    _assert_allow(_guard(claude, "cat .env", cwd=str(tmp_path)))


_CLI = [
    ("gh auth token", "gh-auth-token"),
    ("gh -R x/y auth token", "gh-auth-token"),
    ("gh auth status --show-token", "gh-auth-show-token"),
    ("git credential fill", "git-credential-fill"),
    ("git -C . credential fill", "git-credential-fill"),
    ("git credential-store get", "git-credential-helper"),
    ("docker-credential-desktop get", "docker-credential-get"),
    ("gcloud auth print-access-token", "gcloud-print-token"),
    ("gcloud auth print-identity-token", "gcloud-print-token"),
    ("gcloud secrets versions access latest --secret=s", "gcloud-secrets-access"),
    ("az account get-access-token", "az-account-get-token"),
    ("az keyvault secret show --name n --vault-name v", "az-keyvault-secret-show"),
    ("aws configure get aws_secret_access_key", "aws-configure-get"),
    ("aws configure export-credentials", "aws-configure-export-credentials"),
    ("aws ecr get-login-password", "aws-ecr-login-password"),
    ("aws ecr-public get-login-password --region us-east-1", "aws-ecr-login-password"),
    ("aws codeartifact get-authorization-token --domain d", "aws-codeartifact-token"),
    ("aws secretsmanager get-secret-value --secret-id s", "aws-secretsmanager-get"),
    ("aws ssm get-parameter --name n --with-decryption", "aws-ssm-get-parameter"),
    ("aws ssm get-parameters --names n --with-decryption", "aws-ssm-get-parameter"),
    ("kubectl config view --raw", "kubectl-config-view-raw"),
    ("kubectl get secret s -o yaml", "kubectl-get-secret"),
    ("kubectl get secrets -o jsonpath={.data}", "kubectl-get-secret"),
    ("security find-generic-password -w -s svc", "security-find-password"),
    ("security find-internet-password -g -s svc", "security-find-password"),
    ("op read op://vault/item/field", "op-read"),
    ("op item get login --reveal", "op-item-get-reveal"),
    ("vault print token", "vault-print-token"),
    ("vault kv get secret/x", "vault-kv-get"),
    ("sops -d secrets.enc.yaml", "sops-decrypt"),
    ("sops decrypt secrets.enc.yaml", "sops-decrypt"),
    ("ansible-vault view vault.yml", "ansible-vault-view"),
    ("heroku auth:token", "heroku-auth-token"),
    ("fly auth token", "fly-auth-token"),
    ("flyctl auth token", "fly-auth-token"),
    ("secret-tool lookup service svc", "secret-tool-lookup"),
    ("pass show github/token", "pass-show"),
    ("doppler secrets get X --plain", "doppler-secrets-get"),
    ("doppler secrets download --no-file", "doppler-secrets-get"),
]


@pytest.mark.parametrize(("command", "rule"), _CLI)
def test_a_cli_that_hands_back_a_token_is_blocked(tmp_path: Path, command: str, rule: str) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), rule, TOKEN)


def test_every_cli_rule_is_exercised() -> None:
    """Each rule in the code has at least one blocked command above, so a new
    rule without a test is caught."""
    assert {rule for _, rule in _CLI} == {c.id for c in guard._CLI}


@pytest.mark.parametrize("command", [
    "ls", "ls -la", "cat README.md", "grep -r TODO .", "env PYTHONPATH=. pytest",
    "env -i PATH=/usr/bin make", "set -x", "set -- a b", "declare -f myfunc",
    "export FOO=bar", "ps aux", "ps -ef", "ps -e",
    "echo '$ACME_API_TOKEN'", "echo ${#ACME_API_TOKEN}", "echo $PATH",
    'curl -H "Authorization: Bearer $ACME_API_TOKEN" https://api.example.invalid',
    "printenv PATH", "cat ~/.aws/config", "ls ~/.aws/credentials", "wc -l ~/.aws/credentials",
    "chmod 600 ~/.aws/credentials", "cat /proc/self/status",
    "aws configure get region", "aws ssm get-parameter --name n", "kubectl get secret s",
    "kubectl get pods -o yaml", "gh auth status", "git credential", "op item get login",
    "security find-generic-password -s svc", "pass ls", "vault kv put secret/x value=1",
    "command -v printenv",
    "ps -p 1 -o user", "ps -C sleep", "ps -u jenkins", "ps -o time -p 1", "ps axo user",
    "ps --sort time", "ps -U jenkins -u jenkins", "ps -eo user", "ps -eo etime", "ps -fu jenkins",
    "ps -fC sleep",
    # A credential passed on stdin or written to a file is used, not printed.
    'echo "$ACME_API_TOKEN" | gh auth login --with-token',
    'printf %s "$ACME_API_TOKEN" | docker login --password-stdin',
    'echo "$ACME_API_TOKEN" |\n  gh auth login --with-token',
    'echo "$ACME_API_TOKEN" > out.txt', 'echo "$ACME_API_TOKEN" >> out.txt',
    'echo "$ACME_API_TOKEN" 2>/dev/null > out.txt', 'echo "$ACME_API_TOKEN" >/dev/null',
    # Captured by a command substitution: the value goes into another
    # command's argument, not to the agent.
    'curl -H "Authorization: Bearer $(printf %s "$ACME_API_TOKEN")" https://api.example.invalid',
    'curl -H "Authorization: Basic $(echo -n "u:$ACME_API_TOKEN" | base64)"'
    " https://api.example.invalid",
    'x=$(echo "$ACME_API_TOKEN")', 'x=`echo "$ACME_API_TOKEN"`',
    'x=$(echo "$ACME_API_TOKEN" | tee /dev/null)', 'echo "$ACME_API_TOKEN" | tee out > /dev/null',
    'x=$(echo "$ACME_API_TOKEN" 2>&1)',
    'echo "$ACME_API_TOKEN" &>/dev/null', 'echo "$ACME_API_TOKEN" &>> out.log',
    'echo "status: $(curl -s -H "Authorization: Bearer $ACME_API_TOKEN" https://x.invalid)"',
])
def test_ordinary_commands_are_left_to_run(tmp_path: Path, command: str) -> None:
    _assert_allow(_guard(sx.build(tmp_path), command))


# --- 2. the deny names no value, path or command ------------------------------------------


def test_the_deny_reason_names_no_value_path_or_command(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    values = claude.setup.values
    # Forward slashes so the command is POSIX on every OS (a backslash is a
    # shell escape; the guard and a real POSIX shell never see a Windows path).
    home = claude.setup.home.as_posix()
    cases = [
        'echo "$ACME_API_TOKEN"',
        f"cat {home}/.aws/credentials",
        f"cat {home}/.aws/credentials && echo {values[fx.ACME]}",  # the value in the command
    ]
    for command in cases:
        run = _guard(claude, command)
        text = run.stdout + run.stderr
        reason = _reason(run)
        # No credential value or 6-character run of one, decoded or not.
        cfx.assert_value_free(text, values.values())
        # No path, variable name or command fragment from the input appears:
        # the whole command, the home path, the variable name, the file name.
        assert home not in text
        assert command not in text
        assert "ACME_API_TOKEN" not in reason
        assert "credentials" not in reason


# --- 3. lexing: pipelines, substitutions, wrappers, heredocs ------------------------------


@pytest.mark.parametrize(("command", "rule", "what"), [
    ("ls && gh auth token", "gh-auth-token", TOKEN),
    ("false || cat ~/.aws/credentials", "credential-file", FILE),
    ("ls | gh auth token", "gh-auth-token", TOKEN),
    ("echo $(gh auth token)", "gh-auth-token", TOKEN),
    ("echo `gh auth token`", "gh-auth-token", TOKEN),
    ("(printenv)", "env-dump", ENV),
    ("{ gh auth token; }", "gh-auth-token", TOKEN),
    ("bash -c 'printenv'", "env-dump", ENV),
    ('sh -c "gh auth token"', "gh-auth-token", TOKEN),
    ("bash -lc 'gh auth token'", "gh-auth-token", TOKEN),
    ("eval printenv", "env-dump", ENV),
    ("sh -c 'ls; gh auth token'", "gh-auth-token", TOKEN),
    ("env -S 'printenv'", "env-dump", ENV),
    ("diff <(gh auth token) /dev/null", "gh-auth-token", TOKEN),
    # Inside a compound command: the reserved words are not the program.
    ("if true; then gh auth token; fi", "gh-auth-token", TOKEN),
    ("if printenv; then :; fi", "env-dump", ENV),
    ("if false; then :; elif true; then printenv; else printenv; fi", "env-dump", ENV),
    ("while true; do printenv; done", "env-dump", ENV),
    ("until false; do gh auth token; done", "gh-auth-token", TOKEN),
    ("for f in a b; do cat ~/.aws/credentials; done", "credential-file", FILE),
    ("! printenv", "env-dump", ENV),
    ("if ! printenv; then :; fi", "env-dump", ENV),
    ("if true; then { printenv; }; fi", "env-dump", ENV),
    ("if (printenv); then :; fi", "env-dump", ENV),
    ("f() { echo hi; }; printenv", "env-dump", ENV),
    ("f() { printenv; }", "env-dump", ENV),
    ("function f { printenv; }", "env-dump", ENV),
    ("function f() { gh auth token; }; f", "gh-auth-token", TOKEN),
    ("function f { echo; }; printenv", "env-dump", ENV),
    ("x=$(if true; then gh auth token; fi)", "gh-auth-token", TOKEN),
    ("if true; then FOO=1 printenv; fi", "env-dump", ENV),
    # A stray closer at the top does not end the check.
    ("echo ) ; printenv", "env-dump", ENV),
    ("} ; printenv", "env-dump", ENV),
    ("printenv 2>/dev/null", "env-dump", ENV),
])
def test_the_guard_finds_the_command_wherever_it_hides(
    tmp_path: Path, command: str, rule: str, what: str
) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), rule, what)


@pytest.mark.parametrize("command", [
    "cat <<'EOF'\nprintenv\ngh auth token\nEOF",  # a heredoc body is data, not commands
    "cat <<-END\n\tcat ~/.aws/credentials\nEND",
    "echo '$(gh auth token)'",  # single-quoted: no command substitution
    "git commit -m \"$(cat <<'EOF'\nprintenv\nEOF\n)\"",
    COMMIT_PAREN, COMMIT_APOSTROPHE,
])
def test_a_heredoc_body_or_single_quote_is_not_a_command(tmp_path: Path, command: str) -> None:
    _assert_allow(_guard(sx.build(tmp_path), command))


@pytest.mark.parametrize("body", [COMMIT_PAREN, COMMIT_APOSTROPHE])
def test_the_command_after_a_heredoc_commit_message_is_still_checked(
    tmp_path: Path, body: str
) -> None:
    """Claude Code's own commit form: a heredoc inside `$(...)`. The body's
    `)` or `'` neither ends the substitution nor hides what follows it."""
    claude = sx.build(tmp_path)
    _assert_deny(_guard(claude, body + " && printenv"), "env-dump", ENV)
    _assert_deny(_guard(claude, body + "\ngh auth token"), "gh-auth-token", TOKEN)


@pytest.mark.parametrize(("command", "rule", "what"), [
    ("sudo cat /proc/self/environ", "proc-environ", PROC),
    ("sudo -u root printenv", "env-dump", ENV),
    ("nohup printenv", "env-dump", ENV),
    ("timeout 5 gh auth token", "gh-auth-token", TOKEN),
    ("timeout -s KILL 5 printenv", "env-dump", ENV),
    ("nice -n 10 printenv", "env-dump", ENV),
    ("command printenv", "env-dump", ENV),
    ("env -i gh auth token", "gh-auth-token", TOKEN),
    ("stdbuf -oL gh auth token", "gh-auth-token", TOKEN),
])
def test_wrappers_are_peeled_to_the_real_command(
    tmp_path: Path, command: str, rule: str, what: str
) -> None:
    _assert_deny(_guard(sx.build(tmp_path), command), rule, what)


# --- 4. fail open --------------------------------------------------------------------------


def test_an_unreadable_inventory_leaves_an_ordinary_command_to_run(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    missing = claude.setup.report.with_suffix(".missing")
    run = _guard(claude, "ls", report=missing)
    assert (run.exit_code, run.stdout) == (1, "")
    (line,) = run.stderr.splitlines()
    assert guard.GUARD_NOT_CHECKED in line
    cfx.assert_value_free(line, claude.setup.values.values())


def test_a_fixed_rule_still_blocks_when_the_inventory_is_gone(tmp_path: Path) -> None:
    """The fixed rules need no inventory, so a credential dump is blocked even
    when the report cannot be read; only the variable and file rules need it."""
    claude = sx.build(tmp_path)
    missing = claude.setup.report.with_suffix(".missing")
    _assert_deny(_guard(claude, "printenv", report=missing), "env-dump", ENV)
    # The variable rule needs the inventory: with none, the call runs (exit 1).
    run = _guard(claude, "echo $ACME_API_TOKEN", report=missing)
    assert run.exit_code == 1


@pytest.mark.parametrize(("kwargs", "allow"), [
    ({"tool": "Read"}, True),
    ({"tool": "Edit"}, True),
    ({"has_command": False}, True),
    ({"command": None}, True),
])
def test_only_a_bash_command_is_checked(
    tmp_path: Path, kwargs: dict[str, object], allow: bool
) -> None:
    _assert_allow(_guard(sx.build(tmp_path), kwargs.pop("command", "printenv"), **kwargs))


@pytest.mark.parametrize("command", ["echo (x)", "echo x)", ")", "foo ) bar", "a (b) c"])
def test_malformed_commands_do_not_hang_the_lexer(tmp_path: Path, command: str) -> None:
    """A stray metacharacter the lexer cannot place is skipped, never looped
    on: the guard returns promptly and leaves the call to run."""
    _assert_allow(_guard(sx.build(tmp_path), command))


@pytest.mark.parametrize("stdin", ["not json", "", "[]", "42"])
def test_input_it_cannot_read_fails_open(tmp_path: Path, stdin: str) -> None:
    run = _guard(sx.build(tmp_path), None, raw=stdin)
    assert run.exit_code == 1
    assert run.stdout == ""
    (line,) = run.stderr.splitlines()
    assert guard.GUARD_NOT_CHECKED in line


# --- 5. the rule list does not drift between the code and the docs ------------------------


def _docs_section() -> str:
    text = DOCS.read_text()
    assert "## The command guard" in text, "docs/statusline.md has no command guard section"
    return text.split("## The command guard", 1)[1].split("\n## ", 1)[0]


def test_the_docs_rule_table_matches_the_code() -> None:
    """The rule table in docs/statusline.md lists exactly the rules the code
    matches, with the same ids, in the same order, each with the shape it
    would print. Derived from the docs artifact and the code, not restated."""
    section = _docs_section()
    rows = re.findall(r"^\| `([a-z][a-z0-9-]*)` \| (.+?) \|", section, re.M)
    assert rows == list(guard.RULES)
    assert f"version {guard.GUARD_RULES_VERSION}" in section


def test_the_deny_reason_is_documented(tmp_path: Path) -> None:
    """The exact reason the guard prints is quoted in the docs, so the
    message a user reads and the one the model gets stay the same."""
    reason = _reason(_guard(sx.build(tmp_path), "printenv"))
    section = _docs_section()
    # The reason's fixed opening and its standing warning, both value-free.
    assert "Weir blocked this command before it ran" in section
    assert "is not a security boundary" in reason and "is not a security boundary" in section


# --- setup and undo (like the redaction hook's) ------------------------------------------

GUARD_QUESTION = "Add the command guard too?"
_OWN = {"statusLine": {"type": "command", "command": "echo mine"},
        "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [
            {"type": "command", "command": "echo edited"}]}]}}


def _setup(claude: sx.Claude, *flags: str, answer: str | None = None) -> sx.Run:
    args = ["statusline", "setup", *claude.inputs(), "--cache", str(claude.state),
            "--claude-dir", str(claude.config), *flags]
    return claude.invoke(args, stdin=answer)


def _guard_entries(claude: sx.Claude) -> list[object]:
    settings = json.loads(claude.settings.read_text())
    return [g for g in settings.get("hooks", {}).get("PreToolUse", [])
            if " -m weir statusline guard " in json.dumps(g)]


@sx.posix_shell
@pytest.mark.parametrize("answer", ["yes\nno\nno\n", "yes\nno\ny\n", "yes\nno\n yes\n"])
def test_setup_adds_the_guard_only_on_an_exact_third_yes(tmp_path: Path, answer: str) -> None:
    claude = sx.build(tmp_path)
    run = _setup(claude, answer=answer)
    assert run.exit_code == 0, run.stderr
    assert "hooks" not in json.loads(claude.settings.read_text())


@sx.posix_shell
def test_setup_shows_the_guard_and_adds_it_on_yes(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    dry = _setup(claude, "--dry-run")
    assert not claude.settings.exists()

    run = _setup(claude, answer="yes\nno\nyes\n")  # apply, no hook, yes guard

    assert run.exit_code == 0, run.stderr
    (entry,) = _guard_entries(claude)
    command = entry["hooks"][0]["command"]  # type: ignore[index,call-overload]
    assert entry == {"matcher": "Bash", "hooks": [
        {"type": "command", "command": command, "timeout": guard.GUARD_TIMEOUT_S}]}
    # The guard reads the inventory only: no store, key, cache or markers.
    assert "--inventory" in command
    for absent in ("--store", "--key", "--markers", "--cache"):
        assert absent not in command, absent
    for shown in (command, "matcher Bash", "PreToolUse", GUARD_QUESTION):
        assert shown in dry.stdout, shown
    assert f'added only when you also answer yes to "{GUARD_QUESTION}"' in dry.stdout

    # Claude Code runs the guard command in a shell, the input on stdin.
    shell = sx.run_shell(command, _stdin("printenv", claude.project()), claude.env())
    assert shell.exit_code == 0, shell.stderr
    out = json.loads(shell.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


@sx.posix_shell
@pytest.mark.parametrize("before", [None, b'{"model": "fake-model"}', json.dumps(_OWN).encode()])
def test_setup_with_the_guard_then_undo_leaves_settings_as_they_were(
    tmp_path: Path, before: bytes | None
) -> None:
    claude = sx.build(tmp_path)
    if before is not None:
        claude.settings.parent.mkdir(parents=True, exist_ok=True)
        claude.settings.write_bytes(before)
    assert _setup(claude, answer="yes\nno\nyes\n").exit_code == 0
    assert len(_guard_entries(claude)) == 1
    assert "command guard" in claude.invoke(["statusline", "undo", "--dry-run"]).stdout

    run = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert run.exit_code == 0, run.stderr
    assert (claude.settings.read_bytes() if claude.settings.exists() else None) == before


@sx.posix_shell
def test_setup_adds_both_the_hook_and_the_guard_and_undo_removes_both(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    before = b'{"model": "fake-model"}'
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)

    assert _setup(claude, answer="yes\nyes\nyes\n").exit_code == 0

    settings = json.loads(claude.settings.read_text())
    assert len(settings["hooks"]["PostToolUse"]) == 1
    assert len(settings["hooks"]["PreToolUse"]) == 1
    command = _guard_entries(claude)[0]["hooks"][0]["command"]  # type: ignore[index,call-overload]
    shell = sx.run_shell(command, _stdin("gh auth token", claude.project()), claude.env())
    assert json.loads(shell.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    assert claude.invoke(["statusline", "undo"], stdin="yes\n").exit_code == 0
    assert claude.settings.read_bytes() == before


@sx.posix_shell
@pytest.mark.parametrize("before", [b'{"hooks": []}', b'{"hooks": {"PreToolUse": {}}}'])
def test_malformed_hooks_refuse_the_guard_and_still_set_up(tmp_path: Path, before: bytes) -> None:
    claude = sx.build(tmp_path)
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)

    dry = _setup(claude, "--dry-run")
    refused = _setup(claude, answer="yes\nno\nyes\n")  # ask for the guard it cannot add

    assert "command guard: cannot be added" in dry.stdout
    assert f'answer no to "{GUARD_QUESTION}"' in dry.stdout
    assert refused.exit_code == 2 and claude.settings.read_bytes() == before
    assert "nothing changed" in refused.stderr
    # Without the guard it still sets up the status line, and undoes.
    assert _setup(claude, answer="yes\nno\nno\n").exit_code == 0
    assert claude.invoke(["statusline", "undo"], stdin="yes\n").exit_code == 0
    assert claude.settings.read_bytes() == before


@sx.posix_shell
def test_undo_leaves_a_weir_guard_the_settings_held_before_setup(tmp_path: Path) -> None:
    claude = sx.build(tmp_path)
    command = f"{sys.executable} -m weir statusline guard --inventory {claude.setup.report}"
    before = json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": command}]}]}}).encode()
    claude.settings.parent.mkdir(parents=True, exist_ok=True)
    claude.settings.write_bytes(before)
    assert "command guard: cannot be added" in _setup(claude, "--dry-run").stdout
    assert _setup(claude, answer="yes\nno\nno\n").exit_code == 0

    undo = claude.invoke(["statusline", "undo"], stdin="yes\n")

    assert undo.exit_code == 0, undo.stderr
    assert claude.settings.read_bytes() == before
