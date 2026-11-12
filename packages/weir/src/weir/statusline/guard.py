"""The command guard (docs/statusline.md, "The command guard").

A Claude Code `PreToolUse` hook for the Bash tool: it lexes
`tool_input.command` into simple commands and denies the call when one
matches a fixed, versioned rule list of command shapes that print a
credential (an environment dump, a read of a credential file, a CLI that
hands back a stored token). The deny reason names no value, path or part of
the command. It is an accident catcher, not a security boundary, and fails
open: an input or inventory it cannot use leaves the call to run. It reads
the inventory report for names and places only, no store, key or value.
"""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path
from typing import NamedTuple, cast

import msgspec

from weir.inventory._types import Inventory, LocationKind, Source

# Bumped when the matched shapes or a rule id change; docs/statusline.md names
# this version and drift-tests its rule table against RULES.
GUARD_RULES_VERSION = 1
GUARD_TIMEOUT_S = 10
GUARD_NOT_CHECKED = "the command was not checked by the weir guard"
_MAX_DEPTH = 40  # how deep lexing descends (sub-shells, sh -c, eval)

# The deny reason, with the shape it would print (WHAT) and the rule's id put
# in. It quotes no command, name, path or value.
DENY_REASON = (
    "Weir blocked this command before it ran: it would print {what}, which would put a"
    " credential into this session. Do not run it in another form. Where a command needs a"
    ' credential, refer to it by name (such as "$API_TOKEN") without printing it; where the'
    " user needs to see it, ask them to run the command themselves. (weir guard {rule}; it"
    " catches common commands only and is not a security boundary.)"
)

# The WHAT each rule family puts in the reason.
_ENV = "the environment"
_VARS = "the shell's variables"
_PROC = "a process's environment"
_PS = "processes' environments"
_VARIABLE = "a variable that holds a credential"
_FILE = "a file that holds a credential"
_TOKEN = "a stored credential or token"


class Deny(NamedTuple):
    rule: str
    what: str


class GuardError(Exception):
    """The guard could not finish its check, so it blocks nothing; the
    message is one of a fixed set and holds no value."""


class Word(NamedTuple):
    """`text` is the unquoted literal, with `~`/`$HOME` expanded and every
    other expansion a NUL (so an unresolved path matches no real one).
    `expands` names the variables it expands for their value outside single
    quotes (not `${#NAME}`), or a command substitution in it echoes: what
    makes `echo "$TOKEN"` a print."""

    text: str
    expands: frozenset[str]


class Simple(NamedTuple):
    """A simple command: program basename, the words after it, `<` targets,
    whether its stdout is kept from the agent (a file, or captured by a
    command substitution), and the program its stdout is piped into (None
    when it is not piped)."""

    prog: str
    args: list[Word]
    redirs: list[Word]
    hidden: bool = False
    pipe: str | None = None


class Cli(NamedTuple):
    """A CLI that hands back a stored token. `prog`: basenames (fnmatch) that
    may match. `seq`: words that must appear consecutively after the program,
    each a set of alternatives. `flags`: any one must be present. `opt`/
    `opt_vals`: an option whose value must be (or begin) one of a set. `tail`:
    substrings the first operand after `seq` must contain."""

    id: str
    prog: tuple[str, ...]
    seq: tuple[tuple[str, ...], ...]
    flags: frozenset[str] = frozenset()
    opt: tuple[str, ...] = ()
    opt_vals: tuple[str, ...] = ()
    tail: tuple[str, ...] = ()


_CLI: tuple[Cli, ...] = (
    Cli("gh-auth-token", ("gh",), (("auth",), ("token",))),
    Cli("gh-auth-show-token", ("gh",), (("auth",), ("status",)),
        flags=frozenset({"-t", "--show-token"})),
    Cli("git-credential-fill", ("git",), (("credential",), ("fill",))),
    Cli("git-credential-helper", ("git",), (("credential-*",), ("get",))),
    Cli("docker-credential-get", ("docker-credential-*",), (("get",),)),
    Cli("gcloud-print-token", ("gcloud",),
        (("print-access-token", "print-identity-token"),)),
    Cli("gcloud-secrets-access", ("gcloud",), (("secrets",), ("versions",), ("access",))),
    Cli("az-account-get-token", ("az",), (("account",), ("get-access-token",))),
    Cli("az-keyvault-secret-show", ("az",), (("keyvault",), ("secret",), ("show",))),
    Cli("aws-configure-get", ("aws",), (("configure",), ("get",)), tail=("secret", "token")),
    Cli("aws-configure-export-credentials", ("aws",), (("configure",), ("export-credentials",))),
    Cli("aws-ecr-login-password", ("aws",), (("ecr", "ecr-public"), ("get-login-password",))),
    Cli("aws-codeartifact-token", ("aws",), (("codeartifact",), ("get-authorization-token",))),
    Cli("aws-secretsmanager-get", ("aws",), (("secretsmanager",), ("get-secret-value",))),
    Cli("aws-ssm-get-parameter", ("aws",), (("ssm",), ("get-parameter", "get-parameters")),
        flags=frozenset({"--with-decryption"})),
    Cli("kubectl-config-view-raw", ("kubectl",), (("config",), ("view",)),
        flags=frozenset({"--raw"})),
    Cli("kubectl-get-secret", ("kubectl",), (("get",), ("secret", "secrets")),
        opt=("-o", "--output"), opt_vals=("yaml", "json", "jsonpath", "go-template")),
    Cli("security-find-password", ("security",),
        (("find-generic-password", "find-internet-password"),),
        flags=frozenset({"-w", "-g"})),
    Cli("op-read", ("op",), (("read",),)),
    Cli("op-item-get-reveal", ("op",), (("item",), ("get",)), flags=frozenset({"--reveal"})),
    Cli("vault-print-token", ("vault",), (("print",), ("token",))),
    Cli("vault-kv-get", ("vault",), (("kv",), ("get",))),
    Cli("sops-decrypt", ("sops",), (), flags=frozenset({"-d", "--decrypt", "decrypt"})),
    Cli("ansible-vault-view", ("ansible-vault",), (("view", "decrypt"),)),
    Cli("heroku-auth-token", ("heroku",), (("auth:token",),)),
    Cli("fly-auth-token", ("fly", "flyctl"), (("auth",), ("token",))),
    Cli("secret-tool-lookup", ("secret-tool",), (("lookup",),)),
    Cli("pass-show", ("pass",), (("show",),)),
    Cli("doppler-secrets-get", ("doppler",), (("secrets",), ("get", "download"))),
)

# Every rule id and its WHAT, in the order docs/statusline.md lists them: the
# six shape rules, then the CLI token rules. The drift test reads the table
# from the docs and compares it to this.
RULES: tuple[tuple[str, str], ...] = (
    ("env-dump", _ENV),
    ("shell-vars", _VARS),
    ("proc-environ", _PROC),
    ("ps-environ", _PS),
    ("credential-variable", _VARIABLE),
    ("credential-file", _FILE),
    *((c.id, _TOKEN) for c in _CLI),
)

# Programs whose output is a file's contents: an operand of one that names a
# credential file is a read of it.
_READERS = frozenset({
    "cat", "tac", "head", "tail", "less", "more", "bat", "nl", "strings", "od", "xxd",
    "hexdump", "base64", "sed", "awk", "cut", "sort", "uniq", "grep", "egrep", "fgrep",
    "rg", "jq", "yq",
})

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# Shell reserved words that can come before a command at its start.
_RESERVED = frozenset({"if", "then", "elif", "else", "do", "while", "until", "!"})
# `ps` long options that consume the next word as a value, and the option
# letters that do when they end a UNIX (`-eo`) or a BSD (`axo`) cluster.
_PS_VAL = frozenset({
    "--cols", "--columns", "--format", "--Group", "--group", "--lines", "--pid", "--ppid",
    "--quick-pid", "--rows", "--sid", "--sort", "--tty", "--User", "--user", "--width",
})
_PS_UNIX_VAL = "CGgOopqstUu"
_PS_BSD_VAL = "OoptUk"
# Options these wrappers take that consume the next word as a value.
_SUDO_VAL = frozenset({
    "-u", "--user", "-g", "--group", "-C", "-p", "--prompt", "-h", "--host", "-U", "-r",
    "--role", "-t", "--type", "-D", "--chdir",
})


# --- lexing ------------------------------------------------------------------


def _base(text: str) -> str:
    """A program word's basename, forward slashes (a command runs in a POSIX
    shell), `/usr/bin/env` as `env`."""
    return text.rsplit("/", 1)[-1]


def _is_assignment(text: str) -> bool:
    """A leading `NAME=...`: an environment assignment before the command."""
    name, sep, _ = text.partition("=")
    return bool(sep) and name.isidentifier()


def _prefix(words: list[Word]) -> int:
    """How many leading words are reserved words (`if`, `do`, `!`, ...) or a
    function header (`NAME()`, `function NAME`): words before the command at
    a command's start, not its program."""
    i = 0
    while i < len(words):
        t = words[i].text
        if t == "function":
            i += 2
        elif t in _RESERVED or (len(t) > 2 and t.endswith("()")):
            i += 1
        else:
            break
    return min(i, len(words))


def _to_file(text: str) -> bool:
    """A `>` target that is a file, not a terminal or a stream (`/dev/stderr`,
    `/dev/tty`, `/proc/self/fd/1`)."""
    return text == "/dev/null" or not text.startswith(("/dev/", "/proc/"))


class _Raw:
    """A simple command as lexed: its words, its `<` targets, whether its
    stdout is captured by a command substitution or sent to a file
    (`hidden`) and whether it is sent to a stream the agent sees (`stream`:
    `/dev/stderr`, `/dev/tty`, `>&2`), the command its stdout is piped into,
    and the names whose values a pipe feeds it."""

    __slots__ = ("hidden", "into", "redirs", "stdin", "stream", "words")

    def __init__(self) -> None:
        self.words: list[Word] = []
        self.redirs: list[Word] = []
        self.hidden = False
        self.stream = False
        self.into: _Raw | None = None
        self.stdin: frozenset[str] = frozenset()

    def blank(self) -> bool:
        return not (self.words or self.redirs)

    def kept(self) -> bool:
        """Whether its stdout is kept from the agent: captured or sent to a
        file, and neither it nor a `tee` operand sent to a stream."""
        if not self.hidden or self.stream:
            return False
        words = _peel(self.words)
        return not (words and _base(words[0].text) == "tee" and any(
            not _to_file(w.text) for w in words[1:] if not w.text.startswith("-")))

    def carries(self) -> frozenset[str]:
        """The names whose values its stdout may hold: those an `echo`/
        `printf` expands, and those piped into a reader or `tee`."""
        words = _peel(self.words)
        prog = _base(words[0].text) if words else ""
        if prog in ("echo", "printf"):
            return frozenset[str]().union(*(w.expands for w in words[1:]))
        return self.stdin if prog in _READERS or prog == "tee" else frozenset()


class _Scan:
    """Lexes one command string into simple commands, skipping heredoc bodies.
    A command or process substitution, a sub-shell or a `{ }` group is lexed
    by a nested scan of the same string from its opener, which stops at its
    own closer; backticks are lexed as a string of their own. `closer` is the
    character that ends this scan ("" at the top)."""

    def __init__(self, text: str, out: list[_Raw], home: str, depth: int,
                 closer: str = "", start: int = 0) -> None:
        self.s = text
        self.i = start
        self.n = len(text)
        self.out = out
        self.home = home
        self.depth = depth
        self.closer = closer
        self.cmd = _Raw()
        self.piped: _Raw | None = None  # the command whose stdout feeds the next one
        self.heredocs: list[tuple[str, bool]] = []
        # "in" (a < target), "file"/"stream" (a stdout target), "out" (ignored), ""
        self.expect = ""
        self.end = -1  # where the last word of the command ended
        self.last: _Raw | None = None  # the last command this scan ended

    def _captured(self) -> frozenset[str]:
        """This scan as a command substitution: its last command's stdout is
        captured into the enclosing word, not shown. The names whose values
        it may carry there."""
        last = self.last
        if last is None:
            return frozenset()
        last.hidden = True
        return last.carries()

    def run(self) -> None:
        while self.i < self.n:
            c = self.s[self.i]
            if self._closes(c):
                break
            if c in " \t":
                self.i += 1
            elif c == "\n":
                self._newline()
            elif c == "#" and self.cmd.blank():
                nl = self.s.find("\n", self.i)
                self.i = self.n if nl == -1 else nl
            elif c in ";&|":
                self._separator()
            elif c in "({" and self._opens(c):
                self.piped = None
                self._sub(")" if c == "(" else "}")
            elif c == "<":
                self.expect = self._redir_in()
            elif c == ">":
                self.expect = self._redir_out()
            else:
                self._place(self._word())
        self._flush(pipe=False)

    def _closes(self, c: str) -> bool:
        """Whether `c` ends this scan: a `)` anywhere, a `}` at a command's start."""
        return c == self.closer and (c == ")" or (self.cmd.blank() and not self.expect))

    def _opens(self, c: str) -> bool:
        """Whether a `(` or `{` at the index opens a group: at a command's
        start (after any reserved words), a `{` only as a word of its own."""
        if _prefix(self.cmd.words) < len(self.cmd.words):
            return False
        return c == "(" or self.s[self.i + 1:self.i + 2] in (" ", "\t", "\n", "")

    def _sub(self, closer: str) -> _Scan:
        """Lex the group or substitution whose opener is at the index, leaving
        the index past its closer; the nested scan. Past the depth bound
        nothing more is lexed."""
        child = _Scan(self.s, self.out, self.home, self.depth + 1, closer, self.i + 1)
        if self.depth >= _MAX_DEPTH:
            self.i = self.n
            return child
        child.run()
        self.i = child.i + 1
        return child

    def _place(self, word: Word) -> None:
        if self.expect == "in":
            self.cmd.redirs.append(word)
        elif self.expect in ("file", "stream"):
            if self.expect == "file" and _to_file(word.text):
                self.cmd.hidden = True
            else:
                self.cmd.stream = True
        elif self.expect == "":
            self.cmd.words.append(word)
            self.end = self.i
        self.expect = ""

    def _flush(self, pipe: bool) -> None:
        """End the simple command being lexed; `pipe`: its stdout feeds the
        next one. A blank one (a newline after `|`) keeps a pipe open."""
        self.expect = ""
        cmd = self.cmd
        if cmd.blank():
            self.cmd = _Raw()
            return
        self.out.append(cmd)
        self.last = cmd
        if self.piped is not None:
            self.piped.into = cmd
            cmd.stdin = self.piped.carries()
        self.piped = cmd if pipe else None
        self.cmd = _Raw()

    def _newline(self) -> None:
        self._flush(pipe=False)
        self.i += 1
        for delim, strip in self.heredocs:
            self._skip_heredoc(delim, strip)
        self.heredocs.clear()

    def _separator(self) -> None:
        """`;`, `&`, `|` and their pairs end a command; `&>` and `&>>` are a
        stdout target of the command being lexed."""
        two = self.s[self.i:self.i + 2]
        if two == "&>":
            self.i += 1
            self.expect = self._redir_out()
            return
        self._flush(pipe=two[0] == "|" and two != "||")
        self.i += 2 if two in ("&&", "||", "|&") else 1

    def _fd(self) -> str:
        """The fd number written against the redirect at the index (`2>`),
        taken off the words; "" when there is none."""
        words = self.cmd.words
        if words and self.end == self.i and words[-1].text.isdecimal():
            return words.pop().text
        return ""

    def _proc_sub(self) -> None:
        """A process substitution `<(...)`/`>(...)`: lexed, and a word."""
        self.i += 1
        self._sub(")")
        self.cmd.words.append(Word("\0", frozenset()))

    def _redir_in(self) -> str:
        if self.s[self.i + 1:self.i + 2] == "(":
            self._proc_sub()
            return ""
        self._fd()
        if self.s[self.i:self.i + 3] == "<<<":  # a here-string: data, not a file
            self.i += 3
            return "out"
        if self.s[self.i:self.i + 2] == "<<":  # a heredoc: skip its body
            strip = self.s[self.i:self.i + 3] == "<<-"
            self.i += 3 if strip else 2
            while self.i < self.n and self.s[self.i] in " \t":
                self.i += 1
            self.heredocs.append((self._word().text, strip))
            return ""
        self.i += 1
        return "in"

    def _redir_out(self) -> str:
        """`>`, `>>` or `>|` of stdout is a "file" target, and a `>&`
        duplicate of it a "stream"; another fd's target is ignored."""
        if self.s[self.i + 1:self.i + 2] == "(":
            self._proc_sub()
            return ""
        fd = self._fd()
        op = self.s[self.i:self.i + 2]
        self.i += 2 if op in (">>", ">&", ">|") else 1
        if fd not in ("", "1"):
            return "out"
        return "stream" if op == ">&" else "file"

    def _skip_arith(self) -> None:
        """Step past an arithmetic `((...))` whose first `(` is at the index.
        Quotes and backslashes inside are stepped over."""
        self.i += 1
        depth = 1
        while self.i < self.n and depth:
            c = self.s[self.i]
            if c == "'":
                self.i += 1
                while self.i < self.n and self.s[self.i] != "'":
                    self.i += 1
                self.i += 1
            elif c == '"':
                self.i += 1
                while self.i < self.n and self.s[self.i] != '"':
                    self.i += 2 if self.s[self.i] == "\\" else 1
                self.i += 1
            elif c == "\\":
                self.i += 2
            else:
                depth += (c == "(") - (c == ")")
                self.i += 1

    def _skip_heredoc(self, delim: str, strip: bool) -> None:
        while self.i < self.n:
            nl = self.s.find("\n", self.i)
            line = self.s[self.i:self.n if nl == -1 else nl]
            self.i = self.n if nl == -1 else nl + 1
            if (line.lstrip("\t") if strip else line) == delim:
                return

    def _word(self) -> Word:
        parts: list[str] = []
        expands: set[str] = set()
        while self.i < self.n:
            c = self.s[self.i]
            # a stray ( or ) outside a `(...)` scan becomes a literal, so a word always advances
            if c in " \t\n;&|<>" or c == self.closer == ")":
                break
            if c == "'":
                self._single(parts)
            elif c == '"':
                self._double(parts, expands)
            elif c == "`":
                expands |= self._backtick()
                parts.append("\0")
            elif c == "$":
                self._dollar(parts, expands)
            elif c == "\\":
                self.i += 1
                if self.i < self.n:
                    parts.append(self.s[self.i])
                    self.i += 1
            elif c == "~" and not parts and self.s[self.i + 1:self.i + 2] in ("", "/", " ", "\t"):
                parts.append(self.home)
                self.i += 1
            else:
                parts.append(c)
                self.i += 1
        return Word("".join(parts), frozenset(expands))

    def _single(self, parts: list[str]) -> None:
        self.i += 1
        start = self.i
        while self.i < self.n and self.s[self.i] != "'":
            self.i += 1
        parts.append(self.s[start:self.i])
        self.i += 1

    def _double(self, parts: list[str], expands: set[str]) -> None:
        self.i += 1
        while self.i < self.n:
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\":
                nx = self.s[self.i + 1:self.i + 2]
                if nx in ('$', '`', '"', '\\'):
                    parts.append(nx)
                    self.i += 2
                elif nx == "\n":
                    self.i += 2
                else:
                    parts.append("\\")
                    self.i += 1
            elif c == "$":
                self._dollar(parts, expands)
            elif c == "`":
                expands |= self._backtick()
                parts.append("\0")
            else:
                parts.append(c)
                self.i += 1

    def _backtick(self) -> frozenset[str]:
        """A backtick substitution, lexed as a string of its own; the names
        its captured output may carry."""
        self.i += 1
        start = self.i
        while self.i < self.n and self.s[self.i] != "`":
            self.i += 2 if self.s[self.i] == "\\" else 1
        inner = self.s[start:self.i]
        self.i += 1
        child = _Scan(inner.replace("\\`", "`").replace("\\$", "$").replace("\\\\", "\\"),
                      self.out, self.home, self.depth + 1)
        if self.depth < _MAX_DEPTH:
            child.run()
        return child._captured()

    def _dollar(self, parts: list[str], expands: set[str]) -> None:
        after = self.s[self.i + 1:self.i + 2]
        if self.s[self.i:self.i + 3] == "$((":  # arithmetic: not a command
            self.i += 1
            self._skip_arith()
            parts.append("\0")
        elif after == "(":  # command substitution
            self.i += 1
            expands |= self._sub(")")._captured()
            parts.append("\0")
        elif after == "{":
            self.i += 2
            start = self.i
            while self.i < self.n and self.s[self.i] != "}":
                self.i += 1
            self._param(self.s[start:self.i], parts, expands)
            self.i += 1
        elif after.isalpha() or after == "_":
            start = self.i + 1
            self.i += 1
            while self.i < self.n and (self.s[self.i].isalnum() or self.s[self.i] == "_"):
                self.i += 1
            self._name(self.s[start:self.i], parts, expands)
        else:
            parts.append("$")
            self.i += 1

    def _param(self, expr: str, parts: list[str], expands: set[str]) -> None:
        """A `${...}` body. `${#NAME}` (length) and `${!NAME}` (indirect) do
        not expand NAME's value; anything else does."""
        if expr[:1] in ("#", "!"):
            parts.append("\0")
            return
        name = expr
        for i, ch in enumerate(expr):
            if not (ch.isalnum() or ch == "_"):
                name = expr[:i]
                break
        self._name(name, parts, expands, modified=name != expr)

    def _name(self, name: str, parts: list[str], expands: set[str],
              modified: bool = False) -> None:
        if name == "HOME" and not modified:
            parts.append(self.home)
        else:
            if name.isidentifier():
                expands.add(name)
            parts.append("\0")


def _commands(text: str, home: str, depth: int = 0) -> list[Simple]:
    """Every simple command in `text`, each normalized: leading assignments
    and reserved words dropped, wrappers peeled, `env`/`sh -c`/`eval`
    resolved to the command they run."""
    raw: list[_Raw] = []
    _Scan(text, raw, home, depth).run()
    out: list[Simple] = []
    for r in raw:
        hidden = r.kept() or (r.into is not None and r.into.kept())
        out.extend(_normalize(r.words, r.redirs, home, depth, hidden,
                              _consumer(r, home, depth)))
    return out


def _consumer(r: _Raw, home: str, depth: int) -> str | None:
    """The program `r`'s stdout is piped into, or None when it is piped into
    no command."""
    if r.into is None:
        return None
    inner = _normalize(r.into.words, r.into.redirs, home, depth)
    return inner[0].prog if inner else None


def _skip_opts(args: list[Word], val_opts: frozenset[str]) -> int:
    """How many leading option words to drop: each `-x`, and the value after
    one in `val_opts`; `--` ends the options."""
    i = 0
    while i < len(args):
        t = args[i].text
        if t == "--":
            return i + 1
        if not t.startswith("-") or t == "-":
            break
        i += 2 if t in val_opts else 1
    return i


def _peel(words: list[Word]) -> list[Word]:
    """Strip leading assignments, reserved words (`if`, `do`, `!`, ...), function
    headers and wrappers (`sudo`, `nohup`, `timeout DUR`, ...) to reveal the program
    actually run. `command -v`, a query not a run, is left."""
    while words:
        text = words[0].text
        prog = _base(text)
        rest = words[1:]
        k = _prefix(words)
        if k or _is_assignment(text) or prog in ("builtin", "exec", "nohup", "noglob"):
            words = words[max(k, 1):]
        elif prog == "command":
            if rest and rest[0].text in ("-v", "-V"):
                break
            words = rest[_skip_opts(rest, frozenset()):]
        elif prog == "time":
            words = rest[_skip_opts(rest, frozenset()):]
        elif prog == "nice":
            words = rest[_skip_opts(rest, frozenset({"-n"})):]
        elif prog == "timeout":
            words = rest[_skip_opts(rest, frozenset({"-s", "--signal", "-k", "--kill-after"})) + 1:]
        elif prog == "stdbuf":
            words = rest[_skip_opts(
                rest, frozenset({"-i", "-o", "-e", "--input", "--output", "--error"})):]
        elif prog == "sudo":
            words = rest[_skip_opts(rest, _SUDO_VAL):]
        else:
            break
    return words


def _dash_c(args: list[Word]) -> str | None:
    """The code string of a `-c` option (`-c STR`, or combined `-lc STR`), or
    None when there is none."""
    for i, w in enumerate(args):
        t = w.text
        combined = (t.startswith("-") and not t.startswith("--") and t.endswith("c")
                    and t[1:].isalpha())
        if t == "-c" or combined:
            return args[i + 1].text if i + 1 < len(args) else ""
    return None


def _env(words: list[Word], redirs: list[Word], home: str, depth: int, hidden: bool,
         pipe: str | None) -> list[Simple]:
    """`env ...` resolved: its options and assignments dropped, `-S STR` run
    as a command, an inner command peeled again, and `env` with no command at
    all left as an environment dump."""
    rest = words[1:]
    j = 0
    while j < len(rest):
        t = rest[j].text
        if t in ("-i", "--ignore-environment", "-0", "--null", "-v"):
            j += 1
        elif t in ("-u", "--unset", "-C", "--chdir"):
            j += 2
        elif t.startswith(("--unset=", "--chdir=")):
            j += 1
        elif t in ("-S", "--split-string"):
            return _commands(rest[j + 1].text, home, depth + 1) if j + 1 < len(rest) else []
        elif t.startswith("--split-string="):
            return _commands(t.split("=", 1)[1], home, depth + 1)
        elif t.startswith("-S") and len(t) > 2:
            return _commands(t[2:], home, depth + 1)
        elif _is_assignment(t):
            j += 1
        else:
            break
    inner = rest[j:]
    if not inner:
        return [Simple("env", [], redirs, hidden, pipe)]
    return _normalize(inner, redirs, home, depth, hidden, pipe)


def _normalize(words: list[Word], redirs: list[Word], home: str, depth: int,
               hidden: bool = False, pipe: str | None = None) -> list[Simple]:
    """One lexed simple command as the commands it runs. `hidden`/`pipe`,
    where its stdout goes, carry to the command itself, not to one that
    `sh -c`, `eval` or `env -S` runs."""
    words = _peel(words)
    if not words:
        return []
    prog = _base(words[0].text)
    if prog == "env":
        return _env(words, redirs, home, depth, hidden, pipe)
    if prog in _SHELLS:
        code = _dash_c(words[1:])
        if code is not None:
            return _commands(code, home, depth + 1)
    if prog == "eval":
        return _commands(" ".join(w.text for w in words[1:]), home, depth + 1)
    return [Simple(prog, words[1:], redirs, hidden, pipe)]


# --- the rules ---------------------------------------------------------------

def _is_proc_environ(text: str) -> bool:
    """`/proc/<id>/[task/<id>/]environ`, an id any one segment (`self`, a
    number, `$$`, an expansion, a glob)."""
    parts = text.split("/")
    if len(parts) < 4 or parts[0] or parts[1] != "proc" or parts[-1] != "environ":
        return False
    if not parts[2]:
        return False
    middle = parts[3:-1]
    return middle == [] or (len(middle) == 2 and middle[0] == "task" and bool(middle[1]))


def _ps_environ(args: list[Word]) -> bool:
    """`ps` args holding a dashless letters-only option cluster with `e` (the
    BSD environment option); an option's value is not a cluster."""
    value = False
    for w in args:
        t = w.text
        if value:
            value = False
        elif t.startswith("-"):
            value = t in _PS_VAL or (t[1:].isalpha() and t[-1] in _PS_UNIX_VAL)
        elif t.isalpha():
            if "e" in t:
                return True
            value = t[-1] in _PS_BSD_VAL
    return False


def _positional(args: list[Word]) -> list[Word]:
    """The words that are neither an option nor an assignment."""
    return [w for w in args if not w.text.startswith("-") and not _is_assignment(w.text)]


def _fixed_rule(sc: Simple) -> Deny | None:
    """The rules that need no inventory."""
    for w in [Word(sc.prog, frozenset()), *sc.args, *sc.redirs]:
        if _is_proc_environ(w.text):
            return Deny("proc-environ", _PROC)
    if sc.prog == "ps" and _ps_environ(sc.args):
        return Deny("ps-environ", _PS)
    if sc.prog in ("env", "printenv") and not _positional(sc.args):
        return Deny("env-dump", _ENV)
    if sc.prog == "set" and not sc.args:
        return Deny("shell-vars", _VARS)
    if sc.prog in ("export", "declare", "typeset", "readonly"):
        # A whole dump: options only (`export -p`, `declare`), never a name or
        # an assignment (`export FOO`, `export FOO=bar`), and not `-f`/`-F`
        # which list functions, not variables.
        if all(w.text.startswith("-") for w in sc.args) and not any(
            w.text in ("-f", "-F") for w in sc.args
        ):
            return Deny("shell-vars", _VARS)
    hit = _cli_hit(sc)
    return Deny(hit, _TOKEN) if hit is not None else None


def _match(word: str, alts: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(word, a) for a in alts)


def _subseq(args: list[str], seq: tuple[tuple[str, ...], ...]) -> int:
    """The index just past `seq` where it appears as consecutive words, or -1.
    An empty `seq` is at 0."""
    if not seq:
        return 0
    for i in range(len(args) - len(seq) + 1):
        if all(_match(args[i + k], seq[k]) for k in range(len(seq))):
            return i + len(seq)
    return -1


def _opt_value(args: list[str], opt: tuple[str, ...], vals: tuple[str, ...]) -> bool:
    for i, a in enumerate(args):
        value: str | None = None
        if a in opt:
            value = args[i + 1] if i + 1 < len(args) else None
        else:
            for name in opt:
                if a.startswith(name + "="):
                    value = a[len(name) + 1:]
                elif name == "-o" and a.startswith("-o") and len(a) > 2 and a[2] != "=":
                    value = a[2:]
        if value is not None and any(value == v or value.startswith(v + "=") for v in vals):
            return True
    return False


def _cli_hit(sc: Simple) -> str | None:
    args = [w.text for w in sc.args]
    for rule in _CLI:
        if not _match(sc.prog, rule.prog):
            continue
        after = _subseq(args, rule.seq)
        if after < 0:
            continue
        if rule.flags and not (set(args) & rule.flags):
            continue
        if rule.opt and not _opt_value(args, rule.opt, rule.opt_vals):
            continue
        if rule.tail:
            operand = next((a for a in args[after:] if not a.startswith("-")), "")
            if not any(sub in operand.lower() for sub in rule.tail):
                continue
        return rule.id
    return None


def _posix(path: str) -> str:
    """Forward-slash form, so a path matches the same on every OS: the
    inventory stores forward slashes, while os.path uses `\\` on Windows (and
    Claude Code normalises paths to POSIX form before matching too)."""
    return path.replace("\\", "/")


def _resolve(text: str, cwd: str | None) -> str | None:
    """A path word resolved: NUL (an unresolved expansion) is skipped,
    relative paths join `cwd`, and the result is realpath'd, forward slashes."""
    if not text or "\0" in text:
        return None
    if not os.path.isabs(text):
        if cwd is None or not os.path.isabs(cwd):
            return None
        text = os.path.join(cwd, text)
    return _posix(os.path.realpath(text))


def _glob_hit(pattern: str, cwd: str | None, files: frozenset[str]) -> bool:
    """A glob operand matched per path segment against a credential file,
    `*` never matching a leading dot."""
    if not os.path.isabs(pattern):
        if cwd is None or not os.path.isabs(cwd):
            return False
        pattern = os.path.join(cwd, pattern)
    pat = _posix(pattern).split("/")
    for path in files:
        seg = _posix(path).split("/")
        # Each segment: the glob matches it and, unless the glob starts with a
        # dot, the segment does not (the shell hidden-file rule).
        if len(seg) == len(pat) and all(
            (p.startswith(".") or not s.startswith(".")) and fnmatch.fnmatchcase(s, p)
            for p, s in zip(pat, seg, strict=True)
        ):
            return True
    return False


def _file_hit(sc: Simple, cwd: str | None, files: frozenset[str],
              resolved: frozenset[str]) -> bool:
    operands = sc.redirs.copy()
    if sc.prog in _READERS:
        operands += _positional(sc.args)
    for w in operands:
        if any(ch in w.text for ch in "*?[") and "\0" not in w.text:
            if _glob_hit(w.text, cwd, files):
                return True
        else:
            path = _resolve(w.text, cwd)
            if path is not None and path in resolved:
                return True
    return False


def _variable_hit(sc: Simple, names: frozenset[str]) -> bool:
    if sc.prog in ("echo", "printf"):
        shown = not sc.hidden and (sc.pipe is None or sc.pipe in _READERS or sc.pipe == "tee")
        return shown and any(w.expands & names for w in sc.args)
    if sc.prog == "printenv":
        return any(w.text in names for w in _positional(sc.args))
    if sc.prog in ("declare", "typeset") and any(w.text == "-p" for w in sc.args):
        return any(w.text in names for w in _positional(sc.args))
    return False


class _Inventory(NamedTuple):
    names: frozenset[str]  # variable names the inventory holds a credential for
    files: frozenset[str]  # absolute credential-file paths, forward slashes
    resolved: frozenset[str]  # those paths realpath'd


def _load(report_path: Path) -> _Inventory:
    try:
        report = msgspec.json.decode(report_path.read_bytes(), type=Inventory)
    except (OSError, msgspec.DecodeError, msgspec.ValidationError):
        raise GuardError("its inventory report cannot be read") from None
    names: set[str] = set()
    files: set[str] = set()
    for c in report.credentials:
        if c.source is Source.ENVIRONMENT:
            names.add(c.name)
        if c.location.kind is LocationKind.FILE and c.location.path is not None:
            files.add(c.location.path)
    return _Inventory(
        frozenset(names), frozenset(files),
        frozenset(_posix(os.path.realpath(f)) for f in files),
    )


def decide(stdin: bytes, report_path: Path) -> dict[str, object] | None:
    """The deny object for a Bash call that matches a rule, or None to leave
    it to Claude Code. Raises GuardError when the input or the inventory
    cannot be used, so the caller fails open."""
    try:
        parsed: object = json.loads(stdin)
    except ValueError:
        raise GuardError("its input is not JSON") from None
    if not isinstance(parsed, dict):
        raise GuardError("its input is not a hook input")
    payload = cast("dict[str, object]", parsed)
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    command = cast("dict[str, object]", tool_input).get("command") if isinstance(
        tool_input, dict) else None
    if not isinstance(command, str):
        return None
    raw_cwd = payload.get("cwd")
    cwd = raw_cwd if isinstance(raw_cwd, str) else None
    simples = _commands(command, _posix(os.path.expanduser("~")))
    for sc in simples:
        hit = _fixed_rule(sc)
        if hit is not None:
            return _deny(hit)
    inventory = _load(report_path)
    for sc in simples:
        if _variable_hit(sc, inventory.names):
            return _deny(Deny("credential-variable", _VARIABLE))
        if _file_hit(sc, cwd, inventory.files, inventory.resolved):
            return _deny(Deny("credential-file", _FILE))
    return None


def _deny(deny: Deny) -> dict[str, object]:
    reason = DENY_REASON.format(what=deny.what, rule=deny.rule)
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}
