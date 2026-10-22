# weir audit: the credential audit contract

> **Experimental.** `weir audit` is experimental: its output and JSON schema
> may change without notice.

> **The contract.** `weir audit` (in `packages/weir/src/weir/audit/`)
> implements this document, and this document is what its implementation,
> its tests and every audit fixture are judged against. Where code and this
> text disagree, one of them is a bug.

`weir audit` answers one question about a person's own credentials: did any
of them reach a coding agent? It takes the keyed fingerprints that
[`weir inventory --store`](inventory.md) wrote for the credentials on the
machine, reads saved agent session files or exported telemetry, and
reports, per credential, whether its value **entered the agent's context**
(the agent read it: a tool result, a prompt, an attachment) or was **sent
out in a tool call** (the agent put it in a tool's arguments), with counts
and locations. It never prints a value or any fragment of one.

The audit works from fingerprints alone. It never reads a credential file
and never holds a value it did not find in the files it was given: it takes
candidate strings from those files, fingerprints each one under the
inventory's key, and looks the fingerprint up in the store. A match is
exact, so a hit is the credential itself, not a pattern guess.

It runs offline: it opens no socket, starts no process, reads no clock and
uses no randomness. It reads only the files it is given, and the same input
bytes always give the same output bytes.

## Running it

```sh
weir audit --inventory REPORT --store STORE --key KEY [--json] PATH...
```

| option | meaning |
| --- | --- |
| `--inventory` | **Required.** The `weir-inventory/1` report, as `weir inventory --json` prints it. Names every credential. |
| `--store` | **Required.** The `weir-inventory-store/1` fingerprint store from the same `weir inventory` run (`--store`). |
| `--key` | **Required.** The fingerprint key that run used (`--key`, default `HOME/.weir/fingerprint.key`). The audit never creates a key: a new key would match nothing and read as a clean result. |
| `PATH` | **One or more.** A session file, telemetry file or directory. A directory is read recursively in sorted path order. |
| `--json` | Print the `weir-audit/1` JSON report instead of the text report. |

There is no default for any input, so a run never reads a real home by
accident.

A directory entry that is a symbolic link is not followed and is reported
as not scanned. Every other entry, and every given path, must be a readable
regular file or directory: one that cannot be read in full, or is a FIFO,
socket or device, is exit 2 naming the path, and so is a file reached
through two given paths. A file that starts with the gzip magic bytes is
not scanned.

### The three inventory inputs

- The report and the store must come from one `weir inventory` run: every
  store record's `credential_id` must name a credential in the report whose
  `value_state` is `literal`, and every such credential must have a store
  record. Otherwise the inputs do not match, exit 2.
- The key must be the one the store was written under. The store carries a
  **key check** (`key_check`, the lowercase hex HMAC-SHA256 of the ASCII
  bytes `weir-inventory-store key check` under the key), and a key whose
  check differs is exit 2, as is a store with no key check (one written
  before 0.7.0: run `weir inventory --store` again).
- The key file is 64 hex characters (surrounding whitespace ignored), as
  `weir inventory` writes it. Anything else is exit 2.
- A store record with a `fingerprint_v` other than 1 is exit 2.

An error names the input, never content read from it.

### Credentials the audit can check

A credential is **checkable** when the store holds a fingerprint of its
value: the report's `value_state` is `literal`. Every other credential (a
whole-file credential, a shell expansion, a scanner result the file does
not hold, a value not fully read) is listed as **not checkable**, with its
`value_state`, and is never reported as not found.

## Files and formats

Each file is read in full, and its format is recognised from its bytes and
its path, never guessed from its name alone. The path rules below read the
path made absolute (without following symbolic links), so a relative path
such as `memory/MEMORY.md` is recognised as its absolute path would be; the
report still prints the path as given:

| format | recognised when | read as |
| --- | --- | --- |
| `claude-code` | a JSON Lines file whose parsed lines are JSON objects, at least one with `type` `user` or `assistant` and a string `sessionId`; or, with no such record, a JSON Lines file inside a Claude Code projects directory with at least one record, every record's `type` a bookkeeping type: `summary`, or a type the Claude Code table below makes `stored` at every location (`file-history-snapshot`, say). A Claude Code projects directory is a directory `projects` directly inside a directory named `.claude` (`~/.claude/projects/`), or the `projects` directory of the Claude config directory the environment variable `CLAUDE_CONFIG_DIR` names; any other directory named `projects` is not one. A `user` or `assistant` record without a string `sessionId`, or a record of any other type, makes such a file `unknown` | a Claude Code session file: the main transcript or a subagent's (`<session>/subagents/*.jsonl`), or a file of bookkeeping records beside them |
| `claude-code-tool-results` | a file whose parent directory is named `tool-results` | a large tool output Claude Code saved beside a session (`<session>/tool-results/`): text |
| `claude-code-memory` | a file named `CLAUDE.md`, or a `.md` file in a directory named `memory` two levels below a directory named `projects` (`projects/<project>/memory/*.md`, `MEMORY.md` included) | a file Claude Code loads into the agent's context: a `CLAUDE.md` or an auto-memory file. Text |
| `otlp` | a JSON Lines file whose parsed lines are OTLP/JSON export requests (an object holding `resourceSpans`, `resourceLogs` or `resourceMetrics`), or, when no line is an export request, a whole file that is one such request (pretty-printed, say) | exported telemetry |
| `unknown` | anything else | searched as text, line by line; a line that is a JSON value is walked as one |

The first rule that holds wins. A `claude-code` or `otlp` file's lines are
records: a line that is not a JSON object (truncated, not JSON, an empty
line) is an **unparsed line**, searched as text. In an `otlp` file a JSON
object that is not an export request is an unparsed line too.

### Strings

The audit searches **strings**:

- in a JSON record: every string value and every object key, with its
  **location**, the path to it (`.key` into an object, `[i]` into an
  array), as `weir canary judge` and the exposure scan write it;
- in OTLP: what `weir canary judge`'s structured walk reads
  ([docs/canary.md](canary.md), "The capture"), a `bytesValue` after base64
  decoding included, with the same locations;
- in a text file or an unparsed line: each line, with no location; a line
  that is itself a JSON object or array is walked as one, with locations
  as in a record.

## Matching

### Forms

Each string is searched in every **form**, the inverse of the encoded forms
the canary judge matches ([docs/canary.md](canary.md), "The encoded
forms"). A form gives **decoded texts**, whose candidates (below) are
fingerprinted, or **decoded candidates** directly:

| form | what is fingerprinted |
| --- | --- |
| `raw` | the candidates of the string itself |
| `json` | when the string holds a `\`: the candidates of the string *unescaped*, and, for each JSON string literal in it (a `"` to the next `"` not escaped by a `\`) whose content holds a `\`, the content unescaped as a candidate whole and its candidates. *Unescaped*: each JSON escape (`\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t` `\uXXXX` in either letter case, a surrogate pair as one character) replaced by its character, any other `\` left as it is |
| `json2` | `json` applied to each text `json` unescaped |
| `url` | when the string holds a `%` followed by two hex digits, or a `+`: the candidates of the string *URL-decoded*, and each candidate of the string itself that holds one, URL-decoded, as a candidate whole. *URL-decoded*: every such `%XX` replaced by its byte, in two variants, `+` kept and `+` read as a space, the bytes read as UTF-8 |
| `base64` | the candidates of each run of 8 or more characters of `A-Za-z0-9+/` (and up to two `=` after it), decoded from its first, second, third and fourth character on (a last group of 2 or 3 characters padded, one of 1 dropped), read as UTF-8 |
| `base64url` | the same for each run of 8 or more characters of `A-Za-z0-9_-` that holds a `-` or a `_` |
| `hex` | the candidates of each run of 16 or more hex digits, decoded from its first and from its second digit on, up to the last whole pair, read as UTF-8 |

The JSON string literal rule and the url rule decode a candidate found in
the encoded string, so a value holding a separator (a quote, say) is still
found where its encoding holds none. "Read as UTF-8": a byte that is not
valid UTF-8 becomes an undecodable character, which is a separator (below).
Forms do not compose, except that `json2` is `json` twice, as in the judge.

### Candidates

From a text the audit takes these **candidates**:

1. the whole text, without surrounding whitespace;
2. each line (split at `\n`, `\r\n` or `\r`) without surrounding
   whitespace, and without a line-number prefix (spaces, digits, then `→`
   or a tab), as Claude Code's Read tool writes one;
3. for each line that is an assignment, a `NAME` (a letter or `_`, then
   letters, digits, `_`, `.` or `-`), optional spaces, `=` or `:`, then the
   value, optionally after `export ` and a line-number prefix: the value
   without surrounding whitespace, and without one pair of matching quotes
   around it (so the password of a decoded HTTP Basic `user:password` is
   one);
4. each quoted run in a line: the characters between two `"`, two `'` or
   two backticks;
5. each PEM private key: `-----BEGIN ... PRIVATE KEY-----` through the next
   `-----END ... PRIVATE KEY-----`;
6. each **word**, a maximal run of characters with no whitespace, control
   or undecodable character in it: whole, without the separators (below)
   at its two ends, and without every character other than a word
   character or `-` at its two ends;
7. each **token** and its **sub-spans**. A token is a maximal run of
   characters none of which is a **separator**: whitespace, a control
   character, an undecodable character, or one of ``" ' ` < > ( ) [ ] { } ,
   ; | \``. In a token, every character other than a word character (a
   Unicode letter or digit, or `_`) or `-` is a **break**; the token's two ends and the positions just
   before and just after each break are its **cut points**. A sub-span
   runs from a cut point to any of the 64 cut points after it. A token of
   256 or more characters that are all base64 or all hex characters is a
   candidate only whole.

A candidate is never empty and never longer than 65536 characters.

A candidate is **a credential** when the lowercase hex HMAC-SHA256 of its
UTF-8 bytes (an undecodable character as the byte it stood for) under the
key is a fingerprint in the store. Every store record with that
fingerprint is that credential: several inventory credentials that share a
value (`same_value_as`) all match.

One string gives at most one **hit** per credential: its location, and the
first form in the table above that holds it.

### What a hit means

Every hit has a **kind**:

| kind | meaning |
| --- | --- |
| `context` | the value entered the agent's context: the agent read it |
| `tool_call` | the value was sent out in a tool call: it is in the arguments of a tool the agent called |
| `stored` | the value is stored locally, in the file, but neither entered the agent's context nor was sent out: bookkeeping the agent never reads (a `file-history-snapshot` record, say) |
| `unknown` | the audit cannot tell whether the agent read it |

A `tool_call` value was in the context as well, since the agent wrote it;
the two are counted apart because a value in a tool call has left for
wherever that tool sends it.

#### Claude Code session files

A record's kind is decided by its `type` and the hit's location:

| record `type` | location | kind |
| --- | --- | --- |
| `user` | `message.content` when it is a string | `context` |
| `user` | `message.content[i]` and below, block `type` `text`, `image`, `document` or `tool_result` | `context`; for a `tool_result`, `tool` is the `name` of the `tool_use` with its `tool_use_id` earlier in the same file |
| `assistant` | `message.content` when it is a string | `context` |
| `assistant` | `message.content[i]` and below, block `type` `text`, `thinking` or `redacted_thinking` | `context` |
| `assistant` | `message.content[i].input` and below, block `type` `tool_use` or `server_tool_use` | `tool_call`; `tool` is the block's `name`, `argument` the location below `input` |
| `assistant` | anything else in a `tool_use` or `server_tool_use` block | `context` |
| `attachment` | `rendered` and below | `context` |
| `attachment` | anything else, when the record has `rendered` | `stored` |
| `summary` | `summary` | `context` |
| `user`, `assistant`, `attachment`, `summary` | a `message.content[i]` block of any other `type` | `unknown` |
| `user`, `assistant`, `attachment`, `summary` | anything else | `stored` |
| `queue-operation`, `last-prompt`, `cost-state`, `atis-latch`, `file-history-snapshot`, `custom-title`, `agent-name`, `tag`, `permission-mode`, `pr-link`, `worktree-state` | anything | `stored` |
| any other `type`, or none | anything | `unknown` |

An `attachment` with no `rendered` is `unknown`. A record whose `type` is
not in the table is an **unrecognised record**.

A `claude-code-tool-results` file is `stored`: Claude Code shows the agent
a preview of a large tool output and saves the whole output there, and the
preview's own copy is in the transcript's `tool_result`.

A `claude-code-memory` file is `context`: Claude Code loads `CLAUDE.md` and
its auto-memory files into the agent's context. Each line is a string, with
no location.

#### OTLP telemetry

Kinds follow the OpenTelemetry GenAI semantic conventions, and, in a log
record, the attributes of Claude Code's own log events. For a string in a
span, a span event or a log record, the attribute it sits under decides:

| attribute | in | kind |
| --- | --- | --- |
| `gen_ai.tool.call.arguments` | any record | `tool_call`; `tool` is the record's `gen_ai.tool.name`, `argument` the location below the attribute |
| `gen_ai.tool.call.result` | any record | `context`; `tool` is the record's `gen_ai.tool.name` |
| `gen_ai.input.messages`, `gen_ai.system_instructions` | any record | `context` |
| `gen_ai.output.messages` | any record | `context`, except in a message part whose `type` is `tool_call`: there, below `arguments`, `tool_call`, with `tool` the part's `name` and `argument` the location below `arguments` |
| `tool_parameters` | a log record | `tool_call` (Claude Code's `claude_code.tool_result` event); `tool` is the record's `tool_name`, `argument` the location below the attribute |
| `prompt` | a log record | `context` (Claude Code's `claude_code.user_prompt` event) |
| anything else | | `unknown` |

An attribute's value is read the same way whether it is a string holding a
JSON document or a structured value (an `arrayValue` or `kvlistValue`): a
string holding a JSON document is walked as that document, so `argument`
is the location within the arguments (for example `command`) and a message
part's `type` and `name` can be read; a structured value is read as the
canary judge's walk reads it, an `arrayValue` element as `[i]` and a
`kvlistValue` entry as `.key`. A `tool_call` part's `arguments` that is
itself a string holding a JSON document is walked the same way. The
location of a hit inside it is the attribute's location followed by the
location within the document or value.

The structured walk reads `resourceSpans`, `resourceLogs` and
`resourceMetrics`. Every other member of an export request is searched as
well, with its location, and a hit there is `unknown`.

#### Unknown formats and unparsed lines

Every hit in an `unknown` file or an unparsed line is `unknown`.

## The report

### Credential states

Every credential in the report ends in exactly one state, the first that
holds:

| state | when |
| --- | --- |
| `not_checkable` | the store holds no fingerprint of it |
| `in_tool_call` | at least one `tool_call` hit |
| `in_context` | at least one `context` hit |
| `unknown` | at least one `unknown` hit |
| `stored` | at least one `stored` hit |
| `not_found` | no hit |

### Unknown

The audit is **incomplete**, and lists each reason, when:

| reason | subject | when |
| --- | --- | --- |
| `unrecognised_format` | the file | a file's format is `unknown` |
| `unparsed_line` | `<file>:<line>` | a line of a `claude-code` or `otlp` file is not a record |
| `not_scanned` | the file | a file was not scanned (`compressed`, or a `symlink` inside a directory) |
| `unknown_kind` | `<file>:<line>` | a hit whose kind is `unknown` |

An unrecognised record is walked in full and counted in the coverage, and
does not by itself make the audit incomplete: every string in it was
searched, and a hit in it is `unknown_kind`.

### Result and exit codes

The **result** is `exposed` when any credential is `in_tool_call` or
`in_context`, otherwise `unknown` when the audit is incomplete, otherwise
`clean`. A credential found in the context outranks incompleteness, and the
unknown reasons are still listed. `stored` hits and `not_checkable`
credentials do not change the result.

| code | result | meaning |
| --- | --- | --- |
| `0` | `clean` | complete, and no checkable credential entered the agent's context or a tool call |
| `1` | `exposed` | at least one credential entered the agent's context or was sent out in a tool call |
| `2` | none | usage or input error: bad arguments, an unusable or mismatched report, store or key, an unreadable path. No report is printed |
| `3` | `unknown` | no credential found in the context or a tool call, but the audit is incomplete: an unknown format, an unparsed line, a file not scanned, or a hit whose kind is unknown. A zero here would not be a real zero |

### Printing

A credential is printed by its inventory name, location and scope:
`<name> (<display>)` or `<name> (<display> <scope>)`. Every string the
audit prints that came from an input (a name, a display, a scope, a file
path, a record type, a location segment, a tool name) is flattened to
one line, cut to 200 characters (a file path is never cut), and replaced
entirely by `[withheld]` if it holds any encoded form (as the judge builds
them) or any run of 6 consecutive characters of any value the audit found,
or has a credential shape (the inventory's `looks_secret_shaped`). A
location or an argument is printed key by key under this rule, so a key
that holds a value reads `[withheld]` in its place
(`at=message.content[0].input.[withheld]`). A file whose path holds a
found value is printed as `[withheld]`: open the files given to find it.

So no output holds a value the audit found, an encoded form of one or a run
of 6 of its characters, and no output holds a hash, a fingerprint or a
masked form of any value. **What the rule cannot promise:** the audit holds
fingerprints, not values, so it cannot recognise a piece of a credential
that never appears whole in the files. A tool name or a key that holds, say,
8 characters of a credential found nowhere else, with no credential shape,
is printed as it is.

### The text report

One line per hit and credential, most severe kind first, then one summary
line per credential with hits, then the not found, not checkable, not
scanned and unknown lines, then the coverage line and the result:

```text
TOOL_CALL ACME_API_TOKEN (launch env) file=s.jsonl:7 record=assistant tool="Bash" argument=command at=message.content[0].input.command form=raw
CONTEXT aws_secret_access_key (~/.aws/credentials default) file=s.jsonl:9 record=user tool="Bash" at=message.content[0].content form=raw
UNKNOWN ACME_API_TOKEN (launch env) file=notes.log:3 format=unknown form=base64
ACME_API_TOKEN (launch env): in_tool_call (1 tool call, 0 context, 0 stored, 1 unknown)
aws_secret_access_key (~/.aws/credentials default): in_context (0 tool calls, 1 context, 0 stored, 0 unknown)
not found: GH_TOKEN (launch env)
not checkable: id_ed25519 (~/.ssh/id_ed25519) absent
unknown: unrecognised_format notes.log
coverage: 4 credentials (3 checkable), 2 files (1 claude-code, 1 unknown), 12 records (0 unrecognised), 0 unparsed lines, 230 strings
result: exposed
```

Precisely:

- a hit: `<KIND> <credential> file=<file>:<line>`, then `record=<type>` for
  a `claude-code` record, or `signal=<signal>` and `span=<quoted name>`,
  `log=<index>` or `metric=<quoted name>` for an OTLP record, or
  `signal=<signal>` alone for an OTLP string outside any record (a
  resource or scope attribute), or `format=<format>` for a text line (an
  `unknown`, `claude-code-tool-results` or `claude-code-memory` file, or an
  unparsed line) or an export request member outside the signals, then
  `tool=<quoted name>` and
  `argument=<location>` when there is one, then `at=<location>` when there
  is one, then `form=<form>`; `<KIND>` is `TOOL_CALL`, `CONTEXT`, `UNKNOWN`
  or `STORED`; quoted names use JSON string quoting; `<line>` is the line of
  the record, or of the text line;
- `<credential>: <state> (<T> tool calls, <C> context, <S> stored, <U> unknown)`
  for each credential with a hit, `tool call` when `<T>` is 1;
- `not found: <credential>`, `not checkable: <credential> <value_state>`,
  `not scanned: <file> (<reason>)` and `unknown: <reason> <subject>`;
- `coverage: <N> credentials (<K> checkable), <F> files (<groups>), <R> records (<U> unrecognised), <P> unparsed lines, <S> strings`,
  `<groups>` the count of each format present, in the order
  `claude-code`, `claude-code-tool-results`, `claude-code-memory`, `otlp`,
  `unknown`, then
  `<X> not scanned` when files were not scanned, joined by `, ` (so the
  groups add up to `<F>`; `0 files ()` when there are none). A count of 1
  takes the singular: `1 credential`, `1 file`, `1 record`,
  `1 unparsed line`, `1 string`;
- `result: clean|exposed|unknown`.

Hits sort by kind (as above), credential, file, line, location and form;
the other lists by credential, file or reason. The same input gives
byte-identical output, and the output depends on where values appear,
never on what they are.

### The JSON report (`weir-audit/1`)

`--json` prints indented JSON, fields in schema order, lists sorted as in
the text report. Its JSON Schema is generated from the structs and
drift-tested: [`packages/weir/schema_artifacts/audit.v1.schema.json`](../packages/weir/schema_artifacts/audit.v1.schema.json).

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | `"weir-audit/1"` |
| `result` | string | `clean`, `exposed` or `unknown` |
| `exit_code` | integer | `0`, `1` or `3` |
| `credentials` | array | one per credential in the report (below), sorted by name, display, scope and id |
| `hits` | array | one per hit and credential (below) |
| `files` | array | `{file, format, records, unrecognised_records, unparsed_lines, strings, bytes, not_scanned}`, sorted by file; `not_scanned` is `compressed`, `symlink` or null, and `format` is null for a file not scanned |
| `unknown` | array | `{reason, subject}` |
| `coverage` | object | `credentials`, `checkable`, `not_checkable`, `files`, `claude_code_files`, `claude_code_tool_results_files`, `claude_code_memory_files`, `otlp_files`, `unknown_files`, `not_scanned`, `records`, `unrecognised_records`, `unparsed_lines`, `strings`, `bytes` |

A credential:

| field | type | meaning |
| --- | --- | --- |
| `id` | string | the inventory credential id |
| `name`, `source`, `display`, `scope` | string, string, string, string or null | as in the inventory report, printed under the rule above |
| `value_state` | string | the inventory's `value_state` |
| `state` | string | the credential state |
| `tool_call`, `context`, `stored`, `unknown` | integer | its hits of each kind |

A hit:

| field | type | meaning |
| --- | --- | --- |
| `credential` | string | the inventory credential id |
| `kind` | string | `tool_call`, `context`, `stored` or `unknown` |
| `file` | string | the path, as given or found under a given directory |
| `line` | integer | 1-based line of the record or text line |
| `format` | string | the file's format |
| `record` | string or null | a Claude Code record's `type` |
| `signal` | string or null | `traces`, `logs` or `metrics` for any OTLP string, a resource or scope attribute included |
| `span`, `span_id`, `log_record`, `metric` | string, string, integer, string, or null | the OTLP record, as in the canary report |
| `tool` | string or null | the tool's name |
| `argument` | string or null | the location within the tool call's arguments |
| `location` | string or null | the location within the record, or within a JSON line of a text file; null for any other text line |
| `form` | string | the first form whose decoded text held the value |

## What the audit does not claim

A `clean` result is evidence about the files given, the checkable
credentials and the matching rules above. The audit does not find:

- a value that is not a whole candidate: a value glued to a word character
  or `-` on a side that is not a cut point, a truncated, split, masked or
  line-wrapped value, or a value holding a separator that no line,
  assignment, quoted run, PEM or word rule takes whole;
- a value hashed, encrypted, compressed, or encoded in a way not listed
  (URL-encoded base64, UTF-16, HTML entities);
- a credential whose value changed since the inventory ran (its
  fingerprint is of the old value);
- anything in the agent's context that is not in the files given: a
  session file that was deleted or never passed, telemetry that was never
  exported.

The kinds are a reading of the file formats, not of the agent's memory: a
`context` value was in the record the format says the agent receives.

### Known limit: speed

The audit searches every candidate of every string in every form, and
prints nothing until it is done. Measured on fake data: about 3 seconds per
MB of tool output text with little repetition (10 MB took 30 seconds), and
about 10 seconds for one 3 MB base64 image block, which is decoded and
searched from each of its four offsets. A whole `~/.claude/projects/` of
hundreds of MB can take tens of minutes or more.

## Testing against this contract

- Every fixture is derived from this document and from a real `weir
  inventory` run on a fake home: plant a fake value where the inventory
  finds it, write the session or telemetry file with the value in a place
  this document classifies, and expect what this document says. No
  expectation is a restated literal.
- Each form has a test that fails when that form's decoder is removed;
  each unknown reason a test that fails when its check is removed.
- Fake values only, built under a scratch home. No fixture is built from a
  real session.

## Versioning

- `weir-audit/1` changes only with an incompatible change; additive fields
  keep the version.
- Adding a format, a form, a kind, a credential state or an unknown reason
  changes what an audit means, so each is a CHANGELOG entry in the release
  that ships it.
