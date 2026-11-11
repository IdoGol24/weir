# Changelog

## [Unreleased]

weir-run's unmediated tool call below is decided by weir-run's own mock
and needs nothing of weir-scan's `weir canary judge`, so weir-run still
requires `weir-scan>=0.6.0`.

### Added
- **The exposure scan reads OpenTelemetry log records**: `weir scan` and
  `weir gauge` accept an OTLP logs export (`resourceLogs`, camelCase or
  snake_case) as well as a traces export, alone or mixed in one file or one
  document. In each log record the scan judges the attributes, the body
  (string, structured or nested) and the resource and scope attributes,
  with the same detectors, grades, printing rule and review queue as a span.
  A finding names its log record by 0-based position in the input
  (`log record 0` in text and HTML; `log_record` on the hit and the finding,
  with an empty `span_ref` and `span_name`). A batch holding data the scan
  cannot read, such as metrics, is reported as `data in 1 batch not
  scanned` in the terminal and the HTML report, never as clean. A logs-only
  input no longer exits 2.
- **Log records are read in every OTLP JSON spelling**: a log record's
  values may use snake_case wrappers (`string_value`, `kvlist_value`, ...),
  as protojson writes them with proto field names, and a `bytesValue` in a
  log record is base64-decoded and scanned when it is UTF-8 text. A log
  body written as a bare string is read as the body.
- **A log-record value the exposure scan cannot read is reported as not
  scanned** (`1 value not scanned`): bytes that are not UTF-8, a resource,
  list or record in a shape OTLP JSON does not use, or nesting past the
  depth cap.
- **`weir gauge` on a logs-only export** prints `flow scan: the input held
  no spans, so no flow trace was built` in place of the flow coverage
  lines, then the line for any input it could not decode (a JSONL line
  that is not JSON, bytes that are not UTF-8), then the exposure scan
  lines.
- **More credential shapes in the exposure scan.**
  - A bearer token is found in a request header map recorded as one
    OpenTelemetry kvlist attribute (for example
    `http.request.headers = {authorization: "Bearer ..."}`). An
    `authorization` or `proxy-authorization` entry, in any case, at any
    depth and with `_` for `-` (`proxy_authorization`), gives the same hit
    as the `http.request.header.authorization` attribute. Other entries are
    scanned as plain strings. A `http.request.header.proxy_authorization`
    attribute is now read as the header too.
  - A bearer token is found in a URL-encoded authorization header, with the
    space written `%20` or `+`, doubled or not (`authorization=Bearer%20...`,
    also inside a query string or a form body), and in a whole header line
    encoded as one value, the colon written `%3A` or kept
    (`authorization%3A%20Bearer%20...`, `authorization:%20Bearer%20...`).
    Inside the token, `%2F` and `%2B` count as token characters and `%3D`
    as padding, so a URL-encoded standard-base64 token is found whole. The
    token is judged decoded: it gets the same floors, length, last 4 and
    fingerprint as the same token in a plain header.
    After a `%20` or `+` the token ends at the next `+`, an encoded space
    too, so an encoded sentence is not a token. The display prefix stays
    `authorization: Bearer`.
  - A JSON-quoted credential field whose value is an array
    (`"api_key": ["..."]`, compact, indented, escaped or Python-repr, and
    nested arrays such as `[["..."]]`) is judged by its first string item of
    8 or more characters: up to three leading `null`, `None`, number or
    shorter string items are skipped. That item must pass the same
    8-character floor, placeholder rules and letter-and-digit rule for
    `token` as the string form. A placeholder first item hides a real value
    after it (`["REDACTED", "..."]` is not a hit).
- **The exposure scan reads names and keys.** `weir scan` and `weir gauge`
  now read a span's name, each span event's name, a log record's
  `eventName` (`event_name` in snake_case) and every attribute key as
  text: span, event, link, resource, scope and log record attributes, and
  the keys of a structured value at any depth. They also read each span
  link's attributes and `traceState`, a span's own `traceState`, a log
  record's `severityText`, the resource's and the scope's `schemaUrl`, the
  resource's `entityRefs`, and the scope's name and version: every
  free-form string field OTLP defines for spans and log records. A field
  OTLP does not define is not read (see Changed: it makes the export
  incomplete). A credential held only there is found and
  graded the same as one in an attribute value. Each such hit is reported
  at its own location: `name`, `events[0].name`,
  `links[0].attributes.app.cred`, `scope.name`, `eventName`, or for a key
  its attribute path marked `(key)` (`attributes.app.cred (key)`), and
  printed under the `[withheld]` rule,
  so the key itself is never printed. The gauge's string count now
  includes these strings; an empty name or key is not counted. A log
  record `eventName` or `severityText`, a span event name, a `traceState`
  or a `schemaUrl` that is not a string, or a span link or entity ref that
  is not an object, is counted as not scanned. Results
  for attribute values are unchanged.
- **weir-run: an unmediated tool call fails the run.** The mock keeps a
  tool ledger of its own: every tool call its model API issues, by call
  id, and every request served at a `[[mock.endpoint]]` whose new `tool`
  key names the tool that calls it, which is that tool executing (the
  pytest plugin's `endpoint(..., tool=...)` sets the same). Each execution
  is judged when it happens: it answers the oldest call issued for that
  tool in the flow that none has answered yet and whose result has not
  gone back to the model yet, or repeats an execution whose result has
  not gone back yet (a retry, several requests). A tool that executes
  with no call to answer, as when a program runs a tool call a caller put
  into the conversation or runs a tool after its call's result went back,
  is a finding named `unmediated-tool-call` (reason `not_issued`). A tool
  result under the call id the model gave another tool, which names a
  tool that executed while the asked tool never did, is the same finding
  with the reason `tool_mismatch`, even when the executed tool had a call
  of its own, so an alias or a substitution is told apart from an orphan
  call. It is printed on execution, never as a leak:
  `unmediated tool call: send_file (executed without a model request)`,
  `unmediated tool call: send_file (executed in answer to a model request
  for read_file)`. An execution without a model request is never clean,
  in a stored Responses conversation too. Nothing a model request carries
  makes a finding: few-shot tool-use examples, a replayed transcript, a
  framework's own hand-off, a summary or guardrail request, another
  agent's conversation. Neither do retries or batched calls. A tool that
  keeps sending requests to its endpoint after its result went back, such
  as a background upload, or first reaches it only then, such as a
  deferred or async tool, is a finding: a call answered without its tool
  running mediates no later run. A tool with no `tool` endpoint is
  never reported, and `tool` must be exactly the name the program offers
  the model. See docs/canary.md, "Tool calls".
- **The canary judge reads JSON escapes.** A planted value is found when
  the JSON around it writes any of its characters as a `\uXXXX` escape,
  not only the characters a standard serializer escapes: in a telemetry
  string, a request part, and a line only the raw sweep reads (console
  output and other swept files, and a capture line the walk or the
  request parser cannot read) that is JSON or holds a JSON object or
  array, such as a log line printing a tool's arguments, wherever that
  line is written. Text that holds no JSON, and the value of a credential
  field, are matched as before. The hit is reported at the same record
  and location as the plain value would be, under form `json` (escaped once) or `json2` (escaped more than
  once). Text is unescaped up to 16 times; text escaped deeper makes the
  run incomplete (`unparsed_record`), never clean. A name the judge
  prints whose unescaped text holds a value is shown as `[withheld]`.
  Every other judge result is unchanged (docs/canary.md, "The decoded
  view").
- `GOVERNANCE.md`, describing how the project is run: the maintainer, how
  decisions are made, how changes land, how to become a maintainer and how
  the document changes. It names the security lead, who `SECURITY.md` now
  names too. `CONTRIBUTING.md` links to it.

### Changed
- **`weir scan` exits 3, incomplete, when the export holds data the scan
  did not read.** An accepted export holding metrics, another signal, or
  span or log-record data in a shape the scan does not read (a span that
  fails to decode, a span value in a snake_case wrapper or in `bytesValue`,
  a span event that is not an object), or a field OTLP does not define
  holding data at any level (a span, event, link, status, scope, resource,
  log record, their resourceSpans, scopeSpans, resourceLogs and scopeLogs
  elements, or an attribute and its value), no longer passes clean. Such a
  field is counted, never read, and neither its name nor its value is
  printed. Unless a
  finding makes it exit 1, `weir scan` now exits 3, prints the not-scanned
  lines and then `incomplete: the export holds data the scan did not read
  (see above)`, and its HTML report shows an incomplete notice in place of
  the green page. Exit codes 0, 1 and 2 and the results
  for the data that was read are unchanged, and `weir gauge` still exits
  0. What you need to do: a CI step that treats any non-zero exit of
  `weir scan` as a failure needs no change; one that checks for exit 1
  alone should also fail on 3, or drop the unread data from the export.
- **`weir scan` prints `[withheld]` for a name that holds a found value.**
  In the text output and the HTML report, a span name, span id or attribute
  key that holds a value the scan found, eligible or in the review queue,
  or any 6 characters in a row of one, now prints as `[withheld]`. The
  name is checked as written, without undoing JSON escapes. Verdict lines
  and review-queue rows are both covered, on every exit code. What the
  scan reports, its counts, verdicts and exit codes are unchanged.
- **weir-run: exit 1 is a finding, a leak or an unmediated tool call.** No
  exit code was added: `weir-run run`, `weir-run verify`, the pytest
  plugin and the GitHub Action still exit 0 clean, 1 failed, 2 error and 3
  incomplete. Any finding fails a run; otherwise any gap makes it
  incomplete; only neither is clean. The run's text report is the judge's,
  with the `unmediated tool call` lines before its coverage line and the
  run's own result as its last line. The Action takes exit 1 with the
  result `leak` or `unmediated-tool-call`, and its `result` output can be
  `unmediated-tool-call`. For that result its PR comment headline and its
  error annotation are titled "Weir check", never a leak check.
- **`weir-run verify` writes `weir-verify-evidence/2`**, a new schema
  version with its own JSON Schema artifact
  (`weir-verify-evidence.v2.schema.json`): the v1 record with `findings`
  (`{type, reason, count}`) and the verdict `unmediated-tool-call`. Its
  predicate is `FAILED` with `finding:<type>` in `failedTests`. A run with
  an unmediated tool call cannot produce a `PASSED` result; its `FAILED`
  result is signed like a leak's. `weir-run predicate` still accepts a
  `weir-verify-evidence/1` record, which weir-run 0.3.0 wrote, and makes
  the same predicate for it as 0.3.0 did; the v1 schema artifact is
  unchanged. verify's own probe runs no tool, so its current target never
  reaches this verdict.
- **weir-run: `--report` writes `canary-report/2`**, the run's JSON
  report, with a JSON Schema artifact (`canary-report.v2.schema.json`):
  `result` and `exit_code` are always the run's, so a failing run never
  reads `clean`; `findings` (the finding types, as data), `unmediated`
  (`{tool, reason, issued_tool, count}` per group) and `judge`, the
  judge's own `canary-report/1`, unchanged. What you need to do: a job
  that reads the report's `result` or `exit_code` keeps working and now
  sees the run's verdict, `unmediated-tool-call` included; a job that
  reads the judge's other fields, such as `hits`, `placements` or
  `coverage`, reads them from `judge`.
- **weir-run: the mock's Chat Completions and Responses call ids are
  `call_mock_<n>_<i>`** (were `call_<n>_<i>`), so an id a program or a
  framework makes up is less likely to look like one the mock issued.
- Project links point to github.com/ralis-ai/weir.

### Fixed
- **weir-run never relays a slice of a planted key.** When `weir-run run`
  or the pytest plugin prints a flow's own stdout and stderr, every line
  that holds 6 or more characters in a row of a planted value is now
  replaced by `[withheld]`, as `weir-run verify` already did; before, only
  a whole value (in any of its encoded forms) was replaced, so a flow that
  printed part of its key showed that part. In a flow's relayed output,
  the prefix every key of a shape carries, such as `sk-ant-api03-`, is not
  itself withheld: only the random part of the value is judged. For an
  ID token the mock mints, that is its subject and signature, so another
  JWT with the same header and claims reads as printed. A refused-egress
  host, a blocked direct target and an unmocked request keep the judge's
  printing rule, the whole value with its prefix, and are now judged in
  either letter case, since the mock records a host in lower case: a host
  name that holds a slice of a key now reads `[withheld]`. Output that
  holds no part of a value is relayed exactly as before.
- **A long run of backslashes after a credential-field key no longer slows
  the scan.** The `credential_field` and `json_credential_field` patterns
  now check each backslash run once, not once per value character. Such
  input now scans at about the speed of ordinary input of the same size,
  where before it was more than 10 times slower. Matches are unchanged.

### Corpus
- The diffspec baselines were regenerated for the new catalog digest. The
  diff is digest-only.
- `fixtures/exposure/attribute-exposure.expected.json` was regenerated:
  each hit, and each rule result drawn from it, now records `span_key` and
  `site_key`, the span and location it is at, which the counts use. No
  other field changed.

## [0.9.0] - 2026-11-08

### Added
- **The exposure scan finds `Authorization: Bearer` tokens** (class
  `bearer_token`, rule `bearer-token-in-telemetry`) in plain, lower-case,
  JSON, JSON-escaped and Python-repr form, as a JSON array value
  (`{"Authorization": ["Bearer ..."]}`, the shape Go's `json.Marshal`
  gives an `http.Header`, compact or indented), in a Python or ASGI header
  tuple list
  (`[(b'authorization', b'Bearer ...')]`), and in the OpenTelemetry span
  attributes `http.request.header.authorization` and
  `http.request.header.proxy-authorization` (string or array, any case),
  which the scan reads as the header line `<name>: <value>`. Every other
  request header attribute is scanned as before. A sentence period
  after the token is not part of it. A token of 20 or more characters
  is verdict-grade; a placeholder (`<token>`, `${TOKEN}`,
  `YOUR_ACCESS_TOKEN`, filler) never is. The display prefix is the header
  as written, with quotes, escapes and operators normalized (for example
  `Authorization: Bearer`).
- **The exposure scan finds Google OAuth credentials** (class
  `google_oauth_credential`, rule `google-oauth-credential-in-telemetry`):
  access tokens (`ya29.`), refresh tokens (`1//`, a digit, then 39 to 511
  characters of `A-Z`, `a-z`, `0-9`, `_` or `-`) and client secrets
  (`GOCSPX-`). The display prefix is 4 characters of the class head, so no
  output prints 6 or more characters of a value. `weir inventory` finds both
  in project files, code files included.
- **JSON written with escaped slashes (`\/`) does not hide a token**: a
  bearer token or a Google refresh token keeps its hit when an encoder
  writes each `/` as `\/`.
- **The exposure scan finds JSON-quoted credential fields** (class
  `json_credential_field`, rule `json-credential-field-in-telemetry`,
  review queue only): `"api_key": "..."`, `'password': '...'` and the same
  field inside escaped JSON. The value runs to its closing quote, spaces
  included, and the 8-character floor and the masked/None/null/REDACTED
  rules judge the whole value. Under the key `token` exactly (any case) the
  value counts only when it has a letter and a digit, and a character
  inside an escape sequence (`\n`, `\u0041`, `\xe4`) counts as neither, so
  the `"token"` of an LLM logprobs response (`"Certainly"`, or `"\u4f60"`
  as an ASCII-only encoder writes a non-English token) is not a match.
  `"tokenizer"`, `"password_hint"` and `"max_tokens"` do not match. `credential_field`
  keeps the unquoted `key=value` form, value ending at the first space.

### Corpus
- The diffspec baselines were regenerated for the new catalog digest
  (digest-only diff); the attribute-exposure capture gained one escaped
  placeholder line per new class, which reaches the review queue only.
- The bundled canary sample (`canary-sample/otlp.jsonl`) now shows one
  `json_credential_field` review-queue match: its fake `api_key` field inside
  escaped JSON. The scan's exit code is unchanged.
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.8.0 to
  0.9.0. That diff is version-only; no flow fact, node count or finding
  moved.

## [weir-run 0.3.0] - 2026-11-08

Released beside weir-scan 0.9.0, still requiring `weir-scan>=0.6.0`.

### Added
- **`weir-run verify` and a signed result.** Checks that a credential swap
  or sandbox keeps a planted fake key out of the model request, telemetry,
  console output and outbound requests; the first target is `--target
  iron-proxy`. Exit 0 clean, 1 leak, 3 incomplete: what the run could not
  check is incomplete, never clean. `--evidence` writes a value-free record
  with a JSON Schema; `weir-run predicate` makes an in-toto test-result
  predicate from it (PASSED only for clean), and the reusable workflow
  `.github/workflows/verify-attest.yml` signs it. See docs/verify.md.

### Changed
- **Every placement is required by default.** A placement with
  no `required` setting now makes the run incomplete (exit 3,
  `incomplete: required_not_exercised <id>`) when no flow exercised or
  leaked it; before, it was only reported as `not exercised` and the run
  could still be clean. This covers `[[placement]]` in a `weir-run run`
  config and `canary_check.env` and `canary_check.code` in the pytest
  plugin. Checks that already set `required = true` are unchanged. To keep
  the old behaviour for a placement, set `required = false` in TOML or pass
  `required=False`. The pytest helpers now refuse a `required` value that
  is not `True` or `False` (such as `None` or `0`), as TOML already did,
  so only `False` opts out.

## [0.8.0] - 2026-10-26

### Added
- **`weir statusline hook`: a redaction hook for Claude Code
  (experimental).** A `PostToolUse` hook for Read, Bash, Grep, Glob and
  WebFetch results, with a 10 second timeout, that replaces each
  inventoried credential with `[weir: NAME removed]` before the model sees
  it. It finds values by keyed fingerprint, in every form `weir audit`
  matches, and holds no plaintext key; a base64 or hex value is replaced
  with its whole run. The result keeps its exact shape, and one with no
  known value passes untouched. Claude Code's hooks reference says
  `updatedToolOutput` "only changes what Claude sees"; for a large output
  Claude Code also saves the whole output, the original, in the session's
  `tool-results` folder before the hook runs and gives Claude its path, so
  the hook also rewrites that saved copy with the same replacements,
  owner-only, taking it only at the exact path the result names, in that
  session's folder, and only up to 256 KiB and 6 seconds of searching: a
  larger saved file, or one not searched in time, is left as it is and the
  call flagged, so searching the saved file never holds the hook past the
  timeout.
  Each call leaves a marker (pending, then done with counts by name once
  its output is written and its saved file rewritten, or failed) that
  holds no value. With the hook installed, the status line and `/weir`
  count three kinds, entered, sent and kept out (`weir ✓ no known key
  seen · 2 kept out`), and add `possibly not redacted` in amber after the
  line's own words (`unknown`, `scanning… P%`, `partly checked` or the
  counts), never green, for a covered tool result the hook did not finish:
  a call marked failed (a saved file it could not rewrite included), one
  still pending past the timeout, or a result with no marker. The binary
  payloads a Read returns (image, PDF and notebook image data) are left
  unsearched, and markers and their folders are owner-only. Markers older
  than 7 days are folded into one summary per session on a status line
  refresh, at most once a day, without changing what any session reads.
  `weir statusline setup` shows the hook in its preview and adds it only
  on an exact `yes` to its own question, `Add the redaction hook too?`,
  asked after the `yes` that applies the change, and suggests answering no
  to that question when the settings' `hooks` value cannot take it; `undo`
  takes it out and removes its markers, kept in a folder per Claude config
  dir. Limits: it doesn't undo a command that already ran, it can't catch
  a value pasted into the chat, a hook failure sends the original output
  (flagged), an agent that is taken over can switch hooks off, it matches
  whole values only, a WebFetch result has already been through Claude
  Code's own model, a large output's original is in its saved file for a
  moment before the rewrite (and stays there over 256 KiB or 6 seconds of
  searching), and the output
  of a failed tool call reaches the model without it; `/weir` then says the
  key entered through a failed tool call and, for a key that lives in a
  file whose path may be printed, gives a Claude Code `Read` deny rule
  snippet with what such a rule does and does not stop
  ([docs/statusline.md](docs/statusline.md#the-redaction-hook)). For a key
  found only in a saved tool output, `/weir` says the agent was given that
  file's path and advises deleting it.
  The README describes the hook with its three main limits and links the
  full list.

### Changed
- **The status line's first count says `entered`.** It was `in context`:
  `weir ⚠ 2 entered · 1 sent → /weir`, in the segment and the first line
  of `/weir`.

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.7.1 to
  0.8.0. That diff is version-only; no flow fact, node count or finding
  moved.

## [0.7.1] - 2026-10-26

### Fixed
- **`/weir` no longer prints part of a key in a folder name.** When the
  report says the session is not in the inventoried project, or that it
  cannot tell, it named the inventory's project folder and the session's
  or current folder as they were. A folder name that holds a key, 6 or
  more characters of a key the report found, or a segment shaped like a
  key now shows as `[withheld]`, as every other place the report names
  does, and the command to switch the inventory to that folder says to
  run it in the folder, with `--project .`. When the inventory's report,
  store or key sits under such a folder (a home whose name holds part of
  a key, say), the switch command is not shown: the report gives the
  whole command to run in the folder, with a placeholder for each
  inventory path, to fill in with the inventory's own. A folder or file
  name with a character the report does not print, such as a line break,
  is handled the same way, so it no longer adds a line of its own to the
  switch command.

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.7.0 to
  0.7.1. That diff is version-only; no flow fact, node count or finding
  moved.

## [0.7.0] - 2026-10-26

### Added
- **`weir statusline`: a Claude Code status-line segment and a `/weir`
  report (experimental).** The segment counts, for the current session,
  the inventoried credentials that entered the agent's context and those
  sent out in a tool call (`weir ⚠ 2 in context · 1 sent → /weir`, the
  first count amber, the second red, a zero dim). It says
  `weir ✓ no known key seen` in green only for a session read to its end
  with nothing found, inside the inventory's project: it knows only the
  inventory's keys, so it claims no more than that. The session's project
  folder is Claude Code's `workspace.project_dir`, else `cwd`; when it is
  not the inventory's project or under it, when the inventory has no
  project, or when the folder is not a usable absolute path, the line
  shows a dim `weir project not inventoried` in place of the green.
  Otherwise it says so plainly, in dim text: `nothing to check` when the
  inventory holds no credential weir can check, `unknown` rather than a
  false zero, and `scanning… P%` while a long session is read in
  checkpointed steps. A long record gets 5 seconds
  of its own; one not searched whole in three tries in a row makes the
  session `partly checked`, never a count, and `weir audit` or `/weir`
  gives the full answer. Every coloured part resets after itself, so the
  status line beside it keeps its own colours, and `NO_COLOR` gives the
  same words with no colour codes. `/weir` lists each credential with its
  source, turn, tool call, where it now sits and what to do. It judges the
  same folder the status line saw: the segment records each session's
  project folder in an owner-only file in its cache, and `/weir` reads it
  by session id, so no folder name is ever part of the command. Until the
  status line has recorded a folder, `/weir` is never green. Outside the
  inventory's project it says so and gives the command that switches the
  inventory to that folder, never to the home or a folder that holds it.
  Neither ever shows a value ([docs/statusline.md](docs/statusline.md)).
- **Status-line setup in two commands.** `weir statusline setup` needs no
  flags: `--inventory`, `--store` and `--key` default to
  `~/.weir/inventory.json`, `~/.weir/store.json` and
  `~/.weir/fingerprint.key`, and each flag still overrides its default.
  With no inventory at the default path, setup takes one of the standard
  credential locations in the home, the shell startup files and the
  launch environment (the shell it runs in is taken as the environment
  Claude Code starts with). Before it does, setup names the current
  folder and offers to include its files as the project; only an exact
  `yes` includes it. The home, or a folder that holds it, is never
  offered, since its walk would read the whole home, and neither is a
  folder that cannot be read. Without a project the preview says the
  status line then never shows green and gives the command that includes
  one later. The preview lists each credential found by name, source and
  location only, never a value. An inventory already at the default path
  is used as it is and named in the preview. Nothing is written before an
  exact `yes`, and `--dry-run` writes nothing. On `yes` it writes the key
  (only when there is none), the store, the unknown variable names and
  the report, all readable by the owner only, then adds the segment
  beside the existing status line. With the default store and key, the
  preview prints the command that refreshes the inventory:
  `weir inventory --home ~ --no-project --process-env --json --store
  ~/.weir/store.json > ~/.weir/inventory.json`, with `--project DIR` in
  place of `--no-project` when the inventory has a project. The inventory
  holds one project at a time: the same command with another
  `--project DIR` switches it, and the earlier project's keys then stop
  being counted. The status line picks up the new report on its next
  refresh. Setup refuses a path for the `/weir` command that holds a `$`,
  which Claude Code would substitute. With `--inventory` given,
  setup refuses (exit 2) when that file is missing, or when `--store` or
  `--key` is left to a default file that is missing. `weir statusline
  undo` puts the settings back and leaves `~/.weir` in place.
- **`weir audit` checks your own credentials against your own agent
  sessions (experimental).** Given the report, the fingerprint store and
  the key from one `weir inventory --store` run, it reads Claude Code
  session files (main and subagent transcripts, their sidecars and saved
  tool outputs), `CLAUDE.md` and auto-memory files, and OTLP/JSON
  telemetry offline. For each credential, by inventory name and never by
  value, it reports whether it entered the agent's context or was sent
  out in a tool call, with counts and the file, line, field, tool and
  argument of each sighting. Values are matched by keyed fingerprint in
  every form the canary judge matches (raw, JSON, double JSON, URL,
  base64, base64url, hex); the base64 data of an image is not searched.
  An unrecognised file format, a line that is not a record, a file not
  scanned, a sighting it cannot place, a PDF whose text is compressed, or
  an empty input (a missing or empty directory, or paths whose files were
  all skipped) makes the result `unknown`, never a false clean. When
  `CLAUDE_CONFIG_DIR` is set, the `projects` folder of that directory
  counts like `~/.claude/projects`. Exit codes: 0 clean, 1 exposed, 2
  unusable input, 3 unknown. Report schema `weir-audit/1`
  ([docs/audit.md](docs/audit.md)).
- **`weir inventory --no-project`.** It walks no project directory and
  reads no map; the report's `inputs.project` is null, as in a first
  status-line setup with no project folder. It cannot be
  combined with `--project`, `--gitleaks` or `--trufflehog` (exit 2).
- **The inventory store carries a key check.** `weir-inventory-store/1`
  gains `key_check`, an HMAC of a fixed message under the fingerprint
  key, so a reader can tell whether a store was made with its key.
  `weir audit` refuses a store without it: run `weir inventory --store`
  again.
- **A GitHub Action: `uses: ralis-ai/weir@<ref>`.** One step in a pull
  request job installs weir-scan and weir-run at exact versions (by
  default the versions recorded at the action's ref, wheels only), runs
  `weir-run run --config` (`canary.toml` by default, `require-isolation`
  optional) and posts the verdict as one PR comment, updated in place on
  a re-run. The comment and the step summary show the result and the
  report's own lines, never a value. The job passes on clean (0) and
  fails on leak (1), incomplete (3) and error (2, or an exit code the
  report's result line does not confirm). A comment that cannot be
  posted, as on a pull request from a fork, is a warning and the verdict
  stands. On GitHub-hosted Linux runners it allows unprivileged user
  namespaces so the flows run isolated. It uses the job's own
  `GITHUB_TOKEN` with `pull-requests: write` only, and of its own steps
  only the one that posts the comment, after the flows have run, is given
  the token. The comment names the pull request's head commit; on a
  `pull_request` event the tree judged is GitHub's merge of that head
  into the base branch. At a ref between releases, where the recorded
  weir-run needs a newer weir-scan than the one recorded, it stops with
  an error instead of installing older code
  ([action/README.md](action/README.md)).

- **`weir --version`** prints the installed version, as `weir 0.7.0`.

### Changed
- **A fingerprint key file others can read is refused.** `weir
  inventory`, `weir audit` and `weir statusline` all refuse (exit 2) a
  key file another user owns or that others can read or write. Run
  `chmod 600` on a key file made by hand.
- **`weir statusline setup` and `undo` refuse plainly when they cannot
  write.** A read-only Claude config directory or `commands/` folder, or
  a full disk, is exit 2 with a message naming the file and how to finish
  (run setup again, or `weir statusline undo`), and `settings.json` is
  never left half written.
- **A shorter README.** It leads with the sample and the two ways to use
  Weir: testing your agent with planted fake keys, and watching your own
  Claude Code sessions. The detail it no longer carries moved to
  [docs/canary.md](docs/canary.md), a new [docs/scan.md](docs/scan.md),
  [docs/audit.md](docs/audit.md), [docs/statusline.md](docs/statusline.md)
  and [action/README.md](action/README.md).

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.6.0 to
  0.7.0. That diff is version-only; no flow fact, node count or finding
  moved.

## [weir-run 0.2.1] - 2026-10-26

Released beside weir-scan 0.7.0, still requiring `weir-scan>=0.6.0`. No
code change.

### Changed
- **The README names the GitHub Action.** Its limits no longer say there
  is no GitHub Action; they point to the action that runs a config and
  posts the verdict on the pull request.

## [0.6.0] - 2026-10-22

### Added
- **The judge reports whether the network was isolated.**
  `canary-ledger/1` gains a `network` record (`isolated`, `required`) and a
  `direct` record (`flow`, `protocol`, `target`, `attempts`) for each
  connection attempt isolation blocked. Every report carries a network
  line after the coverage line, `network isolated: N direct connections
  blocked` or `network not isolated: direct connections were not
  observed`, and `canary-report/1` a `network` object. Two incomplete
  reasons are new: `network_not_isolated` (isolation was required and
  missing) and `direct_connection` (a flow tried to reach a host around the
  mock). A ledger with no `network` record is reported as not isolated.
- **Outbound requests are a sink (`weir canary judge
  --requests`).** The judge reads a request capture (`canary-requests/1`,
  one line per request the mock received: destination, method, path,
  query, headers and body, and whether it was served, refused or a
  `CONNECT`) and searches every request for every planted value in every
  encoded form. A value in a credential field of a request to the
  placement's own provider (a ledger placement's new optional `providers`
  endpoint ids and `provider_host`; each request record names its
  `credential_fields`) is `request` or `egress` evidence that it was
  exercised; anywhere else, the rest of that request included, it is a
  leak, reported with `signal=requests`,
  the request's `sink` (`model`, `oauth`, `otlp`, a declared api's id,
  `unmocked`, or `<host> (blocked)` for a refused plain-HTTP request) and
  the field (`headers.<name>`, `query.<name>`, `body.<json path>`,
  `body.<form field>`, `path`, `host`, `method`, or the whole `query` or
  `body`). A refused `CONNECT` has no visible content: it is listed as a
  blocked connection attempt and counted in the coverage, never a leak by
  itself. The report gains the hit field `sink`, a `blocked` list and the
  coverage counts `request_files`, `requests`, `requests_refused` and
  `connections_blocked`; the text coverage line gains a requests segment
  when a request capture is given. A request capture line that is not a
  request record, or a body the mock could not read in full, makes the run
  incomplete (`unparsed_record`). The schema artifact
  `canary-requests.v1.schema.json` is new; `canary-ledger.v1` and
  `canary-report.v1` gain the fields above. The judge stays offline and
  deterministic.

### Changed
- **The printing rule withholds runs of 6 characters, down from 8.** No
  report prints a run of 6 or more consecutive characters of any planted
  value, and a ledger id may not hold one.
- **The PyPI summary names every sink the judge searches.** It reads
  "Leak tests for AI agents: deterministically find planted credentials
  in your agent's telemetry, model requests and outbound calls."

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.5.0 to
  0.6.0. That diff is version-only; no flow fact, node count or finding
  moved.

## [weir-run 0.2.0] - 2026-10-22

Released beside weir-scan 0.6.0 and requiring `weir-scan>=0.6.0`.

### Added
- **Flows run where the only network is loopback.** On Linux,
  `weir-run run` and the pytest plugin run the mock and every flow in an
  unprivileged user and network namespace with no route out, so a client
  that ignores the proxy settings reaches nothing. Each blocked attempt is
  seen and reported (`tcp` and `udp` by address and port, `dns` by name),
  and a blocked datagram's payload, a DNS query included, is swept capture,
  so a canary in it is a leak. Where the namespace cannot be made (not
  Linux, user namespaces disabled or restricted), the run goes ahead
  unisolated and says why. `--require-isolation`
  (`--canary-require-isolation`) makes an unisolated run incomplete, exit
  3. weir-run now requires `weir-scan>=0.6.0`, whose judge reads the new
  ledger records.
- **Every request the mock receives is recorded.** The mock
  writes each request, refused ones included, to `capture/requests.jsonl`
  before answering it, and the runner passes it to the judge with
  `--requests` and deletes it after the run with the rest of the capture.
  A placement names its own provider with the new `provider` key (`model`,
  `oauth`, `otlp` or a `[[mock.endpoint]]` id; `provider=` in the pytest
  plugin), so a key pasted into a prompt, sent to the model API as a
  credential, sent to the wrong one of the program's APIs or sent in a
  plain-HTTP request to another host is a leak. A token the mock's OAuth
  endpoints issue belongs to them and to every declared endpoint.
- **A warning for each placement without a provider.** Before
  any flow runs, `weir-run run` and the pytest plugin print `placement
  <id> has no provider: any request holding it counts as a leak` to
  stderr for every placement with neither `provider` nor
  `provider_host`. It names the id, never a value.
- **An Anthropic Messages API mock.** Model APIs can now be
  OpenAI-compatible or Anthropic Messages API. Beside the
  OpenAI-compatible APIs, the mock serves `POST /v1/messages`, plain and
  streaming (`message_start`, `ping`, `content_block_start`,
  `content_block_delta`, `content_block_stop`, `message_delta`,
  `message_stop`), on the same script: with tools offered, turn one
  answers with a `tool_use` block for every tool, and once the last user
  message carries `tool_result` blocks it answers `model_reply`. A query
  such as `?beta=true`, body fields it does not know and `system` entries
  between turns are accepted, and the model API answers `HEAD` and `GET
  /api/hello` with `200`. Flows get `ANTHROPIC_BASE_URL` pointing at the
  mock, the variable the Anthropic SDKs read their base URL from; a
  flow's `env` may no longer set it. The model API now always declares
  the `x-api-key` header as a credential field: a placement with
  `provider = "model"` sent there is exercised, the same value in a
  prompt or a tool result is a leak to `model`, and any other value in
  `x-api-key` is `unexpected.model.x-api-key` and makes the run
  incomplete.

### Changed
- **A placement without `provider` belongs in no request.** Any
  request that holds its value is now a leak, where a credential field
  holding it used to count as exercised wherever it was sent. Add
  `provider` to each placement that a flow legitimately sends to a mocked
  endpoint. The runner refuses a weir-scan whose judge has no `--requests`.
- **The mock no longer writes `request` or `egress` evidence.**
  The judge derives both from the request capture, so the evidence and
  the leak verdict come from one place.
- **The PyPI summary describes the rig.** It reads "Leak tests for AI
  agents: plant fake credentials, run your agent in an isolated rig, and
  capture everything it sends out."

## [0.5.0] - 2026-10-21

### Added
- **`weir canary judge`: did a planted fake credential reach the
  telemetry?** `weir canary judge --ledger FILE --otlp PATH [--json]
  [PATH...]` reads a `canary-ledger/1` ledger (placement ids plus the fake
  values planted there) and the captured telemetry, and reports every
  placement whose value, or an encoded form of it, appears anywhere in the
  capture, naming the placement, file, line, record and location, never a
  value or a fragment of one. The contract is `docs/canary.md`. This first
  version ships the placement kinds `env`, `code` and `mock-oauth`; the
  evidence types `request`, `minted` and `egress`; the forms `raw`, `json`,
  `json2`, `url`, `base64`, `base64url` (the base64 core at byte offsets 0,
  1 and 2) and `hex`; and the incomplete reasons `required_not_exercised`,
  `flow_not_ok`, `unexpected_credential`, `not_scanned`, `unparsed_record`
  and `empty_capture`. `--otlp` files get a structured walk of every span,
  log record and metric (every string, `stringValue` and decoded
  `bytesValue`) plus a raw byte sweep; other paths, such as a flow's stdout
  and stderr, get the raw sweep only. Exit 0 clean, 1 leak, 2 unusable
  input, 3 incomplete. `--json` emits the `canary-report/1` report; both
  schemas are in `packages/weir/schema_artifacts/`. The judge opens no
  socket, starts no process and reads no clock.
- **`weir canary judge --sample`: a leak report in one command.** It judges
  a bundled sample (a ledger of fake values and an OTLP/JSON capture with
  one planted value in a span attribute) with no other input, offline, and
  exits 1 naming the placement, span and attribute, never the value.
- **`weir inventory` (experimental): which credentials an agent could reach,
  by name only.** Its output and JSON schema may change without notice. Four
  sources: a versioned list of standard credential locations under the given
  home (`~/.aws`, Google application default credentials,
  `~/.npmrc`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, git
  credentials, gh and more, including the variables that move them); the
  project tree, through Weir's catalog plus imported gitleaks or trufflehog
  results; the launch environment (`--env-file` or `--process-env`) with the
  shell startup files that re-export into it; and the approved map
  `.weir/reach.yml`. Environment variables are secrets by name or value
  shape, not secrets when the value is a number, boolean, path or plain
  hostname, and otherwise unknown: a count on screen, names in a file, a
  failure only with `--strict`, markable as fine in the map. Files a
  `.gitignore` covers are reported per route (hidden from Grep's directory
  search, still reachable by Read, cat and grep -r). Nothing prints, logs or
  stores a value; `--store` writes HMAC-SHA256 fingerprints under a local
  key plus byte offsets. `--json` emits the `weir-inventory/1` report, whose
  schema and Python API are documented in `docs/inventory.md`. `--home` is
  required: there is no default home.

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.4.1 to
  0.5.0 (main never carried 0.4.2, which shipped from `release/0.4.x`). That
  diff is version-only; no flow fact, node count or finding moved.

## [weir-run 0.1.0] - 2026-10-21

The canary runner is its own package, `weir-run`, released beside weir-scan
0.5.0 and requiring `weir-scan>=0.5.0`. Its versions are recorded here,
under `weir-run` headings.

### Added
- **The canary runner, a separate package.** It plants unique fake canaries
  (`env` and `code` placements), runs a program's flows under an empty
  environment plus an allowlist against a mock bound to `127.0.0.1` (an
  OpenAI-compatible model API with scripted tool calls, OAuth endpoints
  whose issued tokens become `mock-oauth` placements, an OTLP/HTTP receiver
  writing OTLP/JSON lines, the program's own declared APIs, and refusal of
  every proxied request to another host; the runner does not sandbox the
  network, so a client that ignores proxy settings can connect directly),
  relays flow output with every canary form redacted, and exits with the code of `weir canary judge` (docs/canary.md). Ships a
  subprocess-mode pytest plugin and a synthetic demo that is red with a
  leak and green without. weir-scan's commands stay network-free, and weir
  never imports the runner.

## [0.4.2] - 2026-10-20

### Fixed
- **The exposure display no longer shows characters of a key's body.** A
  hit is shown as the class prefix, `...` and the last four characters. The
  prefix was cut at the last `-` or `_` in the first 16 characters, and real
  OpenAI and Google key bodies contain both, so the display could show up to
  8 body characters of an OpenAI project key or 12 of a Google API key. The
  prefix now stops at the class's literal head (`sk-proj-`, `sk-ant-api03-`,
  `ghp_`, `AKIA`, `AIza` and the like).

### Corpus
- The release commit regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.4.1 to
  0.4.2. That diff is version-only; no flow fact, node count or finding moved.

## [0.4.1] - 2026-10-14

### Fixed
- **The `credential_field` key=value detector now sees assignments after an
  escaped line break.** Tool arguments arrive as JSON-encoded text, so line two
  of a written `.env` file or script sits right after a literal `\n` (or `\t`,
  `\r`), and that escape's letter defeated the key-name boundary: no
  assignment past the first line reached the review queue. A JSON `\n`, `\t`
  or `\r` escape now counts as a boundary on both sides: it starts a key name
  and ends the value before it, so a value is measured as decoded, the next
  line is no longer folded into it, and a masked `API_KEY=********` on line two
  is still dropped. A key name glued to any other letter (`mytoken=`) still
  does not match.
- **Every key-shaped detector now sees a value after an escaped line break.**
  `github_token`, `openai_api_key`, `anthropic_api_key`, `aws_access_key_id`,
  `google_api_key` and `financial_account_identifier` opened with a word
  boundary, which read the escape's letter and the value as one word: a key or
  IBAN on line two of JSON-encoded tool arguments or tool results was never
  labeled: no exposure-scan hit for a key, no taint finding for any class. Each
  now opens with `(?:\b|(?<=\\[ntr]))`, a word boundary or a JSON `\n`, `\t`
  or `\r` escape; a value already ended at a following escape. A value glued
  to any other letter (`xghp_...`) still does not match, and `sk-ant-` still
  outranks `sk-` at one offset.

### Corpus
- The diffspec baselines were regenerated for the catalog digest only; no flow
  fact, node count or finding moved. The attribute-exposure capture gains a
  Write tool-call pair: a `.env` line-two assignment that must reach the review
  queue, and a glued-identifier near-miss that must not. It also gains a key
  file with one value of each key-shaped class after a `\n`, `\t` or `\r`
  escape, and the same values glued to a letter as the near-miss; the diffspec
  baselines moved with the catalog digest again, digest only.
- The release commit also regenerated the diffspec baselines for the package
  version, which the baselines embed: `weir_version` moved from 0.4.0 to
  0.4.1. That diff is version-only; no flow fact, node count or finding moved.

## [0.4.0] - 2026-09-07

### Added
- **Credential exposure scan. Exports that exited 0 on 0.3.0 can exit 1 on
  0.4.0.** weir now reports a credential-class value that is *present* in
  exported telemetry, not only one that flows to a sink: an OpenAI, Anthropic,
  AWS, Google or GitHub key, or an assignment-shaped `api_key=` field, found in
  a span attribute, an event attribute, a status message, or a resource/scope
  attribute. The scan reads the raw wire batch before the GenAI span filter, so
  a vendor-attribute leak on a span weir does not otherwise map is still
  reported. Six bundled rules fire it; the text report names the rule and
  prints `to demote: set "stage": "shadow" in <rule file>`.
- **Eligibility floors for credential classes:** `min_distinct_chars` and
  `reject_patterns` (both catalog data, both compiled at load), so
  `sk-proj-0000...`, `api_key='***'` and each provider's documented example key
  never reach verdict grade. A key-name match alone never does either: its
  class declares no floor.
- `--fail-on {high,medium,low}` is real for every finding family, gated on a
  new `RuleSpec.severity` that defaults to `high`.

### Corpus
- The committed diffspec baselines were regenerated **twice** across this
  release, for two unrelated and unavoidable reasons: once for the catalog
  digest, which moves when source classes or eligibility fields are added, and
  once for the package version, which the baselines embed and which the release
  commit bumps. Both diffs are digest-only and version-only respectively; no
  flow fact, node count or finding moved in either.

### Changed
- The HTML report's node preview is masked for every node, not only nodes on a
  witness path, and the adapter's undecodable-span ledger entry names the
  span's keys rather than a raw JSON slice of it. Both were paths by which raw
  content could reach a rendered artifact; a test now runs every credential
  pattern over every artifact weir produces and asserts zero eligible matches.

## [0.3.0] - 2026-08-31

### Added
- **Provenance evidence tier (opt-in).** Declare `untrusted_sources` in the
  catalog and write a sink-scoped rule with `mode: "provenance"` (reserved
  `source_class: "untrusted_origin"`), and an untrusted-origin value reaching a
  must-never sink becomes a verdict-grade finding. It is silent by default: with
  no declared trust boundary, `scan` emits nothing and the triage signal
  (observed `tool_result -> sink` flows grouped by origin tool, plus attribution
  coverage) lives in `gauge`, not `scan`. The loader hard-errors on the unwired
  `context` mode and validates the reserved marker both ways. Benchmarked on
  1,352 labelled AgentDojo banking runs at precision 0.48 / recall 0.95 through
  the shipped pipeline; the co-residence false-positive mode is pinned by a test.

### Changed
- **Tool-node identity is derived from a span's content, not its OTel span
  kind.** A single `execute_tool` span carrying both `gen_ai.tool.call.arguments`
  and `gen_ai.tool.call.result` now splits into a joined tool_call + tool_result
  pair, so the injection-exfil finding fires on real single-span telemetry
  (previously it only fired on a synthetic two-span shape no real instrumentor
  emits). The pure analysis core is unchanged.

### Fixed
- Node ordering now sorts on raw start-nanos rather than the ISO-8601 string, so
  a whole-second span no longer sorts after a same-second fractional one.

## [0.2.0] - 2026-08-25

### Added
- `VerbatimEligibility.pattern`: a third eligibility option matched with
  `re.fullmatch`, so a shape-shaped data type (an AWS key id, a GitHub token,
  a PEM header, a JWT) needs no validator function. `structure_class` remains
  for the few types with a real checksum.
- The default catalog is now loaded from `catalog/bundled/catalog.json`
  instead of a Python literal, with a loader mirroring `load_rules`. Adding a
  source class is a JSON edit. Contributor-authored regexes are compiled at
  load time and fail named by source and field, so a typo can never raise
  mid-scan where a CI gate would read it as a finding.
- `github_token` as the first source class contributed through that path
  rather than authored alongside the engine, with its rule, a positive
  fixture and a near-miss fixture.
- `CONTRIBUTING.md`, documenting the add-a-data-type path that was walked and
  the friction it turned up.

### Changed
- The project moved to the repository root; `weir/CLAUDE.md` is now
  `AGENTS.md`. Corrects two project URLs that pointed into the old path.
- A value repeated inside one node is labeled once. Identical labels carried
  no distinguishing information and surfaced as byte-identical duplicate
  findings on the same witness path.
- Nothing in the repo is gated or held back. Everything is Apache-2.0,
  permanently.

## [0.1.0] - 2026-08-17

First public cut.

### Added
- Seam-1 CanonicalTrace schema (1.1.0) with committed JSON-Schema artifact.
- OTel GenAI OTLP-JSON adapter (dialect-pinned otel-genai/1.42.0): reject-narrow
  ingestion with an 18-row named degradation contract (docs/contract.md),
  evidence-tiered joins (explicit > nested > content-mined; heuristic never
  assigned), JSONL/array/document input, permissive wire scalars.
- `weir gauge` evidentiary-coverage report with capability ladder and
  `--sample` zero-setup demo; `weir scan` with witness-path finding blocks
  and CI exit-code contract (0/1/2, test-backed).
- Paired synthetic generator (weir-tracegen): presets, degradation dials,
  corrupt corpus, byte-for-byte adapter equivalence acceptance.
- Foreign protojson JSONL capture fixture with derived ledger snapshot.
- Determinism (G1) and no-network (G3) harnesses; four import-linter
  contracts; remediation-source audit with drift pin.
