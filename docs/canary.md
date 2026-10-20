# weir canary judge: the canary check contract

> **Contract only.** `weir canary judge` is not implemented yet. This
> document is the contract its implementation, its tests and every canary
> fixture are judged against. Where code and this text disagree once the
> judge lands, one of them is a bug.

A canary check plants unique fake credentials where real ones live, runs a
program's own flows with its telemetry exported to a local receiver, and
asks one question of the capture: did any planted value reach it? Because
the check knows every value it planted, the answer is an exact match, not a
pattern guess. The catalog's credential patterns play no part in the
verdict.

The check has two parts with a hard line between them:

- **`weir canary judge`**, a command in weir-scan. It reads a canary
  ledger (placement ids plus the fake values planted there) and the
  captured telemetry, and reports every placement whose value, or an
  encoded form of it, appears anywhere in the capture. It names the
  placement and where it was found, never a value or any fragment of one.
- **The canary runner** (separate package, name pending). It generates and
  plants the canaries, writes the ledger, runs the flows against a local
  mock, writes the capture, and calls the judge.

This document defines placement kinds, the encoded forms the judge
matches, the ledger and report schemas, coverage states and exit codes.

## The boundary

| | the judge (`weir canary judge`, in weir-scan) | the canary runner (separate package, name pending) |
| --- | --- | --- |
| does | reads a ledger and capture files, prints a report | plants canaries, runs the mock and the flows, writes ledger and capture, calls the judge |
| network | **none**: opens no socket, binds nothing, resolves nothing | a mock bound to `127.0.0.1` only; every other destination is refused |
| processes | starts none | runs each flow under `env -i` with an allowlisted environment |
| writes | nothing but its report on stdout and errors on stderr | the ledger (mode 0600, in the job's temporary directory, deleted after judging), the capture, its own reports |
| reads | only the ledger and the capture paths it is given; no environment variable changes its output | the maintainer's config and the flows' output |
| determinism | a pure function of its input bytes; no clock, no randomness, no model | canary values are random per run (seedable for local reproduction); the mock's replies are scripted |

- The judge stays inside weir-scan's no-network rule: the analysis path
  opens no sockets, and the whole suite runs with socket construction
  blocked (`tests/_harness/g3.py`). The judge is one more command under that
  block.
- The mock opens a loopback socket, so it lives in the runner, never in
  weir-scan. weir never imports the runner. That is enforced the same way
  the engine is kept from importing `weir-tracegen`: an import-linter
  `forbidden` contract in `pyproject.toml`, added with the runner.
- The runner runs on a developer's machine or a CI runner only. It is a
  test-time dependency, never imported by production code, and its mock and
  telemetry receiver exist only for the length of one check run. weir ships
  no capture SDK or collector into production systems.
- **Fake data only.** A ledger holds only fake values: canaries the runner
  generated, tokens the mock minted, and values attributed to one of those
  (see [Runtime values](#runtime-values)). It never holds a real
  credential, and no canary is ever sent to a real provider: the mock
  answers every API the flow is pointed at and refuses every other host.
  The judge cannot tell a fake value from a real one, so this is the
  runner's obligation and the user's.
- Ledgers and captures that hold provider-shaped canaries are never
  committed to a public repository. Public secret scanning would report a
  realistic canary to the provider as a leaked key. Fixtures committed to
  this repository use values with no real provider prefix.

## Running it

```sh
weir canary judge --ledger FILE --otlp PATH [--otlp PATH]... [--json] [PATH...]
```

| option | meaning |
| --- | --- |
| `--ledger` | **Required.** The canary ledger (`canary-ledger/1`, below). |
| `--otlp` | **Required, repeatable.** A telemetry file, or a directory of them: OTLP/JSON export requests, one per line. Only these count toward completeness. |
| `PATH` | Zero or more further capture files or directories, such as non-OTLP telemetry bodies and each flow's stdout and stderr. They are swept for canaries and never count toward completeness. |
| `--json` | Print the `canary-report/1` JSON report instead of the text report. |

A directory, under either role, is read recursively in sorted path order. A
symbolic link inside it is not followed, and is reported as not scanned.
Every other entry must be a readable regular file or directory: an entry
that cannot be opened or read in full, vanishes during the read, or is a
FIFO, socket or device is exit 2 naming the path, exactly like an
unreadable path given on the command line. A file reached through more than
one given path is exit 2. A capture the judge cannot read in full would
leave a value unsearched, so no part of it is ever skipped silently.

There are no tuning flags: which forms are matched, and what counts as
complete, is fixed by this document so that every run of every user means
the same thing.

## Placements and kinds

A **placement** is one place a credential can live in the program under
test, holding one canary. Each placement has a unique id (for example
`env.SEARCH_API_KEY` or `runtime.oauth.access_token#1`), so a hit names its
source. A run plants **one unique value per placement**: two placements
never share a value, or a hit could not say which one leaked.

The kind records how the value got there. The judge matches every kind the
same way; the kind tells the runner how to plant and exercise it and tells
a reader what the hit means.

| kind | where the canary lives | usually exercised by |
| --- | --- | --- |
| `env` | the flow's launch environment, under the variable the software reads | `request` |
| `code` | passed explicitly by the flow to a constructor or call; in subprocess mode the flow reads it from a variable the runner names | `request` |
| `tool-field` | a tool's own credential field, set through `env` or `code` | `request` or `egress` |
| `client-kwargs` | a client's keyword arguments or default headers | `request` |
| `mock-oauth` | a value one of the mock's OAuth endpoints issued during the run: an authorization code, device code, access token, refresh token or ID token; ids `runtime.oauth.<token>#<n>`, `<token>` one of `code`, `device_code`, `access_token`, `refresh_token`, `id_token` | `minted` |
| `oauth-client-secret` | the client secret in the flow's OAuth client configuration | `request` |
| `observed` | a credential field the mock received that holds no needle of any ledger value but verifies against one, such as a signed assertion the software derived in process from a planted key; ids `observed.<endpoint>.<field>#<n>` | `request` |
| `registered` | a token the flow minted in process from a canary with no server involved, handed to the runner's test-only registration API and attributed by the same rule | `assertion` |
| `mcp` | an MCP server's environment or HTTP header | `request` |
| `exporter-auth` | the telemetry exporter's own authentication header; it belongs on the export request's header and must never appear in exported content | `request` |
| `url-userinfo` | the password in a URL's userinfo (a database DSN, for example) | `request` |
| `settings-file` | a settings file the software reads directly (a dotenv file, for example), not the process environment | `request` |

### Runtime values

Three kinds come into being during the run, and each enters the ledger as
it appears:

- Every value the mock's OAuth endpoints issue is a `mock-oauth`
  placement, added to the ledger **before** the reply that hands it to the
  program.
- An `observed` or `registered` value is created by the program, so it is
  added when it appears: when the mock receives it, or when the flow
  registers it. Either way it is only ever a value derived from a fake.

The mock inspects a fixed set of **credential fields** in every request it
receives: the `Authorization` and `Proxy-Authorization` headers (the
credential after the scheme name), the API-key header each mocked endpoint
declares in the runner's configuration, and the OAuth form fields
`client_secret`, `client_assertion`, `assertion`, `code`, `device_code`,
`refresh_token`, `subject_token`, `actor_token` and `password`. No other
header or field is a credential field; a PKCE `code_verifier`, for example,
is not. Each credential field value is handled by the first rule that
applies:

1. **It holds a needle** of one or more ledger values. The mock records
   `request` evidence for each of those placements and stores nothing else:
   a received value is never added as a placement, so a composite such as a
   cookie or a Basic value never enters the ledger.
2. **It verifies against** a ledger value, as a signature made with a
   planted key or an HMAC under a planted secret does. This is the only way
   a new value is **attributed**: the mock adds it as an `observed`
   placement whose `derived_from` names that placement, with `request`
   evidence for both.
3. **Anything else** is never written by the mock, to the ledger or to any
   record of its own. The mock writes an `unexpected` record naming only
   its endpoint and field, and the run is incomplete
   (`unexpected_credential`). A flow that sends a credential no canary
   accounts for has left the check's premise, so it fails visibly instead
   of passing.

The registration API applies the same rules to the value it is handed:
`assertion` evidence for a value holding a needle, a `registered` placement
for a value that verifies against a ledger value, and otherwise a refused
call, so the flow sees the failure, and an `unexpected` record with id
`unexpected.registered#<n>`.

The mock and the registration API control only their own records. Request
headers never enter the capture, but if the program itself logs or exports
a credential, it is in the program's own capture files and output like
anything else the program emits.

### Canary values

- Planted values follow a shapes registry so that software checking a key's
  prefix or length accepts them: a provider's documented prefix followed by
  random characters from `[A-Za-z0-9]` only. JSON and URL escaping leave
  such a value unchanged. Runtime tokens may hold other characters, which is
  why the judge matches escaped forms at all.
- A value never contains `FAKE`, `TEST`, `EXAMPLE`, `DEMO`, `PLACEHOLDER` or
  `REDACTED`. weir's catalog demotes values with those words, which would
  distort any comparison with the pattern scan on the same capture.
- Values come from a CSPRNG, fresh each run.

## The encoded forms

For each placement the judge builds a set of **needles**: byte strings,
each one a form of the value's UTF-8 bytes. A capture string or byte range
that contains a needle is a hit, reported under that needle's form name.
Identical needles from different forms are kept once, under the first form
in this table's order.

| form | needles | why |
| --- | --- | --- |
| `raw` | the value's UTF-8 bytes | the value as it is |
| `json` | the value as JSON string content: `"` and `\` escaped; control characters as `\b \f \n \r \t` or `\u00XX`. Variants: `/` kept or written `\/`; non-ASCII characters kept or written `\uXXXX` (surrogate pairs above U+FFFF) with lowercase or uppercase hex | a value inside a JSON document that was itself stored as a string |
| `json2` | each `json` needle escaped once more by the base rule | JSON inside a string inside JSON |
| `url` | percent-encoding of every byte outside `A-Za-z0-9-._~`. Variants: hex digits uppercase or lowercase; `/` encoded or kept; space as `%20` or `+` | query strings, form bodies, URL userinfo |
| `base64` | the **core** of the standard-alphabet base64 encoding at byte offsets 0, 1 and 2 (below) | a value inside a larger encoded blob, such as an HTTP Basic authorization value |
| `base64url` | the same cores in the URL-safe alphabet (`-` and `_` in place of `+` and `/`) | JWT segments and URL-safe encodings |
| `hex` | the value's bytes as hex, lowercase and uppercase | byte dumps and hex-encoded fields |

**The base64 core.** A value inside a larger plaintext starts at some byte
offset, and its base64 characters differ with that offset modulo 3. For
`k` in 0, 1 and 2, take `k` filler bytes followed by the value's `n`
bytes, encode them, and keep only the characters whose 6 bits all come
from the value: character `i` is kept when `6i >= 8k` and
`6i + 6 <= 8(k + n)`. Those characters are the same whatever bytes surround
the value, so the core matches the value at that alignment inside any
base64 blob, padded or not.

Matching is exact and case-sensitive, except that `hex` and the
percent-escapes of `url` are matched in both letter cases as listed.

### What the judge does not claim

A clean result is evidence about the flows that ran, the placements that
were planted and the forms above. The judge does not match:

- a fragment of a value: a truncated, split or partially masked value is not
  a hit;
- a value that was hashed, encrypted or compressed;
- forms composed beyond those listed (URL-encoded base64, for example),
  other text encodings (UTF-16), line-wrapped base64 or HTML entities;
- telemetry that never reached the capture.

## The ledger (`canary-ledger/1`)

JSON Lines, UTF-8, one object per line, every line ending in `\n`. The
runner creates it with mode 0600 in the job's temporary directory, and
appends to it during the run (the mock and the registration API add
runtime placements, `exercised` evidence and `unexpected` records). Writers
append whole lines.

The first line is the header; every other line is a record with a `type`:

```json
{"schema": "canary-ledger/1"}
{"type": "placement", "id": "env.SEARCH_API_KEY", "kind": "tool-field", "value": "<fake value>", "required": true}
{"type": "placement", "id": "runtime.oauth.access_token#1", "kind": "mock-oauth", "value": "<fake value>"}
{"type": "exercised", "placement": "runtime.oauth.access_token#1", "evidence": "minted"}
{"type": "placement", "id": "observed.search.x-signature#1", "kind": "observed", "value": "<fake value>", "derived_from": "env.SEARCH_API_KEY"}
{"type": "unexpected", "id": "unexpected.search.authorization#1"}
{"type": "flow", "id": "quickstart", "status": "ok"}
```

Every **id** (a placement, flow or unexpected id) is 1 to 128 characters
from `[A-Za-z0-9._:#/-]`, unique among the records of its type, and holds
no run of 8 or more consecutive characters of any value in the ledger. Ids
are printed in both reports, so this rule is what keeps them value-free and
one line each.

| record | field | type | meaning |
| --- | --- | --- | --- |
| header | `schema` | string | `"canary-ledger/1"` |
| `placement` | `id` | string | an id |
| | `kind` | string | one of the kinds above |
| | `value` | string | the fake value, at least 16 characters, unique in the ledger |
| | `required` | boolean | optional, default `false`: the run is incomplete unless this placement is exercised or leaked |
| | `derived_from` | string | required on `observed` and `registered` placements and absent on every other kind: the id of the other placement, defined in this ledger, that the value verifies against |
| `exercised` | `placement` | string | a placement id defined in this ledger, on any line |
| | `evidence` | string | `request` (a credential field the mock received holds a needle of the value, or verifies against it), `minted` (the mock issued it), `egress` (the flow tried to reach the placement's provider host and was refused), `assertion` (an in-process check saw the value used) |
| `flow` | `id` | string | the flow's id, an id |
| | `status` | string | `ok`, `failed` (crashed or exited non-zero), `timeout` or `skipped` |
| `unexpected` | `id` | string | an id, `unexpected.<endpoint>.<field>#<n>` for a credential field the mock could not attribute, or `unexpected.registered#<n>` for a refused registration. The record never carries the value |

The ledger is strict. The judge exits 2, naming the ledger and the line
number, never content, when: the file cannot be read; it is readable by
group or others on a POSIX system; the header is missing or names another
schema; a line is not a JSON object or does not end in a newline; a record
has an unknown `type`, an unknown field, a wrong type or an unknown
`kind`, `evidence` or `status`; an id breaks the id rule; a value repeats
or is shorter than 16 characters; an `exercised` record names no defined
placement; a `derived_from` is missing where required, present where it is
not allowed, or names no other defined placement; or the ledger defines no
placement. A ledger the judge cannot read in full would leave a value
unsearched, so it is never read in part.

## The capture

The capture is every file the runner hands the judge. Each file has one
of two roles, fixed by the command line and never guessed from content:

1. **Telemetry files** (`--otlp`): JSON Lines, every line one OTLP export
   request in the protobuf JSON mapping, a JSON object holding
   `resourceSpans`, `resourceLogs` or `resourceMetrics`. All three signals
   are read. Spans, log records and metric data points read from these
   files are the only telemetry that counts toward completeness.
2. **Swept files** (every other `PATH`): any bytes, such as the body of a
   request to a non-OTLP telemetry endpoint or a flow's captured stdout and
   stderr. A swept file is never parsed, whatever it holds, and nothing in
   it counts toward completeness.

Each file is read this way:

- **The structured walk** (telemetry files). Each line is decoded, and
  every string field and every `stringValue`, plus every `bytesValue` after
  base64 decoding, is matched against every needle. A hit gets a precise
  location.
- **The raw sweep** (every file). The file's bytes, undecoded, are matched
  against every needle. In a telemetry file a raw hit is reported only
  where the structured walk found nothing for the same placement on the
  same line, so a hit is not reported twice.

A line of a telemetry file is the bytes up to and including a `\n`;
nothing after the final `\n` forms a line, so a file ending in `\n` has
no trailing empty line. Bytes after the final `\n` with no `\n` of their
own are a truncated last line. A line that is not an OTLP export request
(it is truncated, does not parse as JSON, is not an object, or holds none
of the three fields in the OTLP/JSON mapping), an empty line included, is
covered by the raw sweep alone, counted under `unparsed_records`, and makes
the run incomplete.

The runner writes OTLP request bodies decompressed, one export request per
line, and does not put request headers in the capture: a credential's
legitimate use as a request header is evidence that it was exercised, not
a leak. A capture file of either role that starts with the gzip magic bytes
is not scanned and makes the run incomplete. A capture path, or any entry
under a capture directory, that cannot be read in full or is not a regular
file or directory is exit 2 (see [Running it](#running-it)).

### Locations

A hit's location is value-free and reads like weir's exposure scan:
`.key` descends into an object or key-value list, `[i]` into an array.

| signal | record | locations within the record |
| --- | --- | --- |
| `traces` | the span: its name and span id | `name`, `traceState`, `attributes.<key>`, `events[<i>].name`, `events[<i>].attributes.<key>`, `links[<i>].traceState`, `links[<i>].attributes.<key>`, `status.message` |
| `logs` | the log record, by its 0-based index in the export request | `body`, `eventName`, `severityText`, `attributes.<key>` |
| `metrics` | the metric, by name | `name`, `description`, `unit`, `metadata.<key>`, `dataPoints[<i>].attributes.<key>`, `dataPoints[<i>].exemplars[<j>].filteredAttributes.<key>` |
| `raw` | none | none: the hit is placed by file and line only |

Any other string field is located by its OTLP/JSON field name. Strings
outside any record (resource and scope attributes, scope name and
version, schema URLs) are reported with no record and a location starting
`resource.` or `scope.`. Nested values extend the location as in
`attributes.app.config.headers[0]`.

**Printing capture-derived text.** A span name, metric name, attribute key,
path segment or capture file name comes from the program under test and may
itself hold a canary. Before any such string is printed it is flattened to
one line (control characters shown as `\xNN`), cut to 200 characters with
`...`, and replaced entirely by `[withheld]` if it contains any needle or any run
of 8 or more consecutive characters of any ledger value. A canary in a
span name is therefore reported as a hit at location `name` of a span
shown as `[withheld]`.

## Coverage states

Every placement ends in exactly one state, in this order of precedence:

| state | evidence | clean? |
| --- | --- | --- |
| `leaked` | at least one hit | no |
| `exercised` | no hit, and at least one `exercised` record | yes |
| `not_exercised` | no hit and no `exercised` record | reported; the run is incomplete if the placement is `required` |

A placement that stayed clean because the code path never touched it is
not evidence of anything, which is why `exercised` needs evidence and why
`not_exercised` is always printed.

The run itself is **incomplete** when any of these holds, each listed as
one reason:

| reason | subject | when |
| --- | --- | --- |
| `required_not_exercised` | the placement id | a `required` placement is `not_exercised` |
| `flow_not_ok` | `<flow id>=<status>`, such as `quickstart=failed` | a `flow` record's status is not `ok` |
| `unexpected_credential` | the `unexpected` record's id | the mock received a credential field, or the registration API was handed a value, that it could not attribute to any placement |
| `not_scanned` | the file | a capture file was not scanned (`compressed`, or a `symlink` inside a capture directory) |
| `unparsed_record` | `<file>:<line>` | a line of a telemetry file is not an OTLP export request |
| `empty_capture` | none | the telemetry files hold no span, log record or metric data point. Swept files never count, whatever they hold |

Silence is never a clean result: an empty capture, a crashed flow, an
unaccounted credential or an untouched required placement fails visibly
instead of passing quietly.

The **result** is `leak` when there is any hit, otherwise `incomplete`
when any reason above holds, otherwise `clean`. A found leak outranks
incompleteness, and the incomplete reasons are still listed.

## Exit codes

| code | result | meaning |
| --- | --- | --- |
| `0` | `clean` | complete, and no canary in the capture |
| `1` | `leak` | at least one canary, in some form, in the capture |
| `2` | none | usage or input error: bad arguments, an unusable ledger, a capture path or directory entry that cannot be read in full or is not a regular file or directory, a file reached through two given paths. No report is printed; the error on stderr names the input and line, never content read from it |
| `3` | `incomplete` | no canary found, but the run is incomplete |

`0`, `1` and `2` follow `weir scan`'s convention (nothing to fail on,
findings, unusable input). The runner exits with
the judge's code, and uses `2` for its own usage and configuration errors.

## The text report

One line per hit, then one line per not-exercised placement, per file not
scanned and per incomplete reason, then the coverage line and the result.
Every output that reaches a verdict carries the coverage line, the clean
one included.

```text
LEAK env.SEARCH_API_KEY file=capture/otlp.jsonl:3 signal=traces span="invoke_agent planner" at=attributes.app.agent.tools form=raw
LEAK oauth.client_secret file=capture/otlp.jsonl:4 signal=traces span="execute_tool fetch" at=events[0].attributes.http.request.header.authorization form=base64
LEAK runtime.oauth.access_token#1 file=capture/flow-quickstart.stderr:41 signal=raw form=raw
not exercised: env.BACKUP_API_KEY
coverage: 4 placements (3 leaked, 0 exercised, 1 not exercised, 1 required), 1 flows (1 ok), 3 files, 12 spans, 0 log records, 6 metric data points, 214 strings, 48210 bytes swept
result: leak
```

Precisely:

- A hit: `LEAK <placement> file=<path>:<line> signal=<signal>`, then
  `span=<quoted name>`, `log=<index>` or `metric=<quoted name>` when there is
  a record, then `at=<location>` when there is one, then `form=<form>`.
  Quoted names use JSON string quoting. `<line>` is where the record starts,
  or, for a raw hit, where the match starts.
- `not exercised: <placement>` for each `not_exercised` placement.
- `not scanned: <path> (<reason>)` for each file not scanned.
- `incomplete: <reason> <subject>` for each incomplete reason.
- `coverage: <P> placements (<L> leaked, <E> exercised, <N> not exercised, <R> required), <F> flows (<K> ok), <files> files, <S> spans, <G> log records, <M> metric data points, <T> strings, <B> bytes swept`
- `result: clean|leak|incomplete`

Lines are sorted (hits by placement, file, line, signal, record, location,
form; the other lists by placement, file or reason), so the same input
gives byte-identical output. The report depends on where values appear,
never on what they are: two runs that plant fresh random values in the same
places print the same report.

## The JSON report (`canary-report/1`)

`--json` prints indented JSON, fields in schema order, lists sorted as in
the text report:

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | `"canary-report/1"` |
| `result` | string | `clean`, `leak` or `incomplete` |
| `exit_code` | integer | `0`, `1` or `3` |
| `hits` | array | one object per hit (below) |
| `placements` | array | `{id, kind, required, state, evidence, hits}`: `state` is `leaked`, `exercised` or `not_exercised`; `evidence` the sorted distinct evidence types; `hits` the count |
| `flows` | array | `{id, status}` |
| `not_scanned` | array | `{file, reason}`; reason `compressed` or `symlink` |
| `incomplete` | array | `{reason, subject}`; `subject` is null for `empty_capture` |
| `coverage` | object | `placements`, `leaked`, `exercised`, `not_exercised`, `required`, `flows`, `flows_ok`, `files`, `files_not_scanned`, `spans`, `log_records`, `metric_data_points`, `unparsed_records`, `strings`, `bytes` |

A hit:

| field | type | meaning |
| --- | --- | --- |
| `placement` | string | the placement id |
| `kind` | string | the placement's kind |
| `file` | string | the capture path, as given or found under a given directory |
| `line` | integer | 1-based line where the record starts, or where a raw match starts |
| `signal` | string | `traces`, `logs`, `metrics` or `raw` |
| `span` | string or null | the span name, printed under the rule above |
| `span_id` | string or null | the span id as lowercase hex |
| `log_record` | integer or null | the log record's 0-based index in its export request |
| `metric` | string or null | the metric name, printed under the rule above |
| `location` | string or null | the location within the record; null for `raw` |
| `form` | string | `raw`, `json`, `json2`, `url`, `base64`, `base64url` or `hex` |

No field of either report can hold a value, a fragment of one, a masked
form (`prefix...last4`), a hash or a fingerprint of a canary. The report
may be uploaded as a CI artifact; the ledger and the capture never are, and
the runner deletes them after judging.

When the judge lands, JSON Schema artifacts for both schemas are generated
from its structs and drift-tested beside the existing ones in
`packages/weir/schema_artifacts/` (`canary-ledger.v1.schema.json`,
`canary-report.v1.schema.json`).

## What the runner owes the judge

The judge's verdict is only as good as its inputs. A runner that uses this
contract:

1. plants one fresh unique value per placement and writes the ledger
   before any flow starts;
2. adds every value the mock's OAuth endpoints issue to the ledger before
   handing it to the program, applies the credential-field rules to every
   received credential field and registered value (evidence for a held
   needle, a new placement only for a verified value, an `unexpected`
   record and no stored value otherwise), and records all other
   `exercised` evidence and one `flow` record per flow;
3. writes OTLP export requests as decompressed OTLP/JSON, one request per
   line, in files it passes with `--otlp`, and every other telemetry body
   and each flow's stdout and stderr as its own capture file, passed as a
   swept `PATH`;
4. relays a flow's own output only after replacing every needle with
   `<canary:PLACEMENT-ID>`;
5. exits with the judge's code, and deletes the ledger and the capture when
   the run ends.

## Testing against this contract

- Every fixture for the judge is derived from this document: plant a value,
  build the form with the definitions above, place it, and expect the hit
  the document says. No expectation is a restated literal.
- Each form has a test that fails when that form's matcher is removed, and
  each incomplete reason a test that fails when its check is removed.
- A determinism test runs the same fixture with two different random
  values and compares the two reports byte for byte.
- Fixtures use prefix-free fake values and are synthetic: no fixture is
  built from a capture of a real framework run.

## Versioning

- `canary-ledger/1` and `canary-report/1` change only with an incompatible
  change. Additive report fields keep the version.
- Adding a form, a kind, an evidence type or an incomplete reason changes
  what a run means, so each is a CHANGELOG entry in the release that ships
  it.
