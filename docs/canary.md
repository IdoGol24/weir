# weir canary judge: the canary check contract

> **The contract.** `weir canary judge` (in `packages/weir/src/weir/canary/`)
> implements this document, and this document is what its implementation,
> its tests and every canary fixture are judged against. Where code and
> this text disagree, one of them is a bug.

A canary check plants unique fake credentials where real ones live, runs a
program's own flows with its telemetry exported to a local receiver and
every outbound request sent to a local mock, and asks one question of the
capture: did any planted value reach a place outside the user's control?
Those places are the program's telemetry (traces, logs, metrics), its
console output, the model provider (prompts and messages) and any other
service or host. Because the check knows every value it planted, the
answer is an exact match, not a pattern guess. The catalog's credential
patterns play no part in the verdict.

The check has two parts with a hard line between them:

- **`weir canary judge`**, a command in weir-scan. It reads a canary
  ledger (placement ids plus the fake values planted there), the captured
  telemetry and console output, and the mock's record of every request the
  program sent, and reports every placement whose value, or an encoded
  form of it, appears anywhere in the capture, or anywhere in a request
  but a credential field of a request to the placement's own provider. It
  names the placement and where it was found (for a request, the sink and
  the field), never a value or any fragment of one.
- **The canary runner** (`weir-run`, a separate package). It generates and
  plants the canaries, writes the ledger, runs the flows against a local
  mock, writes the capture, and calls the judge.

This document defines placement kinds, the encoded forms the judge
matches, the ledger and report schemas, coverage states and exit codes.

## The boundary

| | the judge (`weir canary judge`, in weir-scan) | the canary runner (`weir-run`, a separate package) |
| --- | --- | --- |
| does | reads a ledger and capture files, prints a report | plants canaries, runs the mock and the flows, writes ledger and capture, calls the judge |
| network | **none**: opens no socket, binds nothing, resolves nothing | a mock bound to `127.0.0.1` only, which flows reach through their proxy settings; every proxied request to another host is refused and recorded. On Linux, flows and the mock share a network namespace whose only network is loopback ([Network isolation](#network-isolation)) |
| processes | starts none | runs each flow under `env -i` with an allowlisted environment |
| writes | nothing but its report on stdout and errors on stderr | the ledger (mode 0600, in the job's temporary directory, deleted after judging), the capture (telemetry, flow output and the request capture, deleted after judging), its own reports |
| reads | only the ledger and the capture paths it is given, or with `--sample` the bundled sample; no environment variable changes its output | the maintainer's config and the flows' output |
| determinism | a pure function of its input bytes; no clock, no randomness, no model | canary values are random per run (seedable for local reproduction); the mock's replies are scripted |

- The judge stays inside weir-scan's no-network rule: the analysis path
  opens no sockets, and the whole suite runs with socket construction
  blocked (`tests/_harness/g3.py`). The judge is one more command under that
  block, and an import-linter `forbidden` contract in `pyproject.toml` keeps
  its modules from importing any network, process, clock or randomness
  module, or the trace pipeline.
- The mock opens a loopback socket, so it lives in the runner, never in
  weir-scan. weir never imports the runner. That is enforced the same way
  the engine is kept from importing `weir-tracegen`: an import-linter
  `forbidden` contract in `pyproject.toml`, added with the runner.
- The runner runs on a developer's machine or a CI runner only. It is a
  test-time dependency, never imported by production code, and its mock and
  telemetry receiver exist only for the length of one check run. weir ships
  no capture SDK or collector into production systems.
- **Fake data only.** A ledger holds only runner-generated fake values: the
  canaries the runner plants and the credentials its mock's OAuth endpoints
  issue (see [Runtime values](#runtime-values)). It never holds a real
  credential. Flows reach the mock through their proxy settings: the mock
  answers every API the flow is pointed at and refuses every proxied request
  to another host. On Linux the runner also runs the flows in a network
  namespace with no route out, so a client that ignores proxy settings
  reaches nothing ([Network isolation](#network-isolation)). Where it cannot
  isolate them, such a client can connect to a real provider directly, and
  the report says the network was not isolated. The judge cannot tell a
  fake value from a real one, so keeping canaries away from real providers
  is the runner's obligation and the user's.
- Ledgers and captures that hold provider-shaped canaries are never
  committed to a public repository. Public secret scanning would report a
  realistic canary to the provider as a leaked key. Fixtures committed to
  this repository use values with no real provider prefix.

## Running it

```sh
weir canary judge --ledger FILE --otlp PATH [--otlp PATH]... [--requests PATH]... [--json] [PATH...]
weir canary judge --sample [--json]
```

| option | meaning |
| --- | --- |
| `--ledger` | **Required** unless `--sample`. The canary ledger (`canary-ledger/1`, below). |
| `--otlp` | **Required** unless `--sample`; repeatable. A telemetry file, or a directory of them: OTLP/JSON export requests, one per line. Only these count toward completeness. |
| `--requests` | Optional; repeatable. A request capture file (`canary-requests/1`, see [The request capture](#the-request-capture-canary-requests1)), or a directory of them: every request the mock received. Judged by the attribution rules there. Never counts toward completeness. |
| `PATH` | Zero or more further capture files or directories, such as non-OTLP telemetry bodies and each flow's stdout and stderr. They are swept for canaries and never count toward completeness. |
| `--json` | Print the `canary-report/1` JSON report instead of the text report. |
| `--sample` | Judge the bundled sample instead of given files: a ledger of prefix-free fake values and one OTLP/JSON capture, shipped in the package, with one planted value in a span attribute. It exits `1` and shows what a leak report looks like with no other input. It takes no `--ledger`, `--otlp`, `--requests` or `PATH`. The sample ledger is package data, so the mode-0600 rule below does not apply to it. |

A directory, under any role, is read recursively in sorted path order. A
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
| `env` | the flow's launch environment, under the variable the software reads | `request` or `egress` |
| `code` | passed explicitly by the flow to a constructor or call; in subprocess mode the flow reads it from a variable the runner names | `request` or `egress` |
| `file` | a file the runner wrote where a program usually finds secrets, in a scratch project or scratch home it made for the run, such as a project `.env` or a credentials file | `tool_call` |
| `mock-oauth` | a credential one of the mock's OAuth endpoints issued during the run: an authorization code, device code, access token, refresh token or ID token; ids `runtime.oauth.<token>#<n>`, `<token>` one of `code`, `device_code`, `access_token`, `refresh_token`, `id_token` | `minted` |

### A placement's own provider

A placement may name where it legitimately goes, its **own provider**, in
two ways:

- its **providers**: mocked endpoints by id, `model` (the mock's model
  API), `oauth` (its OAuth endpoints), `otlp` (its telemetry receiver) or
  the id of an endpoint the runner's configuration declares;
- its **provider host**: the host name of its real provider, which the
  mock refuses.

A `served` request to one of its providers, and a `refused` or `connect`
request whose host is its provider host, is a request to its own
provider. Every other request is not (see
[The request capture](#the-request-capture-canary-requests1)). Only the
[credential fields](#runtime-values) of a request to its own provider are
where the placement legitimately goes: the same value anywhere else in
that request, such as the prompt or messages of a request to the model
API, is a leak. A planted placement names at most one provider endpoint,
from the runner's configuration. A `mock-oauth` placement's providers are
`oauth` and every endpoint the configuration declares: the mock issued it to the program
for the program's own APIs, so the model, the telemetry receiver and
every other host are somewhere else. A placement with no provider belongs
in no request: any request that holds it is a leak.

**Reserved for a later release.** These kinds have no rules in this version,
and a ledger that names one is rejected as an unknown `kind`: `tool-field`,
`client-kwargs`, `oauth-client-secret`, `mcp`, `exporter-auth`,
`url-userinfo`, `settings-file`, `observed` (a value the program derives
from a canary and sends to the mock), `registered` (a token the program
mints in process from a canary), signing-key placements, and credentials
issued by a mocked endpoint other than the mock's OAuth endpoints.
Attribution of a derived value by verification, such as a signature made
with a planted key, is reserved with them.

### Runtime values

One kind comes into being during the run. Every credential the mock's OAuth
endpoints issue (an authorization code, device code, access, refresh or ID
token) is a fresh runner-generated fake value, added to the ledger as a
`mock-oauth` placement, with `minted` evidence, **before** the reply that
hands it to the program. The other fields of an OAuth reply, such as
`token_type`, `expires_in`, `scope`, `user_code` and `verification_uri`, are
not credentials and are never ledgered. No value the program creates ever
enters the ledger.

The mock inspects a fixed set of **credential fields** in the requests it
receives:

- on every mocked endpoint, the whole value of the `Authorization` and
  `Proxy-Authorization` headers, scheme name included;
- on every mocked endpoint, the credential fields that endpoint declares
  in the runner's configuration: one or more headers, query parameters or
  body fields;
- on the mock's model API, the `x-api-key` header, where the Anthropic
  Messages API carries its key;
- on the endpoints the runner's configuration declares as the mock's OAuth
  endpoints only, the form fields `client_secret`, `client_assertion`,
  `assertion`, `code`, `device_code`, `refresh_token`, `subject_token`,
  `actor_token` and `password`.

No other header, parameter or field is a credential field; a PKCE
`code_verifier`, for example, is not. Each credential field value is
handled by the first rule that applies:

1. **It holds a needle** of one or more ledger values. The mock writes
   nothing about it to the ledger: whether the request went to each
   placement's own provider is the judge's call, from the request capture,
   where the mock names each request's credential fields.
   A received value is never added as a placement, so a composite such as
   a cookie or a Basic value never enters the ledger.
2. **Anything else** is never written to the ledger. The mock writes an
   `unexpected` record naming only its endpoint and field, and the run is
   incomplete (`unexpected_credential`). A flow that sends a credential no canary
   accounts for has left the check's premise, so it fails visibly instead
   of passing.

Separately from these rules, the mock records every request it receives,
headers and body included, in the request capture (see
[The request capture](#the-request-capture-canary-requests1)): the one
record of request content the mock keeps. Like every capture file it holds
what the program sent, an unaccounted credential included; it is read
only by the judge, which prints from it only a host and the names of
headers, parameters and fields, under the printing rule; and the runner
deletes it with the rest of the capture. If the program itself logs or
exports a credential, it is in the program's own capture files and output
like anything else the program emits.

### Canary values

- Planted values follow a shapes registry so that software checking a key's
  prefix or length accepts them: a provider's documented prefix followed by
  random characters from `[A-Za-z0-9]` only. JSON and URL escaping leave
  such a value unchanged. A `mock-oauth` value may hold other characters
  where its reply's format calls for them, which is why the judge matches
  escaped forms at all.
- Signing keys are not planted in the first release: a private key or
  signing secret cannot take this shape, and its placements are reserved
  (above).
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
- telemetry that never reached the capture;
- a value in another placement's declared field of a `refused` or
  `connect` request: for such a request the credential fields of every
  placement that shares the request's provider host are merged, so when
  two placements share one `provider_host` but belong to different
  endpoints (or one has no provider), one placement's value in the other's
  declared field counts as `egress`, not a leak.

## The ledger (`canary-ledger/1`)

JSON Lines, UTF-8, one object per line, every line ending in `\n`. The
runner creates it with mode 0600 in the job's temporary directory, and
appends to it during the run (the mock adds `mock-oauth` placements,
`exercised` evidence and `unexpected` records). Writers append whole
lines.

The first line is the header; every other line is a record with a `type`:

```json
{"schema": "canary-ledger/1"}
{"type": "placement", "id": "env.SEARCH_API_KEY", "kind": "env", "value": "<fake value>", "required": true, "providers": ["search"], "provider_host": "api.search.example"}
{"type": "placement", "id": "runtime.oauth.access_token#1", "kind": "mock-oauth", "value": "<fake value>", "providers": ["oauth", "search"]}
{"type": "exercised", "placement": "runtime.oauth.access_token#1", "evidence": "minted"}
{"type": "unexpected", "id": "unexpected.search.authorization#1"}
{"type": "flow", "id": "quickstart", "status": "ok"}
{"type": "network", "isolated": true}
{"type": "direct", "flow": "quickstart", "protocol": "tcp", "target": "203.0.113.7:443", "attempts": 1}
```

Every **id** (a placement, flow or unexpected id) is 1 to 128 characters
from `[A-Za-z0-9._:#/-]`, unique among the records of its type, and holds
no run of 6 or more consecutive characters of any value in the ledger. Ids
are printed in both reports, so this rule is what keeps them value-free and
one line each.

| record | field | type | meaning |
| --- | --- | --- | --- |
| header | `schema` | string | `"canary-ledger/1"` |
| `placement` | `id` | string | an id |
| | `kind` | string | one of the kinds above |
| | `value` | string | the fake value, at least 16 characters, unique in the ledger |
| | `required` | boolean | optional, default `false`: the run is incomplete unless this placement is exercised or leaked |
| | `providers` | array of strings | optional, default empty: the endpoint ids of the placement's [own provider](#a-placements-own-provider), each 1 to 40 characters from `[A-Za-z0-9_-]` |
| | `provider_host` | string | optional: the host name of the placement's own provider, 1 to 253 characters from `[A-Za-z0-9._:-]`, matched without regard to letter case |
| `exercised` | `placement` | string | a placement id defined in this ledger, on any line |
| | `evidence` | string | `request` (a credential field of a request to the placement's own provider held a needle of the value), `minted` (the mock issued it), `egress` (the flow tried to reach the placement's provider host and was refused), `tool_call` (the mock's model asked the program, in a tool call, for the place the placement lives, such as reading its file or printing its variable, and the program answered that tool call, with a result or a refusal). The judge also derives `request` and `egress` from the request capture; a runner without one may record them here |
| `flow` | `id` | string | the flow's id, an id |
| | `status` | string | `ok`, `failed` (crashed or exited non-zero), `timeout` or `skipped` |
| | `telemetry` | boolean | optional, default `true`: the flow is expected to export telemetry. `false` for a flow whose program has its telemetry off, so an empty telemetry capture says nothing about it |
| `unexpected` | `id` | string | an id, `unexpected.<endpoint>.<field>#<n>`: a credential field the mock received that held no needle of any ledger value. The record never carries the value |
| `network` | `isolated` | boolean | the flows ran in a network with no route out but loopback ([Network isolation](#network-isolation)) |
| | `required` | boolean | optional, default `false`: the run is incomplete unless `isolated` |
| `direct` | `flow` | string | the id of the flow that made the attempt, defined by a `flow` record on any line |
| | `protocol` | string | `tcp` (a connection opened to an address), `udp` (a datagram sent to an address) or `dns` (a name looked up) |
| | `target` | string | `<address>:<port>` (an IPv6 address in brackets) for `tcp` and `udp`, the name asked for for `dns`; 1 to 260 characters from `[A-Za-z0-9._:[]-]` |
| | `attempts` | integer | how many times, at least 1 |

A ledger has at most one `network` record. Without one, nothing says the
flows were isolated, so the judge reports them as not isolated. A `direct`
record is a connection attempt that isolation blocked, so it needs a
`network` record that says `isolated`, and its flow, protocol and target
are unique among `direct` records. A `direct` record never carries what the
attempt would have sent.

The ledger is strict. The judge exits 2, naming the ledger and the line
number, never content, when: the file cannot be read; it is readable by
group or others on a POSIX system; the header is missing or names another
schema; a line is not a JSON object or does not end in a newline; a record
has an unknown `type`, an unknown field, a wrong type or an unknown
`kind`, `evidence` or `status`; an id, provider or provider host breaks
its rule; a value repeats
or is shorter than 16 characters; an `exercised` record names no defined
placement; a second `network` record; a `direct` record that names no
defined flow, repeats another's flow, protocol and target, or appears
without a `network` record that says `isolated`; or the ledger defines no
placement. A ledger the judge cannot
read in full would leave a value unsearched, so it is never read in part.

## The capture

The capture is every file the runner hands the judge. Each file has one
of three roles, fixed by the command line and never guessed from content:

1. **Telemetry files** (`--otlp`): JSON Lines, every line one OTLP export
   request in the protobuf JSON mapping, a JSON object holding
   `resourceSpans`, `resourceLogs` or `resourceMetrics`. All three signals
   are read. Spans, log records and metric data points read from these
   files are the only telemetry that counts toward completeness.
2. **Swept files** (every other `PATH`): any bytes, such as the body of a
   request to a non-OTLP telemetry endpoint or a flow's captured stdout and
   stderr. A swept file is never parsed, whatever it holds, and nothing in
   it counts toward completeness.
3. **Request files** (`--requests`): the mock's record of every request it
   received, judged by the attribution rules of
   [The request capture](#the-request-capture-canary-requests1). Nothing in
   them counts toward completeness.

Telemetry and swept files are read this way:

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
line, and keeps request headers out of the telemetry and swept files:
every request's headers go to the request capture, where a credential's
use in a credential field of a request to its own provider is evidence
that it was exercised, not a leak. A capture file of any role that starts
with the gzip magic bytes is not scanned and makes the run incomplete. A capture path, or any entry
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
path segment, request host, header, parameter or field name, capture file
name or `direct` target comes from the program under test and may
itself hold a canary. Before any such string is printed it is flattened to
one line (control characters shown as `\xNN`), cut to 200 characters with
`...`, and replaced entirely by `[withheld]` if it contains any needle or
any run of 6 or more consecutive characters of any ledger value. A canary in a
span name is therefore reported as a hit at location `name` of a span
shown as `[withheld]`.

## The request capture (`canary-requests/1`)

The mock records every request it receives, before answering it, as one
line of a request capture file that the runner passes with `--requests`.
JSON Lines, UTF-8, every line ending in `\n`, appended in whole lines. The
first line is the header; every other line is one request:

```json
{"schema": "canary-requests/1"}
{"outcome": "served", "endpoint": "model", "host": "127.0.0.1", "port": 41817, "method": "POST", "path": "/v1/chat/completions", "query": "", "headers": [["Host", "127.0.0.1:41817"], ["Authorization", "Bearer <fake value>"]], "body": "<base64>", "unread": null, "credential_fields": [["header", "authorization"], ["header", "proxy-authorization"], ["header", "x-api-key"]]}
{"outcome": "refused", "endpoint": null, "host": "collector.example", "port": 80, "method": "POST", "path": "http://collector.example/ingest", "query": "", "headers": [["Host", "collector.example"]], "body": "<base64>", "unread": null, "credential_fields": [["header", "authorization"], ["header", "proxy-authorization"]]}
{"outcome": "connect", "endpoint": null, "host": "api.example", "port": 443, "method": "CONNECT", "path": null, "query": null, "headers": [["Host", "api.example:443"]], "body": null, "unread": null, "credential_fields": [["header", "authorization"], ["header", "proxy-authorization"]]}
```

| field | type | meaning |
| --- | --- | --- |
| `outcome` | string | `served` (the mock answered as itself: a mocked endpoint, or a 404 for a path it does not mock), `refused` (a request for another host, refused with 403 and forwarded nowhere: a plain-HTTP request, or an HTTPS request the runner's TLS stub decrypted) or `connect` (a connection to another host that carried no visible content: a `CONNECT` refused with 403 before any byte of the tunnel, or a TLS connection the stub could not decrypt) |
| `endpoint` | string or null | for `served`, the endpoint that answered: `model`, `oauth`, `otlp` or a declared endpoint's id; null for a path the mock does not mock, and for `refused` and `connect` |
| `host` | string | the destination host as received, letter case kept: the mock's own address for `served`, the requested host otherwise |
| `port` | integer | the destination port |
| `method` | string | the request method; `TLS` for a TLS connection the stub could not decrypt |
| `path` | string or null | the request target as received, up to its first `?`, percent-escapes kept: the path, or for an absolute-form request the whole URL, userinfo included; null for `connect` |
| `query` | string or null | the request target after its first `?`, empty when there is none; null for `connect` |
| `headers` | array | every header as a `[name, value]` pair of strings, in the order received |
| `body` | string or null | the body after its `Content-Encoding` is removed, base64-encoded (standard alphabet, padded); empty when there is no body. Null for a `connect`, for an OTLP export (its content is the telemetry capture) and for a declared endpoint that keeps its bodies as swept capture files: a body judged elsewhere is not judged twice |
| `unread` | string or null | why the body could not be judged in full: `encoding` (a `Content-Encoding` the mock cannot remove; `body` holds the bytes as received), `too_large` (over the mock's 64 MiB limit; `body` is null) or `error` (the mock failed while reading or answering the request; `body` is null); null otherwise |
| `credential_fields` | array | the request's [credential fields](#runtime-values), each a `[location, name]` pair: `location` is `header`, `query` or `body`, and a header name is matched without regard to letter case. The `Authorization` and `Proxy-Authorization` headers of every request, then the fields of its endpoints: for a `served` request the endpoint that answered it, and for a `refused` or `connect` request the providers of every placement whose provider host is its host (matched without regard to letter case), since those endpoints stand in for that host. An endpoint's fields are those it declares in the runner's configuration, on the mock's model API also the `x-api-key` header, and on the mock's OAuth endpoints also their form fields. A `body` field is a form field or a member of a top-level JSON object, everything under the member included |

### Attribution

For each request and each placement, the judge searches every part of the
request for every needle of the placement: the method; the host; the path,
as received and percent-decoded; each query parameter's name and value,
percent-decoded with `+` as a space, and the whole query as received; each
header's name and value; and the body, decoded from base64. A body that is
a JSON document is searched string by string, member names included; a
body whose request has a `Content-Type` of
`application/x-www-form-urlencoded` is searched field by field like a
query; and every body is also searched as a whole. Then:

- **Its own provider's credential fields.** A needle found in one of the
  `credential_fields` of a request to the placement's
  [own provider](#a-placements-own-provider) is not a hit. A `served`
  request to one of its providers that holds a needle there is `request`
  evidence that the placement was exercised. Any `refused` or `connect`
  request to its provider host is `egress` evidence, whatever it holds,
  and a needle in its credential fields, such as the `header:x-api-key`
  or `query:key` its own endpoint declares, is not a hit there either.
- **Anywhere else.** A needle found anywhere else in any request is a hit:
  a leak to that request's **sink**. That includes every other part of a
  request to its own provider: a model key copied into
  `body.messages[0].content` of a request to the model API is a leak to
  `model`, a key in the body of a request to its own declared API,
  outside the fields that API declares, is a leak to that API's id, and a
  key in the body of a refused request to its provider host is a leak to
  `<host> (blocked)`.

| sink | the request |
| --- | --- |
| `model` | to the mock's model API: a prompt, messages, or a credential sent to the model provider |
| `oauth` | to the mock's OAuth endpoints |
| `otlp` | to the mock's telemetry receiver: a header or the query of an export |
| `<declared api>` | to an endpoint the runner's configuration declares, by its id: a credential sent to the wrong service |
| `unmocked` | to the mock, at a path it does not mock |
| `<host> (blocked)` | a `refused` plain-HTTP request, or a `connect`, for another host; `<host>` is the record's host in lower case, under the printing rule |

A `connect` has no visible content: the mock refuses the tunnel before
the client sends any byte through it. It is reported as a **blocked
connection attempt**, by host and port, and in the coverage; it is never a
leak by itself. Its host and headers are still searched like any
request's. Each `refused` request is listed the same way, as a blocked
request, whatever its content.

A hit in a request is located by part:

| location | the part |
| --- | --- |
| `method` | the method |
| `host` | the destination host |
| `path` | the request target up to its `?`, as received or percent-decoded |
| `query.<name>` | a query parameter, by its percent-decoded name |
| `query` | the whole query, where no parameter of the request held a needle of the placement |
| `headers.<name>` | a header, by its name in lower case |
| `body.<path>` | a string or member name in a JSON body: `.key` into an object, `[i]` into an array, as in `body.messages[0].content` |
| `body.<name>` | a field of a form body, by its percent-decoded name |
| `body` | the body as a whole, where no JSON string or form field of the request held a needle of the placement |

A name or host is printed under the printing rule, so one that itself
holds a needle reads `[withheld]`. One printed in another form than it was
received (a header name or host in lower case, a parameter or field name
percent-decoded) is withheld when either form would be.

The judge exits 2, naming the file, when a request capture file is empty
or its first line is not the header. A later line that is not a request
record (it is truncated, does not parse, is not an object, or breaks the
field table above) cannot be attributed: it is covered by the raw sweep
alone, so any needle in it is a `raw` hit with no sink, and it is counted
under `unparsed_records` and makes the run incomplete. A record with
`unread` set is judged like any other, its body as given, and also makes
the run incomplete: it names a body the judge could not search in full.

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
| `unexpected_credential` | the `unexpected` record's id | the mock received a credential field that held no needle of any ledger value |
| `not_scanned` | the file | a capture file was not scanned (`compressed`, or a `symlink` inside a capture directory) |
| `unparsed_record` | `<file>:<line>` | a line of a telemetry file is not an OTLP export request, or a line of a request capture file is not a request record or names a body the judge could not search in full (`unread`) |
| `empty_capture` | none | the telemetry files hold no span, log record or metric data point, and the ledger has no `flow` record or at least one that does not say `telemetry` is `false`. Swept files never count, whatever they hold |
| `network_not_isolated` | none | the `network` record says `required` and not `isolated`: the run required isolation and did not have it |
| `direct_connection` | `<flow>=<protocol>:<target>`, such as `quickstart=tcp:203.0.113.7:443` | a `direct` record: a flow tried to reach a host around the mock. Isolation blocked it, so nothing left, but what it would have sent was never seen |

Silence is never a clean result: an empty capture, a crashed flow, an
unaccounted credential, an untouched required placement or a connection
around the mock fails visibly instead of passing quietly. A blocked
connection attempt is not a reason: it is listed and counted in the
coverage.

The **result** is `leak` when there is any hit, otherwise `incomplete`
when any reason above holds, otherwise `clean`. A found leak outranks
incompleteness, and the incomplete reasons are still listed.

## Network isolation

A canary check sees what passes through its mock and what the program
writes to its capture. A client that ignores the proxy settings and
connects to a host directly passes through neither, so the runner takes
that path away instead of trusting every client to honour the settings.

On Linux, the runner makes an unprivileged user and network namespace (what
`unshare --user --net` makes) whose only interface is loopback, starts the
mock listening on `127.0.0.1` inside it and starts every flow inside it.
Nothing in it has a route to any other host. The runner routes every other
address to the namespace's own loopback, so a direct connection is refused
at once instead of hanging, and watches that loopback for attempts. It
records each distinct attempt as a `direct` record, with its flow, and
writes the payload of every blocked UDP datagram, a DNS query included, to
a swept capture file, so a canary in it is a hit like any other.

**Observed** (each one a `direct` record, and the run incomplete):

- a TCP connection opened to any address but loopback: `tcp`, the address
  and port;
- a UDP datagram sent to any address but loopback: `udp`, the address and
  port;
- a DNS query sent to any address, loopback included: `dns`, the name.

**Not observed:**

- the flow's traffic with the mock and with anything else on loopback,
  which never leaves the namespace;
- name lookups a flow makes through a host service over a Unix socket
  (systemd-resolved's NSS module, nscd): such a lookup happens outside the
  namespace, so the name reaches the host's resolver and is not reported.
  The connection that follows is still blocked and reported as `tcp`;
- an attempt over IPv6 where the kernel has IPv6 disabled: it fails with no
  packet;
- Unix-socket traffic to services on the host, such as a Docker or D-Bus
  socket: a network namespace does not separate filesystem sockets;
- anything a process the flow started and detached into its own session
  does after the run.

**Named and decrypted, for a run with the name and TLS stub.** A runner
may also answer, inside the namespace, every name lookup sent to
`127.0.0.1:53` with `127.0.0.1`, and serve `127.0.0.1:443` with TLS
certificates it signs for each name asked for, under a certificate
authority made for the run and trusted only by the flow. A request a flow
then sends to another host is decrypted and recorded in the request
capture as `refused`, by its host and port, its content judged like any
other request; a TLS connection the flow does not complete is recorded as
`connect`, with method `TLS`. A lookup the stub answered is not a `direct`
record: what followed it is in the request capture. A lookup sent to any
other address, and a connection to any other address or port, is observed
as above.

Where the runner cannot make the namespace (not Linux; user namespaces
disabled, as `kernel.unprivileged_userns_clone=0` or
`user.max_user_namespaces=0` do; or restricted, as Ubuntu's
`kernel.apparmor_restrict_unprivileged_userns=1` does), the flows run on
the host's network as before, the runner's output names why, and the
`network` record says not `isolated`. The report then says direct
connections were not observed. A run that must not pass
unisolated says `required`: `weir-run run --require-isolation`, or
`pytest --canary-require-isolation`.

A flow that needs the host's network, such as one that installs packages
or uses a database on the host's loopback, cannot work isolated: install
first, or mock the service.

## Exit codes

| code | result | meaning |
| --- | --- | --- |
| `0` | `clean` | complete, and no canary in the capture |
| `1` | `leak` | at least one canary, in some form, in the capture |
| `2` | none | usage or input error: bad arguments, an unusable ledger, a capture path or directory entry that cannot be read in full or is not a regular file or directory, a file reached through two given paths. No report is printed; the error on stderr names the input and line, never content read from it |
| `3` | `incomplete` | no canary found, but the run is incomplete |

`0`, `1` and `2` follow `weir scan`'s convention (nothing to fail on,
findings, unusable input). The runner exits with the judge's code, and
uses `2` for its own usage and configuration errors and for any other
failure of the run, so a runner fault never reads as a leak.

## The text report

One line per hit, then one line per not-exercised placement, per file not
scanned, per blocked destination and per incomplete reason, then the
coverage line, the network line and the result. Every output that reaches
a verdict carries the coverage and network lines, the clean one included.

```text
LEAK code.search_client.api_key file=capture/otlp.jsonl:4 signal=traces span="execute_tool fetch" at=events[0].attributes.http.request.header.authorization form=base64
LEAK env.SEARCH_API_KEY file=capture/otlp.jsonl:3 signal=traces span="invoke_agent planner" at=attributes.app.agent.tools form=raw
LEAK runtime.oauth.access_token#1 file=capture/flow-quickstart.stderr:41 signal=raw form=raw
not exercised: env.BACKUP_API_KEY
coverage: 4 placements (3 leaked, 0 exercised, 1 not exercised, 1 required), 1 flows (1 ok), 3 files, 12 spans, 0 log records, 6 metric data points, 214 strings, 48210 bytes swept
network not isolated: direct connections were not observed
result: leak
```

Precisely:

- A hit: `LEAK <placement> file=<path>:<line> signal=<signal>`, then
  `span=<quoted name>`, `log=<index>` or `metric=<quoted name>` when there is
  a record, then `sink=<quoted sink>` for a hit in a request, then
  `at=<location>` when there is one, then `form=<form>`. Quoted names use
  JSON string quoting. `<line>` is where the record starts, or, for a raw
  hit, where the match starts.
- `not exercised: <placement>` for each `not_exercised` placement.
- `not scanned: <path> (<reason>)` for each file not scanned.
- `blocked connection: <host>:<port> (<n>x)` for each destination of
  `connect` records, and `blocked request: <host>:<port> (<n>x)` for each
  destination of `refused` records, `<n>` the number of records.
- `incomplete: <reason> <subject>` for each incomplete reason.
- `coverage: <P> placements (<L> leaked, <E> exercised, <N> not exercised, <R> required), <F> flows (<K> ok), <files> files, <S> spans, <G> log records, <M> metric data points, <T> strings, <B> bytes swept`,
  followed, when the judge was given a request capture file, by
  `, <Q> requests (<X> refused, <C> blocked connections)`.
- `network isolated: <D> direct connections blocked`, `<D>` the number of
  `direct` records, or `network not isolated: direct connections were not observed`.
- `result: clean|leak|incomplete`

A run with a request capture reads like this (an excerpt):

```text
LEAK env.SEARCH_API_KEY file=capture/requests.jsonl:3 signal=requests sink="model" at=body.messages[0].content form=raw
LEAK env.SEARCH_API_KEY file=capture/requests.jsonl:4 signal=requests sink="model" at=headers.authorization form=raw
LEAK env.SEARCH_API_KEY file=capture/requests.jsonl:6 signal=requests sink="collector.example (blocked)" at=body.key form=raw
blocked connection: api.example:443 (1x)
blocked request: collector.example:80 (1x)
```

Lines are sorted (hits by placement, file, line, signal, record, sink,
location, form; blocked destinations by kind, host and port; the other
lists by placement, file or reason), so the same input gives
byte-identical output. The report depends on where values appear,
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
| `blocked` | array | `{kind, host, port, count}`: one per blocked destination; `kind` is `connection` (`connect` records) or `request` (`refused` records), `host` printed under the printing rule, `count` the number of records |
| `incomplete` | array | `{reason, subject}`; `subject` is null for `empty_capture` |
| `coverage` | object | `placements`, `leaked`, `exercised`, `not_exercised`, `required`, `flows`, `flows_ok`, `files`, `files_not_scanned`, `spans`, `log_records`, `metric_data_points`, `unparsed_records`, `strings`, `bytes`, `request_files`, `requests`, `requests_refused`, `connections_blocked` |
| `network` | object | `isolated`, `required`, `direct`: the `network` record's two flags, `false` without one, and one `{flow, protocol, target, attempts}` per `direct` record, sorted by flow, protocol and target; `target` printed under the capture-text rule |

A hit:

| field | type | meaning |
| --- | --- | --- |
| `placement` | string | the placement id |
| `kind` | string | the placement's kind |
| `file` | string | the capture path, as given or found under a given directory |
| `line` | integer | 1-based line where the record or request starts, or where a raw match starts |
| `signal` | string | `traces`, `logs`, `metrics`, `requests` or `raw` |
| `span` | string or null | the span name, printed under the rule above |
| `span_id` | string or null | the span id as lowercase hex |
| `log_record` | integer or null | the log record's 0-based index in its export request |
| `metric` | string or null | the metric name, printed under the rule above |
| `sink` | string or null | for a hit in a request, its sink (see [Attribution](#attribution)); null otherwise |
| `location` | string or null | the location within the record or request; null for `raw` |
| `form` | string | `raw`, `json`, `json2`, `url`, `base64`, `base64url` or `hex` |

No field of either report can hold a value, a fragment of one, a masked
form (`prefix...last4`), a hash or a fingerprint of a canary. The report
may be uploaded as a CI artifact; the ledger and the capture never are, and
the runner deletes them after judging.

JSON Schema artifacts for these schemas are generated from the judge's
structs and drift-tested beside the existing ones in
`packages/weir/schema_artifacts/` (`canary-ledger.v1.schema.json`, one
ledger line; `canary-requests.v1.schema.json`, one request capture line;
`canary-report.v1.schema.json`).

## What the runner owes the judge

The judge's verdict is only as good as its inputs. A runner that uses this
contract:

1. plants one fresh unique value per placement and writes the ledger
   before any flow starts;
2. writes each placement's own provider into the ledger, adds every
   credential the mock's OAuth endpoints issue (an authorization code,
   device code, access, refresh or ID token) to the ledger before the
   reply that hands it to the program, applies the credential-field rules
   to every credential field the mock receives, each declared field of
   every endpoint included (an `unexpected` record and no stored value for
   a field that holds no needle), and records one `flow` record per flow;
3. records every request the mock receives, refused and `CONNECT`
   requests included, with its credential fields, in a request capture
   file passed with `--requests`, before answering it;
4. writes OTLP export requests as decompressed OTLP/JSON, one request per
   line, in files it passes with `--otlp`, and every other telemetry body
   and each flow's stdout and stderr as its own capture file, passed as a
   swept `PATH`;
5. relays a flow's own output only after replacing every needle with
   `<canary:PLACEMENT-ID>`;
6. writes one `network` record saying whether the flows ran isolated, and
   whether the run requires it, and one `direct` record per distinct
   connection attempt isolation blocked;
7. exits with the judge's code, and deletes the ledger and the capture,
   the request capture included, when the run ends.

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

- `canary-ledger/1`, `canary-requests/1` and `canary-report/1` change only
  with an incompatible change. Additive fields keep the version: an
  optional ledger field that an older ledger leaves out, and any report
  field.
- Adding a form, a kind, an evidence type, an incomplete reason, a capture
  role or a sink changes what a run means, so each is a CHANGELOG entry in
  the release that ships it.
