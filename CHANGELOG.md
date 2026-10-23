# Changelog

## [Unreleased]

### Added
- **weir-scan: `weir audit` checks your own credentials against your own
  agent sessions (experimental).** Given the `weir-inventory/1` report, the
  fingerprint store and the key from one `weir inventory --store` run, it
  reads Claude Code session files (main transcripts, subagent transcripts
  and their sidecars, and saved tool outputs), `CLAUDE.md` and auto-memory files, and OTLP/JSON
  telemetry (GenAI attributes and Claude Code's own log events) offline,
  and reports per
  credential, by inventory name and never by value, whether it entered the
  agent's context or was sent out in a tool call, with counts and the file,
  line, field, tool and argument of each sighting. Strings are matched by
  keyed fingerprint in every form the canary judge matches (raw, JSON, double
  JSON, URL, base64, base64url, hex). An unrecognised file format, a line
  that is not a record, a file not scanned or a sighting whose place it
  cannot classify makes the result `unknown`, exit 3, never a false clean,
  and so does an empty input: a missing or empty directory, or paths whose
  files were all skipped.
  When `CLAUDE_CONFIG_DIR` is set, the projects folder of the Claude config
  directory it names counts like `~/.claude/projects`.
  Exit codes: 0 clean, 1 exposed, 2 unusable input, 3 unknown. Report
  schema `weir-audit/1` ([docs/audit.md](docs/audit.md)).
- **weir-scan: the inventory store carries a key check.**
  `weir-inventory-store/1` gains `key_check`, an HMAC of a fixed message
  under the fingerprint key, so a reader can tell the store's key from
  another one. `weir audit` refuses a store without it: run
  `weir inventory --store` again.
- **A GitHub Action: `uses: IdoGol24/weir@<ref>`.** One step in a pull
  request job installs weir-scan and weir-run at exact versions (by
  default the versions at the action's ref, wheels only), runs
  `weir-run run --config` (`canary.toml` by default, `require-isolation`
  optional) and posts the verdict as one PR comment, updated in place on a
  re-run, with the job's own `GITHUB_TOKEN` and `pull-requests: write`
  only. The comment and the step summary show the result and the report's
  own lines, never a value. The job passes on clean (0) and fails on leak
  (1), incomplete (3) and error (2, or an exit code the report's result
  line does not confirm). A comment that cannot be posted, as on a pull
  request from a fork, is a warning; the verdict stands. On GitHub-hosted
  Linux runners it allows unprivileged user namespaces so the flows run
  isolated. Of the action's own steps only the one that posts the comment
  is given the token, after the flows have run; with `python-version` set,
  actions/setup-python also receives it through its own `token` input
  default and exits before the check step, so no process holds the token
  while the flows run. The comment names the pull request's head commit;
  on a `pull_request` event GitHub checks out the merge of that head into
  the base branch, so the tree judged is that merge commit. At a ref
  between releases, where the recorded weir-run needs a newer weir-scan
  than the one recorded, it stops with an error instead of installing
  older code. Its README is `action/README.md`.
- **weir-scan: the canary judge reads the Claude Code check's ledger.**
  `canary-ledger/1` gains the placement kind `file` (a file the runner
  wrote where a program usually finds secrets, in a scratch project or
  home), the evidence type `tool_call` (the mock's model asked the program
  for the place a placement lives, in a tool call, and the program
  answered it, with a result or a refusal) and the optional `flow` field
  `telemetry` (default `true`). When every flow record says `telemetry` is
  `false`, an empty telemetry capture no longer makes the run incomplete
  (`empty_capture`). docs/canary.md also defines the runner's name and TLS
  stub: a request a flow sends to another host is decrypted and recorded as
  `refused`, and a TLS connection it does not complete as `connect`, with
  method `TLS`. The ledger schema artifact gains the three values.
- **weir-run: the Claude Code check, "does my Claude Code setup keep my
  keys out?"** It needs the weir-scan release that ships the `file` kind
  and the `tool_call` evidence above.
  A `[claude_code]` config runs the installed Claude Code headless
  (`claude -p`) once, in a scratch project and a scratch home, inside
  bubblewrap where the real home is not mounted, and inside the isolated
  network. It plants fake secrets in the project's `.env`, a project
  config file, a credentials file in the scratch home and an environment
  variable, and a fake model key with `ANTHROPIC_BASE_URL` at the mock;
  copies in the project's whole `.claude` directory (settings, hooks,
  commands, agents, skills) and `CLAUDE.md`, and applies
  `user_settings` as the user's own settings and `managed_settings` as
  managed settings, layered as Claude Code layers them, the verdict
  listing each file applied and saying `user-level and managed settings
  not included` when they are not passed (the run never reads them from
  the user's machine); and lets the mock's
  model ask for ordinary coding actions (read the files, run `cat` and
  `env`). The verdict reads as a check of the user's controls, before the
  judge's report: `kept out: 3 of 4`, then where each other secret went
  and how (`reached the model: .env through a file read (Read .env)`),
  which secrets no action reached (`not exercised`, never kept out) and
  which Claude Code wrote to disk, its session transcript included
  (`stored locally`, apart from what was sent out). A setting that would
  move the model API, the key or the traffic away from the mock
  (`apiKeyHelper`, the base URL, key and provider variables, proxies, OTLP
  endpoints) is overridden and each override reported. The config must
  say whose key the model key is: `key_owner = "anthropic"`
  (`api.anthropic.com` is its own host) or `"gateway"` (any other host is
  a leak); without it the run starts nothing and exits 3
  (`incomplete: key_owner_not_declared`). The project is marked trusted
  for the run. A hook of the settings under test that does not start (its
  script missing or not executable) leaves the run incomplete
  (`incomplete: hook_not_started`, the hook named), never judged.
- **weir-run: a name and TLS stub in the isolated network.** For the Claude Code
  check, every name lookup is answered with the loopback address and
  HTTPS to any host is decrypted under a certificate authority made for
  the run, so connections to hosts other than the configured ones are
  reported by host and what they carried is judged like any request.
  weir-run now depends on `cryptography` to sign the stub's certificates.
- **weir-run: the Messages API mock can follow a script.** Given steps, it asks for
  one tool call per turn, in order, skipping a step whose tool the program
  does not offer, and answers `model_reply` once no step is left.

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
