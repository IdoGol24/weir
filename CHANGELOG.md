# Changelog

## [Unreleased]

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
