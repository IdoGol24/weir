# Changelog

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
