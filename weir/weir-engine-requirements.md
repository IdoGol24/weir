# weir - engine requirements

The normative technical requirements the engine is built against, extracted from the project's internal master specification. Requirement ids (R-, G-, section references) cited across docs/superpowers/ refer to this document.

---

## Design constitution (invariants that outrank features)

1. **Determinism.** Same inputs → byte-identical outputs. No clock, no randomness in the analysis path. (The only sanctioned randomness is witness-commitment salts, generated in the render step and recorded — §8.)
2. **Purity core, imperative shell.** Components 2–7 are pure functions over typed values. File and process I/O live only in the adapters and the CLI.
3. **Totality.** Rule evaluation cannot recurse, loop unboundedly, or execute code. A hostile rule file can waste cycles, never exfiltrate.
4. **Rules and catalogs are data, never code.** Zero tool names in engine source.
5. **Silence is never safety.** Every output — including the green screen — carries the coverage line: steps scanned, rules evaluated, argument-capture percentage. `[B1]`
6. **Offline by construction.** `scan`, `gauge`, `test`, `validate` perform **zero network I/O** and the engine never transmits trace data or telemetry anywhere, ever. Only `verify --online` may touch the network, opt-in (§ C3). This is simultaneously the trust posture and the reason a security team lets the tool near production traces.
7. **Verification is open; signing is closed.** Anyone can verify a signed pack or feed bundle with the free engine; only the commercial plane signs. `[B9]`
8. **Verdict-grade is earned, not default.** A finding reaches the headline section only if every link in its witness is explicit and undegraded (§7). Everything else is triage. `[B2][B6]`
9. **Language discipline is enforced, not requested.** Output templates are linted against a forbidden lexicon (*safe, certified, guaranteed, compliant…*); the word is **evidence**. `[B3 guardrail]`
10. **Degrade, never crash.** Unmappable input becomes a `degraded:true` node; a partial graph still scans and the Gauge reports exactly how partial. `[B1][B11]`
11. **No model in the detection loop.** The analysis path — graph, gauge, labels, taint, evaluation — contains no ML inference. Nothing to refuse, nothing to hallucinate, nothing that answers differently twice; a verdict is a decidable computation, so replay is proof rather than re-asking an opinion. Models may assist humans *around* the engine (triage prose, summaries) but never decide a finding.

---

## 3. High-level architecture (technical-stack constraints)

### 3.2 Repository layout (Python 3.12+, uv workspace — stack settled 2026-08-01)

*Stack settlement: Python over TypeScript. Verification tooling is also first-class here: sigstore-python offline bundle verify, rfc8785, rfc3161-client.*

```
weir/
  pyproject.toml            uv workspace root; ruff (lint+format), pyright strict, pytest+hypothesis
  packages/
    weir/                   # engine distribution
      src/weir/
        schema/             Seam-1 trace, rule, catalog, report, gauge, expected-file schemas
                            (msgspec frozen structs; exported JSON Schemas committed as versioned artifacts)
        adapters/           native + OTel GenAI (default launch adapter; Langfuse only on partner demand)
        graph/ gauge/ label/ taint/ evaluate/     (pure — see enforcement note)
        report/             HTML / SARIF / JSON renderers, commitments (pure given salts)
        verify/  cli/
        catalog/            bundled default catalog (data)
        rules_commons/      teaching rules (data + fixture refs)
    weir-tracegen/          # dev-side generator distribution; imports weir.schema (finding_id
                            # computed one way, one place); the engine never imports tracegen
  fixtures/                 generated gold corpus — committed, never hand-edited; CI regenerates
                            from seeds and fails on any diff
  docs/
```

Purity is enforced, not conventional: import-linter forbids the pure core (`graph`/`gauge`/`label`/`taint`/`evaluate`) from importing `cli` or any I/O module, and ruff banned-API rules make `datetime.now`, `time.time`, `random`, and file I/O (`open`, `Path.read_*`/`write_*`) unimportable in analysis-path modules — `secrets` is permitted only in `report` (the §8 salts, the constitution's one sanctioned randomness). The G1 harness runs every fixture twice under different `PYTHONHASHSEED` values and requires byte-identical output.

### 3.3 Data artifacts (all schema-versioned)

`CanonicalTrace` → `SessionGraph` → `GaugeReport` → `LabeledGraph` → `TaintedGraph` → `Finding[]` → `{report.html, report.sarif, report.json, salts.json}`. The JSON report plus the GaugeReport are the **only** inputs the commercial Evidence Pack Signer consumes (§10) — the closed plane never reaches into engine internals. **Seam schemas contain no floating-point values**: ratios and percentages are integer basis points or `{num, den}` pairs, amounts are integer minor units (canon N2 already guarantees this) — floats are a cross-language determinism hazard, and both the §8 digests and the `expected_gauge.json` equality gate depend on exact representation. Rendering to "84%" happens at display, never in the artifact.

---

## 4. Cross-cutting requirements (G-series)

- **G1 — Determinism contract.** Identical `(trace, catalog, rules, flags)` → identical findings in identical order. Enforced by a repeat-run equality test in CI over the full fixture set.
- **G2 — Totality.** The rule expression core has no recursion, no user loops, no eval. Complexity bound documented per operator; worst-case evaluation is O(rules × V+E).
- **G3 — Offline & zero telemetry.** No network syscalls in `scan|gauge|test|validate` (enforced by a test harness that fails on any socket open). No usage data collection of any kind. `[B5][trust posture]`
- **G4 — Redaction by default.** All human-readable output masks matched values; `--no-redact` is local-only and prints a warning banner. Masked output remains evidentiary via witness commitments (§8). `[B10]`
- **G5 — Language lint.** `weir validate --templates` fails CI if any emit or report template contains the forbidden lexicon (`safe`, `secure`, `certified`, `guaranteed`, `compliant`, `no vulnerabilities`); citation spans (quoting a regulation's own title) are the only allowlisted context. `[B3]`
- **G6 — Exit-code contract.** `0` = no **verdict-grade** findings at or above `--fail-on` (default `high`); `1` = at least one; `2` = input/validation error. Context-mode rows, shadow-stage findings, and heuristic-join findings never affect the exit code. `[B2][B4][B6]`
- **G7 — Versioning.** Trace schema, rule schema, catalog schema, canon, and report schema each carry independent semver; every finding and every Gauge Report records the versions that produced it. A pack is reproducible from `(trace, versions)`.
- **G8 — Performance envelope.** 50k-step session: graph+gauge under 2 s, full scan under 30 s on a laptop. `weir test` fast path (changed rules + smoke set) under 60 s regardless of corpus size. `[B8]`
- **G9 — Error taxonomy.** Schema-invalid trace → line-precise rejection; unmappable fields → `degraded:true` nodes, never a crash. `[carried from v1]`
- **G10 — No DRM.** The loader enforces *authenticity* (signatures), never *entitlement*. License expiry is metadata that gates feed **access** server-side, not local evaluation of already-obtained bundles. `[A13-adjacent; keeps trust posture clean]`

---

## 5. Component requirements

Numbering continues from v1; `[changed]` and `[new]` mark deltas, tags cite the board claim that forced them.

### Component 1 — Trace Adapter
- **R1.1** Accept native weir JSON (Seam-1 schema) with zero transformation. *[unchanged]*
- **R1.2** Ship exactly one real-world adapter at launch — Langfuse **or** OTel GenAI spans. *[unchanged]*
- **R1.3** Format-tolerant: unmappable fields degrade to a generic node with `degraded:true`; a partial graph still scans. *[unchanged]*
- **R1.4** *[changed — B6]* Resolve tool_call↔tool_result joins by precedence (explicit id → parent/child nesting → name+temporal adjacency) and **record `join_confidence: explicit|nested|heuristic` on every join**. Confidence is data that flows all the way to the verdict-grade decision (§7); it is never discarded after joining.
- **R1.5** Emit the mapping-fidelity summary consumed by the Gauge: clean-map %, heuristic-join count, degraded count. *[unchanged]*
- **R1.6** *[new — B11]* Record adapter version and detected framework/framework-version in the trace metadata, so the Gauge can flag adapter↔framework drift.
- **R1.7** *[new — soundness]* Preserve every step's native identifier (span id, message id, event index) as `source_ref` on the node. This is the stable join key for anything produced outside weir over the same trace — event annotations (R4.6), partner-side tooling, dispute-time cross-referencing.

### Component 2 — Graph Builder
- **R2.1–R2.5** as v1: one node per step, temporal `next` edges, `spawns` edges, result joins carried with their `join_confidence`, schema-invalid traces rejected with line-precise errors, pure function. *[unchanged except join_confidence carriage]*

### Component 3 — **Gauge** (was: Coverage Doctor)
- **R3.1** Report % of tool_call nodes carrying inspectable arguments. *[unchanged]*
- **R3.2** Report payload fidelity: degraded, truncated, empty node percentages. *[unchanged]*
- **R3.3** *[changed — B6]* Report join quality as the explicit/nested/heuristic split, not a single number.
- **R3.4** *[changed — B1]* Remediation lines are **catalog data**, keyed by detected framework (`remediations` table in C1): "tool arguments not captured — enable full-payload logging in <framework>: <exact setting>". Adding a framework's remediation is a catalog edit, not code.
- **R3.5** Standalone: `weir gauge <trace>` requires no rules, no catalog customization, no config. *[unchanged]*
- **R3.6** *[new — B11]* Threshold gates for the async capture runbook: `--min-arg-capture <pct>`, `--max-heuristic <pct>`, `--max-degraded <pct>` → exit 0/1, plus `--json` for machine consumption.
- **R3.9** *[new — A4]* Per-agent-path breakdown, so a partner can gauge one sandbox path first and later compare paths.
- **R3.10** *[new — CISO metric]* The Gauge's headline number is **evidentiary coverage**: the percentage of tool-call steps that are *verdict-eligible* — inspectable arguments ∧ explicit-or-nested join ∧ not degraded — i.e., §7's preconditions aggregated over the session. `weir gauge --baseline prior-gauge.json` renders the delta, per path and rolled up.
- **R3.11** *[new — capture-side strategy]* weir ships a **"weir-provable" telemetry profile**: a versioned, testable conformance spec naming exactly what emitted telemetry must contain for verdict-grade analysis — explicit `tool_call_id` linkage, full argument payloads, preserved native step ids (`source_ref`), stable actor/path identifiers. `weir gauge --profile weir-provable/1` verifies conformance and reports precisely which clause fails; R3.4 remediation lines may prescribe the profile itself when a framework's settings dead-end below it. The profile is simultaneously the ask to upstream instrumentation (OTel GenAI semconv, framework maintainers) — capture improvements go **upstream-first**, and per-customer manual capture work productizes as an upstream patch or published recipe, not as weir-shipped runtime code. **weir ships no runtime capture component in v1.** A weir-owned capture SDK or collector processor is explicitly deferred: it would re-introduce an in-path deployed component (weakening the read-only/post-hoc security-review posture), put solo maintenance against N frameworks' release trains inside customer production `[A1/B5 logic]`, and tempt capture-time value hashing — which breaks §8's render-time salted-commitment design (canonical-form-set matching cannot run over values hashed before canonicalization, and unsalted capture-time hashes invite dictionary attacks).

### Component 4 — Labeler
- **R4.1–R4.5** as v1: source labels (tool-pattern and content-pattern), sink labels with true-destination extraction from arguments (recursive descent over nested args via catalog `destination_arg_keys`), guard satisfaction, all patterns from C1, pure and order-independent. *[unchanged]*
- **R4.6** *[NEW-ATR]* Accept an optional **event-annotations** input: `weir scan --events events.json`, where each entry is `{source_ref, event_id, source, rule_version}` — keyed by the **trace's native step identifier** (`source_ref`), *not* by weir-assigned node ids, because the annotation producer (e.g., the ATR event engine) runs over the raw trace and has never seen weir's graph. Adapters preserve each step's native identifier as `source_ref` (R1.7), and the labeler joins annotations to nodes through it, attaching labels of the form `event:<source>:<id>`. weir never embeds or executes the event engine — annotations are input data, keeping G2 totality intact. A convenience importer (`weir events import --format atr`) may ship later as a thin transform.

### Component 5 — Taint Engine
- **R5.1** Context mode as v1 (conservative propagation to session end, same-actor). Downstream rendering is constrained by B2 (see R7.1). *[unchanged mechanics]*
- **R5.2** Verbatim mode as v1: canonicalized source value appearing literally in a sink's args or designated output field. *[unchanged]*
- **R5.3** *[changed — B7]* **canon v2**: the base transform (uppercase; strip whitespace and hyphens) plus a **closed, versioned, fixture-backed normalizer set**: N1 strip currency symbols; N2 amounts to minor units, accepting both `1,234.56` and `1.234,56` conventions; N3 strip dots/slashes in account-like tokens. A value's canonical set is `{base(v)} ∪ {Ni(base(v))}`; a verbatim match is any non-empty intersection. Every normalizer ships with positive **and** negative fixtures; the canon version is recorded in every finding and every Gauge Report (G7). The set grows only by fixture-gated addition — never by config, never per-customer.
- **R5.9** *[new — soundness]* **Verbatim eligibility floor and match modes.** A source value is verbatim-eligible only if it clears a per-source-class floor from the catalog: a minimum canonical length **or** a structure class (IBAN, PAN, key-shaped, etc.). Bare short numerals are never verbatim-eligible — a canonicalized amount like `123456` substring-matching inside an unrelated ID is exactly the false-positive class the near-zero-FP contract cannot survive. Accordingly each normalizer declares its match mode: N2 (amounts) matches **token-bounded only** (the sink-side occurrence must be a delimited field value, not a free substring); N1/N3 and the base transform may match by substring containment. Floors and modes are catalog data, fixture-gated like everything else.
- **R5.4** Every finding records which mode (and which normalizer, if any) produced it. *[extended]*
- **R5.5** No sanitizer primitives — "this step cleanses taint" is exactly the assumption prompt injection violates. *[unchanged]*
- **R5.6** Deterministic, total, O(V+E) reachability per source label. *[unchanged]*
- **R5.7** *[changed — B6]* Degraded nodes are excluded from verbatim matching but still carry context taint; a witness path that traverses any `heuristic` join marks the finding for demotion (§7).
- **R5.8** *[new — B2]* `--mode verbatim` is the default. Context mode is explicit opt-in and its output can never satisfy `--fail-on` (G6).

### Component 6 — Rule Evaluator
- **R6.1–R6.5** as v1: rules are data (source + sink + flow + guard-absence + value predicates), full rule anatomy over the tiny total expression core, minimal witness, stable deterministic ordering. *[unchanged]*
- **R6.6** Exit-code semantics now live in G6 and count **verdict-grade findings only**. *[changed — B2/B4/B6]*
- **R6.7** *[NEW-ATR]* Event labels are first-class in the rule language: usable in source selectors and `when` predicates (e.g., `node has event:ATR:2026-00524 and flows_to sink:network`). This lets flow rules **compose over the community event corpus** instead of re-authoring it.
- **R6.8** *[new — B4]* Rules carry `stage: shadow|active`. Shadow rules are fully evaluated; their findings are segregated (R7.8) and never affect the exit code. Promotion shadow→active is a metadata change shipped through the normal signed-bundle path.
- **R6.9** *[new]* Verdict grade is computed by the engine per §7 — a rule author cannot declare their own finding verdict-grade.

### Component 7 — Reporter
- **R7.1** *[changed — B2]* Context-mode output is collapsed to **one row per (source-label → sink-class) pair**, expandable on demand, rendered as a visually distinct review queue, never interleaved with verdict-grade findings, never a headline count.
- **R7.2** *[changed — B10]* Masking by default (G4), with **witness commitments** (§8) so a masked report remains evidentiary: matched values render as truncated commitments whose equality at source and sink is the visible proof.
- **R7.3** SARIF v2.1.0 for the GitHub Security tab and CI. Only verdict-grade findings map to SARIF `error`; review-queue items map to `note`. *[refined]*
- **R7.4** JSON output with full witnesses, commitments, join provenance, versions — the Evidence Pack seam (§10). *[extended]*
- **R7.5** Coverage line in the footer of every output, sourced from the Gauge. *[unchanged]*
- **R7.6** The green state is a designed screen: "0 verdict-grade findings — N steps scanned, M rules evaluated, X% argument capture" — and passes the G5 lexicon lint like everything else. *[unchanged + linted]*
- **R7.7** *[new — B6]* A finding demoted for heuristic joins shows **why**: the specific join and its precedence level, so a human can confirm or reject the linkage.
- **R7.8** *[new — B4]* Shadow-stage findings render in their own section labeled "shadow — under observation, not findings," with the rule's provenance and its promotion criteria visible.

### Component 8 — CLI
```
weir gauge <trace> [--json] [--min-arg-capture N] [--max-heuristic N] [--max-degraded N]
weir scan  <trace> [--mode verbatim|context] [--rules …] [--catalog …] [--events …]
                   [--report out.html] [--format html|sarif|json] [--fail-on high|med|low]
weir test  [--full | --rule <id>]          # default: changed rules + smoke set   [B8]
weir validate <rules|catalog> [--templates]                                       [B3→G5]
weir verify <pack.zip | bundle.tar> [--online] [--witness <salt> <value>]         [B9]
weir feedback <finding-id> --report report.json                                   [B4]
weir rules list                            # id, version, stage, provenance       [A3]
weir events import --format atr <file>     # stub, post-launch                    [NEW-ATR]
```
`weir doctor` aliases `weir gauge` for one release. Exit codes per G6 everywhere.

### Shared C1 — Catalog
As v1 (sources, sinks + extraction keys, guards, allowlists), plus *[new]*: the **normalizer definitions** referenced by canon v2 `[B7]`, the **remediations table** keyed by framework `[B1]`, and the **event-source registry** (which `event:` namespaces are recognized and how ids are displayed) `[NEW-ATR]`. Layered: bundled default → deployment override, never code changes.

### Shared C2 — Rule Loader
- Load order: bundled commons → user path → signed bundles; stable global ordering. *[unchanged]*
- *[changed — B9]* **Verify before merge**: bundle signature (Sigstore bundle: keyless cert + Rekor inclusion proof, offline-verifiable) checked by the `verify` package; an unverifiable bundle is refused with a precise reason.
- *[new — A3]* **Provenance is mandatory**: every rule carries `{author, created, updated, references[], fixtures[]}`; a rule without fixtures is rejected — this is the contribution gate that makes the commons corpus trustworthy and the feed's freshness claim auditable.
- *[new — B4]* `stage` honored end-to-end.
- *[G10]* No entitlement logic. Authenticity only.

### C3 — Verifier *(new component — B9; lives in the commons on purpose)*
`weir verify` re-derives the canonical-JSON digest (RFC 8785) of a pack or bundle, checks the Sigstore signature and certificate identity, checks Rekor inclusion **offline** from the proof shipped inside the artifact (`--online` re-checks the live log), and validates the RFC-3161 timestamp token. `--witness <salt> <value>` recomputes a disclosed commitment (§8). Output is per-check PASS/FAIL with the signer identity displayed verbatim — the tool asserts signature validity, never artifact "safety" (G5).

### C4 — Feedback *(new component — B4)*
`weir feedback <finding-id>` packages a candidate false-positive fixture from a report: the minimal witness subgraph with values replaced by their commitments or synthetic stand-ins (never plaintext — redaction survives the round trip), rule id + version, canon version, adapter version. Output is a single `feedback-<id>.json` the subscriber sends back through any channel. This is the intake of the shadow-then-promote lifecycle.

---

## 7. Verdict-grade findings — the quality invariant

A finding is **verdict-grade** if and only if all of the following hold:

1. produced in **verbatim** mode `[B2]`;
2. every join on its witness path has `join_confidence ∈ {explicit, nested}` `[B6]`;
3. no witness node is `degraded:true` `[B1]`;
4. the rule's `stage` is `active` `[B4]`.

Everything else is triage: context rows go to the collapsed review queue, heuristic-join findings go to the review queue with their join shown, shadow findings go to the shadow section. Only verdict-grade findings drive exit codes, SARIF errors, and Evidence Pack findings sections. **The near-zero-false-positive claim is scoped to verdict-grade findings and nothing else** — this sentence is the product's honesty contract, and every rendering surface enforces it structurally rather than typographically.

---

## 8. Witness commitments (the B10 result, specified)

Masking by default (G4) must not destroy evidentiary value. The scheme:

- For each **distinct canonical value** `v` appearing in any witness of a report, generate a per-report random 128-bit salt `s_v` (the render step's only randomness, G1).
- Commitment: `c_v = SHA-256(s_v ‖ canon(v))`, canon version recorded.
- The report displays `c_v` (truncated in HTML, full in JSON) at **both** the source occurrence and the sink occurrence. Equality of commitments at the two ends *is* the visible proof that the same value flowed — checkable by any reviewer with no disclosure at all.
- Salts are written to a separate `salts.json` that stays with the trace owner (a disclosed salt would permit dictionary attacks on structured values like IBANs). **Selective disclosure**: for a sampled finding, the owner reveals `(s_v, v)` and the reviewer runs `weir verify --witness` to recompute `c_v`.
- The same value therefore shows the same commitment everywhere within one report (equality is the point) and different commitments across reports (no cross-report linkability).
- **Determinism, precisely** *[soundness]*: the finding **set** (rules fired, node `source_ref`s, witness paths, modes, versions) is deterministic and salt-free; rendered commitments are deterministic **given** `salts.json`, and `--salts <file>` re-renders byte-identically. For salt-independent reproduction checks, every report carries a **findings-skeleton digest**: SHA-256 over the canonical-JSON finding set *with values elided* — no sensitive material, so it can sit in the signed pack and in a transparency log. A re-run by anyone holding the traces reproduces the skeleton digest exactly; values are then checked via commitment equality or selective disclosure. G1's scope in part 1 is to be read with this precision.
- **Finding identity** *[soundness]*: every finding carries a stable `finding_id` — SHA-256 over its value-elided canonical form (rule id + rule version + canon version + ordered witness `source_ref` path + mode/normalizer). Salt-free and deterministic: identical across re-runs and machines. It is the join key for the three-valued gold-gate comparator, for `weir feedback <finding-id>` (C4), and for cross-run diffs; masked and unmasked renders of the same finding share one id, because values never enter it.
