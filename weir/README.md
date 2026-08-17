# weir

A deterministic, post-hoc verification engine for AI-agent sessions.

Point it at the traces your agent already emits. It tells you two things,
in this order:

1. **What your telemetry can prove** (`weir gauge`) - an evidentiary
   coverage report with a concrete remediation for every gap.
2. **What actually happened** (`weir scan`) - findings with witness paths,
   graded by the strength of the evidence behind them, with a CI-ready
   exit code.

No capture component, no proxy, no SDK to wire in. Weir reads OpenTelemetry
GenAI OTLP-JSON exports and its own native trace format, and it never runs
your agent.

## Five minutes to your first coverage report

```
pip install weir-scan
weir gauge your-export.jsonl
```

Most real exports have content capture off (the ecosystem's privacy
default). This is what weir says about one:

```
evidentiary coverage: 0%
argument capture: 0%
degraded: 100%
tool arguments not captured - enable full-payload logging in LangChain: set return_intermediate_steps=True and log intermediate_steps
  linkage: explicit (gen_ai.tool.call.id present)
  payloads: absent - content capture is off
at your current telemetry: coverage YES - taint/scan NO
content capture is off; enable gen_ai.input.messages / gen_ai.output.messages / gen_ai.tool.call.arguments capture to unlock cross-step analysis
```

That is the whole product in eight lines: what your telemetry supports
today, and the exact attributes to enable to climb to the next rung.
Enable capture, re-run, and the ladder reads `taint/scan YES` - at which
point `weir scan` can gate your CI:

```
weir scan your-export.jsonl
1 verdict-grade finding(s)
# exit code 1 - fail the build
```

Exit codes are a contract: `0` clean, `1` at least one verdict-grade
finding, `2` the input is not telemetry at all. Nothing else exits `2`.

## It reads traces weir did not generate

This repository's test suite includes a frozen JSONL capture produced by
`opentelemetry-sdk` and Google's protojson encoder - base64 span ids,
camelCase keys, string nanosecond fields, one export batch per line. No
weir code touched those bytes (`fixtures/foreign/PROVENANCE.md` records
exactly how they were made and what that does and does not prove). The
adapter maps them at full fidelity and reports the one real deviation as
commentary:

```
span ids are not OTLP/JSON lowercase hex (base64 protojson output is the usual cause); linkage is unaffected, but spec-true hex ids are recommended
```

The ingestion posture is **reject-narrow, degrade-maximal**: exactly two
conditions reject (not JSON; nothing OTLP-shaped anywhere in the input).
Everything else - invalid UTF-8, undecodable lines or spans, duplicate or
missing span ids, orphaned parents, truncated or unparseable payloads,
clock garbage, unknown dialects, mixed logs/metrics files - degrades under
one of 18 named contract rows, each carrying a user-facing remediation
string, each exercised by committed corpora (a corrupt-input corpus plus
the capture presets). A malformation without a named row is treated as a
bug in the contract, not a judgment call in the parser.

## Evidence tiers, not vibes

Weir joins tool calls to their results by an explicit precedence of
evidence: the `gen_ai.tool.call.id` attribute, then parent/child span
nesting, then ids mined from message content - and content-mined evidence
has teeth:

- it fills absences only; envelope evidence always wins, and a conflict is
  named on the ledger (it is the fingerprint of malformed instrumentation
  or attempted linkage forgery);
- ambiguous evidence produces no join, ever - reported, never resolved by
  a silent pick, on either side of the join;
- a finding whose witness path crosses a content-mined join is **never
  verdict-grade**. The finding states its demotion reason on its face.

The consequence: the worst an attacker-controlled document can do to the
session graph is add visible, low-confidence noise. It cannot silently
rewire a witness path or suppress a high-confidence finding.

## Calibrated against known ground truth

Weir ships a paired synthetic trace generator (`weir-tracegen`) that emits
the same scenario through two renderers - native traces and OTLP-JSON -
from one plan. The adapter's acceptance test is byte-for-byte equivalence
between the two, per scenario, per capture preset, per degradation dial.
Because the generator knows the ground truth by construction, the gauge is
calibrated against corpora with known degradation:

| corpus preset       | payloads | linkage tier  | evidentiary coverage | taint capable |
|---------------------|----------|---------------|----------------------|---------------|
| `full`              | captured | explicit      | 100%                 | yes           |
| `partial`           | captured | nested        | 100%                 | yes           |
| `default-realistic` | absent   | explicit      | 0%                   | no            |
| flat-linkage dial   | captured | content-mined | 0%                   | yes           |

That last row is deliberate: content-mined linkage supports analysis but
never counts toward verdict-eligible coverage, because its evidence source
is the one an attacker can reach. Every number in this table is enforced
by tests that derive their expectations from the preset definitions and
are mutation-proven (break the source, watch the test fail, revert).

Determinism is a tested guarantee, not an aspiration: identical inputs
produce byte-identical outputs across processes and hash seeds, and the
analysis paths are proven to open no network sockets.

## Design notes: the four objections

**"Agent runs are non-deterministic - any diff against a recording is
noise."** Weir never diffs transcripts. It derives structural facts from a
session graph: which source classes reached which sinks, through which
guards, with what join confidence. Wording changes, step-count variance,
and reordered timestamps do not move those facts; when evidence genuinely
weakens, findings demote with a stated reason instead of flapping.

**"Golden baselines are brittle."** Weir's own gold corpus is generated by
construction and regenerated by its writers - never hand-edited, and
byte-drift-tested in CI. A `weir diff` baseline gate over flow facts is on
the roadmap (the fact schema and baseline format are shipped and versioned;
the diff engine is not yet).

**"Just use pytest."** Do - `weir scan`'s exit code slots into any test
runner. What pytest does not give you is the evidence layer: witness paths
for every finding, a coverage gauge that tells you when your telemetry
cannot support the assertion you are writing, and a reject-vs-degrade
contract for malformed real-world inputs.

**"An LLM judge is good enough."** A judge scores prose and drifts with
its model. Weir proves flows and is deterministic; a finding either has a
witness path through your actual trace or it does not exist. The two are
complementary - use a judge for quality, weir for claims you need to gate
a release on.

Adjacent tools, honestly: promptfoo and similar harnesses evaluate prompts
and outputs by re-running them; trajectory-eval libraries (agentevals and
kin) score agent paths, usually with a judge; observability UIs visualize
traces. Use those for what they are good at. Weir's lane is deterministic,
post-hoc structural verification of the traces you already have - it runs
nothing and scores nothing.

## What ships today, and what does not

Shipped: the Seam-1 trace schema (versioned, with a committed JSON-Schema
artifact), the OTel GenAI OTLP-JSON adapter (dialect-pinned to
`otel-genai/1.42.0`, the last versioned GenAI snapshot with a servable
schema URL), graph/label/taint/evaluate over verbatim evidence, the gauge
with its capability ladder, HTML reports, the paired generator, and the
corpora above. The bundled rule set is a small teaching family
(injection-to-exfiltration); rules are data files loaded from disk with a
deterministic global order - never fabricated in code.

Roadmap, labeled as such: the golden-diff baseline gate (`weir diff` /
`weir baseline`; the fact schema and baseline format are shipped, the diff
engine is not), the commons contribution gate (provenance-mandatory,
fixtures-required rule loading) and a broader rule set behind it, signed
rule bundles with offline verification, and additional dialect rows (the
registry names the GenAI semconv repo's first release, legacy event-style
`gen_ai.*`, OpenLLMetry, OpenInference, and Langfuse; none are built).

## Names, so nothing surprises you

The PyPI distribution is **`weir-scan`** (the name `weir` was taken). The
import package is `weir` and the CLI command is `weir`. One decision,
recorded here so it never has to be re-litigated.

```
pip install weir-scan
python -c "import weir"
weir --help
```

## License

Apache-2.0.
