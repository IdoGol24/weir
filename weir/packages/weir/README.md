# weir

A deterministic, post-hoc verification engine for AI-agent sessions.

No LLM in the loop: every run is byte-identical and replayable, and the
analysis path opens no network sockets (both are tested guarantees, not
aspirations). Weir runs entirely in your environment, on the traces your
agent already emits - it never runs your agent and ships no capture
component. The pipeline is short: your trace becomes a session graph;
tool calls join to their results through explicit tiers of evidence; data
rules evaluate over the tainted graph; every finding carries a witness
path you can walk. A weir, in the older sense, is a low dam built to
measure a river's flow without stopping it.

## Five minutes to your first coverage report

```
pip install weir-scan
weir gauge your-export.jsonl
```

No export handy? A sample ships in the wheel:

<!-- verify: gauge --sample -->
```
evidentiary coverage: 0%
argument capture: 0%
degraded: 100%
tool arguments not captured - enable content capture in your OTel GenAI instrumentation: set OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY (content is off by default; weir reads span attributes)
  linkage: explicit (gen_ai.tool.call.id present)
  payloads: absent - content capture is off
at your current telemetry: coverage reporting YES - taint/scan NO
content capture is off; enable gen_ai.input.messages / gen_ai.output.messages / gen_ai.tool.call.arguments capture (OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY in OTel GenAI instrumentations) to unlock cross-step analysis
```

That is `weir gauge --sample`, and it is the whole product in nine lines:
what your telemetry supports today (most real exports have content capture
off - the ecosystem's privacy default), and the exact switch that unlocks
the next rung. Flip it, re-run, and the ladder reads `taint/scan YES` - at
which point `weir scan` can gate your CI. Here it is catching a planted
injection-to-exfiltration flow, witness path included:

<!-- verify: scan fixtures/injection-exfil.json -->
```
1 verdict-grade finding(s)
finding: injection-exfil-to-outbound-sink
  source: financial_account_identifier at node 2 (tool_result)
  sink: send_email at node 6
  witness path: n2 -> n3 -> n4 -> n5 -> n6
  join tiers crossed: explicit
  verdict grade: yes
  matched value: 22 chars
```

Exit code `1` - fail the build. Note what is on the finding: the source
class, the sink, the path node by node, the evidence tier of every join it
crossed, and a redacted match (weir never prints captured secrets into
your CI logs). Exit codes are a contract: `0` clean, `1` at least one
verdict-grade finding, `2` the input is not telemetry at all. Nothing else
exits `2`, and a test proves it across the whole committed corpus.

## It reads traces weir did not generate

This repository's suite includes a frozen JSONL capture produced by
`opentelemetry-sdk` and Google's protojson encoder - base64 span ids,
camelCase keys, string nanosecond fields, one export batch per line. No
weir code touched those bytes (`fixtures/foreign/PROVENANCE.md` records
how they were made and what that does and does not prove). Weir maps them
at full fidelity and reports the one real deviation as commentary:

<!-- verify: gauge fixtures/foreign/capture.jsonl -->
```
evidentiary coverage: 100%
argument capture: 100%
degraded: 0%
  linkage: explicit (gen_ai.tool.call.id present)
  payloads: present
at your current telemetry: coverage reporting YES - taint/scan YES
span ids are not OTLP/JSON lowercase hex (base64 protojson output is the usual cause); linkage is unaffected, but spec-true hex ids are recommended
```

The ingestion posture is **reject-narrow, degrade-maximal**: exactly two
conditions reject (not JSON; nothing OTLP-shaped anywhere in the input).
Everything else - invalid UTF-8, undecodable lines or spans, duplicate or
missing span ids, orphaned parents, truncated or unparseable payloads,
clock garbage, unknown dialects, mixed logs/metrics files - degrades under
one of 18 named contract rows, each carrying a user-facing remediation
string, each exercised by committed corpora. The full table is generated
from the code and drift-tested: [docs/contract.md](docs/contract.md). A
malformation without a named row is treated as a bug in the contract, not
a judgment call in the parser. Every remediation string that makes a claim
about someone else's software carries a recorded source and check date in
[REMEDIATION_SOURCES.md](REMEDIATION_SOURCES.md).

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

The design intent: the worst an attacker-controlled document should be
able to do to the session graph is add visible, low-confidence noise -
never silently rewire a witness path or suppress a high-confidence
finding. If you can make attacker content do more than that, that is a
security bug and we want to hear about it: see [SECURITY.md](SECURITY.md).

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

The presets are deliberately all-or-nothing so each row isolates one
clause; the metrics themselves aggregate per node, so real, mixed
telemetry (some calls captured, some not) lands between the rows. The
flat-linkage row is deliberate policy: content-mined linkage supports
analysis but never counts toward verdict-eligible coverage, because its
evidence source is the one an attacker can reach. Every number in this
table is enforced by tests that derive their expectations from the preset
definitions and are mutation-proven (break the source, watch the test
fail, revert).

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
corpora above. The bundled rule set is a single teaching rule
(injection-to-exfiltration), deliberately small until the contribution
gate ships; rules are data files loaded from disk with a deterministic
global order - never fabricated in code.

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
