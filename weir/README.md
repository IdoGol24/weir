# Weir - unit tests for your agents

[![CI](https://github.com/IdoGol24/weir/actions/workflows/ci.yml/badge.svg)](https://github.com/IdoGol24/weir/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/weir-scan)](https://pypi.org/project/weir-scan/) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

You cannot unit-test an agent by string-matching its output: every run is
worded differently, takes a different number of steps, and an LLM judge
drifts with its model. But underneath the wording, the things you actually
need to assert are structural facts: did untrusted tool output reach an
outbound sink, did the payment tool fire without its guard, did the
planted secret leave the session. Those facts live in the traces your
agent already emits.

Weir is that assertion. Point it at a trace; it exits `1` if a forbidden
flow happened, with a witness path you can walk node by node, and `0` if
not - deterministically, byte-identically, with no LLM in the loop and no
network access (both are tested guarantees). It never runs your agent and
ships no capture component. A weir, in the older sense, is a low dam built
to measure a river's flow without stopping it.

## Try it in two minutes

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
tool arguments not captured - this scope is emitted by Traceloop/OpenLLMetry's LangChain instrumentation, which captures content to span attributes by default; check TRACELOOP_TRACE_CONTENT (false disables capture) in the traced service's environment
  linkage: explicit (gen_ai.tool.call.id present)
  payloads: absent - content capture is off
at your current telemetry: coverage reporting YES - taint/scan NO
content capture is off; for OTel GenAI instrumentations built on the util-genai layer, set OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental and OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY to capture gen_ai.input.messages / gen_ai.output.messages / gen_ai.tool.call.arguments and unlock cross-step analysis
```

That is `weir gauge --sample`, and it answers the question every other
tool skips: **can your telemetry even support the assertion you want to
write?** Most real exports cannot yet - content capture is off by default
across the ecosystem - so the gauge tells you exactly which switch unlocks
the next rung, derived from the instrumentation recorded in the trace
itself (notice it identified the emitting library and named that library's
specific toggle). Flip the switch, re-run, and the ladder reads
`taint/scan YES`.

## The test itself

Once your telemetry carries content, `weir scan` is the unit test: run
your agent, export the trace, scan it in CI. Here it is catching a planted
injection-to-exfiltration flow:

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

Exit code `1` - fail the build. The finding carries its evidence: the
source class, the sink, the path node by node, the confidence tier of
every join it crossed, and a redacted match (weir never prints captured
secrets into your CI logs). Exit codes are a contract: `0` clean, `1` at
least one verdict-grade finding, `2` the input is not telemetry at all.
Nothing else exits `2`, and a test proves it across the whole committed
corpus.

Because the facts are structural, the test does not flap: rewording,
step-count variance, and reordered timestamps do not move it. When the
evidence genuinely weakens, a finding demotes with its reason stated on
its face instead of silently flipping.

## It reads your traces, not ours

Weir ingests OpenTelemetry GenAI OTLP-JSON - the format your agent stack
already exports - plus its own native format. This repository's suite
includes a frozen JSONL capture produced by `opentelemetry-sdk` and
Google's protojson encoder: base64 span ids, camelCase keys, string
nanosecond fields, one export batch per line. No weir code touched those
bytes (`fixtures/foreign/PROVENANCE.md` records how they were made and
what that does and does not prove). Weir maps them at full fidelity and
reports the one real deviation as commentary:

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

Real telemetry is messy, so ingestion is **reject-narrow,
degrade-maximal**: exactly two conditions reject (not JSON; nothing
OTLP-shaped anywhere in the input). Everything else - invalid UTF-8,
undecodable lines or spans, duplicate or missing span ids, orphaned
parents, truncated payloads, clock garbage, unknown dialects, mixed
logs/metrics files - degrades under one of 18 named contract rows, each
with a user-facing remediation, each exercised by committed corpora. The
full table is generated from the code and drift-tested:
[docs/contract.md](docs/contract.md). Every remediation that makes a claim
about someone else's software carries a recorded source and check date in
[REMEDIATION_SOURCES.md](REMEDIATION_SOURCES.md).

## How it decides, and why you can trust it against an attacker

The pipeline is short: your trace becomes a session graph; tool calls join
to their results through explicit tiers of evidence (the
`gen_ai.tool.call.id` attribute, then parent/child span nesting, then ids
mined from message content); data rules evaluate over the tainted graph;
every finding carries a witness path.

Content-mined evidence has teeth, because message content is exactly what
an attacker controls:

- it fills absences only; envelope evidence always wins, and a conflict is
  named on the ledger (it is the fingerprint of malformed instrumentation
  or attempted linkage forgery);
- ambiguous evidence produces no join, ever - reported, never resolved by
  a silent pick, on either side of the join;
- a finding whose witness path crosses a content-mined join is **never
  verdict-grade**.

The design intent: the worst an attacker-controlled document should be
able to do to the session graph is add visible, low-confidence noise -
never silently rewire a witness path or suppress a high-confidence
finding. If you can make attacker content do more than that, that is a
security bug and we want to hear about it: see [SECURITY.md](SECURITY.md).

## Calibrated against known ground truth

Weir ships a paired synthetic trace generator that emits the same scenario
through two renderers - native traces and OTLP-JSON - from one plan. The
adapter's acceptance test is byte-for-byte equivalence between the two,
per scenario, per capture preset, per degradation dial. Because the
generator knows the ground truth by construction, the gauge is calibrated
against corpora with known degradation:

| corpus preset       | payloads | linkage tier  | evidentiary coverage | taint capable |
|---------------------|----------|---------------|----------------------|---------------|
| `full`              | captured | explicit      | 100%                 | yes           |
| `partial`           | captured | nested        | 100%                 | yes           |
| `default-realistic` | absent   | explicit      | 0%                   | no            |
| flat-linkage dial   | captured | content-mined | 0%                   | yes           |

The presets are deliberately all-or-nothing so each row isolates one
clause; the metrics aggregate per node, so real, mixed telemetry lands
between the rows. The flat-linkage row is policy, not accident:
content-mined linkage supports analysis but never counts toward
verdict-eligible coverage, because its evidence source is the one an
attacker can reach. Every number in this table is enforced by tests that
derive their expectations from the preset definitions and are
mutation-proven (break the source, watch the test fail, revert).

## The four objections, answered

**"Agent runs are non-deterministic - any diff against a recording is
noise."** Weir never diffs transcripts. It derives structural facts:
which source classes reached which sinks, through which guards, with what
join confidence. Those facts are stable across benign variance.

**"Golden baselines are brittle."** Weir's own gold corpus is generated by
construction and regenerated by its writers - never hand-edited, and
byte-drift-tested in CI. A `weir diff` baseline gate over flow facts is on
the roadmap (the fact schema and baseline format are shipped and
versioned; the diff engine is not yet).

**"Just use pytest."** Do - `weir scan`'s exit code slots into any test
runner. What pytest does not give you is the evidence layer: witness paths
for every finding, a coverage gauge that tells you when your telemetry
cannot support the assertion you are writing, and a reject-vs-degrade
contract for malformed real-world inputs.

**"An LLM judge is good enough."** A judge scores prose and drifts with
its model. Weir proves flows and is deterministic; a finding either has a
witness path through your actual trace or it does not exist. Use a judge
for quality, weir for claims you need to gate a release on.

Adjacent tools, honestly: promptfoo and similar harnesses evaluate prompts
and outputs by re-running them; trajectory-eval libraries score agent
paths, usually with a judge; observability UIs visualize traces. Use those
for what they are good at. Weir's lane is deterministic, post-hoc
structural verification of the traces you already have - it runs nothing
and scores nothing.

## What ships today, and what does not

Shipped: the versioned trace schema (with a committed JSON-Schema
artifact), the OTel GenAI OTLP-JSON adapter (pinned to `otel-genai/1.42.0`,
the last versioned GenAI snapshot with a servable schema URL),
graph/label/taint/evaluate over verbatim evidence, the gauge with its
capability ladder, HTML reports, the paired generator, and the corpora
above. The bundled rule set is a single teaching rule
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

## Open core, in writing

The engine is Apache-2.0 permanently - schema, adapters, graph, taint,
evaluation, gauge, reporters, generator, teaching rules, and the future
diff/baseline gate. The loader enforces authenticity, never entitlement:
no license check in evaluation, no feature gate in the analysis path, and
no telemetry phoning home (the analysis path opens no sockets - tested;
fetching rule bundles is a separate, explicit command). The commercial
layer is content and services around the engine - signed, maintained rule
bundles and support - never capability withheld from it. The full signed
boundary: [docs/open-core.md](docs/open-core.md).

## Names, so nothing surprises you

The PyPI distribution is **`weir-scan`** (the name `weir` was taken). The
import package is `weir` and the CLI command is `weir`.

```
pip install weir-scan
python -c "import weir"
weir --help
```

## License

Apache-2.0.
