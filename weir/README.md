# Weir - unit tests for your agents

[![CI](https://github.com/IdoGol24/weir/actions/workflows/ci.yml/badge.svg)](https://github.com/IdoGol24/weir/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/weir-scan)](https://pypi.org/project/weir-scan/) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

<p align="center">
  <img src="docs/assets/weir.jpg" alt="A weir: a low dam across a river, with water flowing evenly over its crest" width="720">
  <br>
  <em>A weir is a low dam built across a river to regulate and measure its
  flow - the water keeps moving; the measurement happens anyway.</em>
  <br>
  <sub>Damhead Weir, Water of Leith. Photo by 501ghost, Wikimedia Commons, CC0.</sub>
</p>

You cannot unit-test an agent by string-matching its output, and an LLM
judge drifts with its model. But what you actually need to assert is
structural: did untrusted tool output reach an outbound sink, did the
payment tool fire without its guard, did the secret leave the session.
Those facts live in the traces your agent already emits.

Weir is that assertion. Point it at an OpenTelemetry GenAI export; it
exits `1` if a forbidden flow happened - with a witness path you can walk
node by node - and `0` if not. Deterministic and byte-identical on every
run, no LLM in the loop, no network access, never runs your agent (all
tested guarantees). Like its namesake: the session keeps flowing; the
measurement happens anyway.

## Try it in two minutes

```
pip install weir-scan
weir gauge your-export.jsonl   # or: weir gauge --sample
```

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

The gauge answers the question every other tool skips: can your telemetry
support the assertion you want to write? Most real exports cannot yet
(content capture is off by default across the ecosystem), so it names the
exact switch - derived from the instrumentation recorded in the trace
itself. Flip it, re-run, and `weir scan` becomes your unit test:

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

Exit `1` - fail the build. The finding carries its evidence, with the
matched secret redacted. Structural facts do not flap: rewording and
step-count variance cannot move them, and when evidence genuinely weakens
a finding demotes with its reason stated instead of silently flipping.

## Why you can trust it

- **It reads your traces, not ours.** The suite includes a frozen JSONL
  capture produced by `opentelemetry-sdk` and Google's protojson encoder
  that no weir code touched ([provenance](fixtures/foreign/PROVENANCE.md)).
  Ingestion is reject-narrow: only not-telemetry is refused; every real
  malformation degrades under one of 18 named contract rows with a
  remediation, generated from code and drift-tested:
  [docs/contract.md](docs/contract.md).
- **Attacker content cannot rewire it.** Joins follow evidence tiers
  (explicit id, then span nesting, then content-mined); content-mined
  evidence fills absences only, ambiguity is reported rather than
  resolved, and a finding crossing a content-mined join is never
  verdict-grade. If you can make attacker content do more than add
  visible low-confidence noise, that is a security bug:
  [SECURITY.md](SECURITY.md).
- **The gauge is calibrated against known ground truth.** A paired
  generator emits each scenario as native traces and OTLP-JSON from one
  plan; the adapter's acceptance test is byte-for-byte equivalence, and
  gauge numbers are pinned against corpora with known degradation,
  mutation-proven.
- **Every external claim is sourced.** Remediation strings that describe
  someone else's software carry a recorded source and check date:
  [REMEDIATION_SOURCES.md](REMEDIATION_SOURCES.md).

## What ships, what does not

Shipped: the OTel GenAI adapter (pinned `otel-genai/1.42.0`), session
graph, verbatim taint and evaluation, the gauge and its capability ladder,
HTML reports, the paired generator and corpora, one teaching rule
(injection-to-exfiltration). Roadmap: the `weir diff` baseline gate, the
rule-contribution gate and a broader rule set, signed bundles, more
dialect rows.

Open core, in writing: the engine - including the future diff gate - is
Apache-2.0 permanently; authenticity, never entitlement. Full signed
boundary: [docs/open-core.md](docs/open-core.md).

Install name `weir-scan` (PyPI `weir` was taken); import `weir`; command
`weir`. Apache-2.0.
