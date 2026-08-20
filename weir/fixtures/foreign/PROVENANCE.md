# capture.jsonl provenance

- Produced: 2026-08-17 (regenerate ONLY deliberately; committed bytes are frozen)
- Producer: opentelemetry-sdk 1.44.0 spans from the toy agent
  in generate_capture.py, serialized by opentelemetry-exporter-otlp-proto-common
  encode_spans + google.protobuf json_format.MessageToJson (the official
  protojson encoder). No weir or weir_tracegen code touched these bytes.
- Deliberate deviation from the M4 spec's "collector file-export" wording:
  no collector binary is assumed in this environment; the protojson encoder
  reproduces the same WIRE realities (camelCase keys, base64 ids, string
  nanos, batch-per-line JSONL).
- MessageToJson is called with use_integers_for_enums=True: the default
  (enum names as strings, e.g. "SPAN_KIND_INTERNAL") is a protojson
  readability option, not the OTLP/JSON wire convention this repo's other
  fixtures and the adapter's WireSpan.kind: int both assume; without it
  every span in a first draft of this capture failed structural decode
  (undecodable_span at $.kind) and dialect fingerprinting never ran
  (unknown_dialect). This is a serialization-option fix, not a semantic
  deviation from an OTel-generated capture.
- What this capture does NOT cover: semantic foreignness. The gen_ai.*
  attributes were hand-authored by weir's author against weir's own dialect
  expectations - the closed-loop residue one layer above the wire.
- STANDING ITEM (pre-OSS-release gate): RESOLVED 2026-08-20 - see below.
  (Original text, for the record: a genuinely third-party capture - a real
  collector run, a published instrumentation-library sample, or the first
  user's export - joins this corpus before release. M4's gate accepts this
  substitute; the release gate must not.)
- expected_ledger.json is DERIVED from this artifact by running the adapter
  (see plan Task 16 step 3); it is regenerated only when the contract
  legitimately changes, with the diff reviewed.

## 2026-08-20: release gate closed - langchain-collector/

The standing item above is resolved. `fixtures/foreign/langchain-collector/`
holds a capture with no weir or weir_tracegen code anywhere in the pipeline,
including the gen_ai.* semantics - closing the semantic-foreignness caveat
this file's original capture carried (that capture's wire bytes were
third-party-serialized, but its gen_ai.* attributes were hand-authored by
weir's author).

Producer chain, all real, all third-party:

- Agent: a real LangChain toy agent (langchain-core 1.6.0) - a
  `GenericFakeChatModel` scripted to call one `@tool` (`lookup`) and reply.
  See `toy_agent.py`.
- Instrumentation: Traceloop's real
  `opentelemetry-instrumentation-langchain` 0.62.3
  (semantic-conventions-ai 0.5.1) via `LangchainInstrumentor().instrument()`.
  No manual `set_attribute` calls anywhere in `toy_agent.py`.
- Export: real OTLP/HTTP export (opentelemetry-sdk 1.44.0,
  `OTLPSpanExporter`) to a real `otelcol-contrib` 0.159.0, receiving on the
  OTLP HTTP receiver and writing JSONL via the file exporter. See
  `collector.yaml`.
- capture.jsonl is the collector's file-exporter output, byte-copied
  verbatim - no weir code touched these bytes or these semantics.

Verified ingestion behavior (derived from the committed bytes, held by
`tests/test_foreign_capture.py`): `adapt_otlp` yields 3 nodes (one
tool_result, two llm_call; none degraded), joins == [],
metadata.framework_name == "langchain",
metadata.instrumentation_scope == "opentelemetry.instrumentation.langchain",
degradations == [] (empty ledger, see expected_ledger.json). `weir gauge`
and `weir scan` both exit 0 against this capture.

Observed dialect traits (real-world findings - the reason this gate
exists):

- Traceloop dual-emits legacy `traceloop.*` attributes AND v1.42-style
  `gen_ai.*` keys (`gen_ai.input.messages` / `output.messages` /
  `tool.call.arguments` / `tool.call.result`) in the same spans.
- A tool execution is a SINGLE span carrying both the call arguments and
  the result (kind INTERNAL, so weir maps it `tool_result`); there is no
  separate tool_call span, no tool_call/tool_result pair, and no linkage
  attributes to join - hence `joins == []`. This is a future dialect row
  candidate, not a defect.

Known presentation note (not a gauge defect, do not change the gauge): this
trace has zero tool_call nodes, so the ladder's argument-capture line
prints "payloads: absent - content capture is off" even though
`gen_ai.tool.call.arguments` and `gen_ai.tool.call.result` are both present
on the tool_result span. That line measures tool_call-shaped payloads
specifically; with zero tool_call nodes the denominator is empty, and
"absent" here is an empty-denominator artifact, not evidence that content
capture is actually off. `weir gauge`'s scope-keyed remediation still
correctly names `TRACELOOP_TRACE_CONTENT` for this scope, which is the
useful signal: evidence-keying working on a real trace.
