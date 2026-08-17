# Remediation string sources

Every user-facing remediation/degradation string that makes a claim about
external software behavior (an instrumentation's defaults, an env var, a
spec-mandated encoding), reviewed and sourced on 2026-08-17.

## `weir.catalog.default.DEFAULT_CATALOG.remediations["langchain"]`

Shipped string:

> tool arguments not captured - enable content capture in your OTel GenAI
> instrumentation: set OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY
> (content is off by default; weir reads span attributes)

Claim: the official OTel LangChain instrumentation is
`opentelemetry-instrumentation-genai-langchain`; it does not capture
prompts/completions by default; capture is controlled by the env var
`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` with values
`NO_CONTENT | SPAN_ONLY | EVENT_ONLY | SPAN_AND_EVENT`; weir reads span
attributes, so `SPAN_ONLY` is the value that unlocks weir's view.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://github.com/open-telemetry/opentelemetry-python-genai/tree/main/instrumentation/opentelemetry-instrumentation-genai-langchain (checked 2026-08-17)

Superseded claim (removed 2026-08-17): the old string said "set
`return_intermediate_steps=True` and log `intermediate_steps`". That kwarg
returns intermediate steps in the chain's own return value and has nothing
to do with `gen_ai.*` OTel span attributes - it was false and is replaced.

## `weir.adapters.otel._contract.REMEDIATION[DegradationReason.MISSING_CONTENT]`

Shipped string:

> content capture is off; enable gen_ai.input.messages /
> gen_ai.output.messages / gen_ai.tool.call.arguments capture
> (OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY in OTel GenAI
> instrumentations) to unlock cross-step analysis

Claim: same env var/mechanism as above, stated generically for any OTel
GenAI instrumentation (not just LangChain); attribute names
`gen_ai.input.messages` / `gen_ai.output.messages` /
`gen_ai.tool.call.arguments` come from the pinned dialect profile
`otel-genai/1.42.0`.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://github.com/open-telemetry/opentelemetry-python-genai/tree/main/instrumentation/opentelemetry-instrumentation-genai-langchain (checked 2026-08-17)
- https://opentelemetry.io/schemas/1.42.0 (dialect profile `otel-genai/1.42.0`, checked 2026-08-17)

## `weir.adapters.otel._contract.REMEDIATION[DegradationReason.NONSTANDARD_ID_ENCODING]`

Shipped string:

> span ids are not OTLP/JSON lowercase hex (base64 protojson output is the
> usual cause); linkage is unaffected, but spec-true hex ids are recommended

Claim: OTLP/JSON mandates lowercase hex trace/span ids (a deviation from
vanilla proto3 JSON, which would base64-encode `bytes` fields); vanilla
protojson encoders that are not OTLP-aware are the usual source of
base64-encoded ids in the wild.

Sources:
- https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding (checked 2026-08-17)

## `weir.adapters.otel._contract.REMEDIATION[DegradationReason.UNMAPPABLE_GENAI_SPAN]`

Shipped string:

> a GenAI span's operation could not be derived; set gen_ai.operation.name on
> every GenAI span

Claim: `gen_ai.operation.name` is a real, pinned attribute name for GenAI
spans. Attribute name comes from the pinned dialect profile
`otel-genai/1.42.0`.

Sources:
- https://opentelemetry.io/schemas/1.42.0 (dialect profile `otel-genai/1.42.0`, checked 2026-08-17)

## `weir.gauge.ladder.capability_ladder_lines` unlock line (native-trace fallback)

Shipped string:

> to unlock cross-step analysis: enable gen_ai.input.messages,
> gen_ai.output.messages capture in your instrumentation

Claim: same content-capture mechanism and attribute names as
`MISSING_CONTENT` above, for traces with no adapter ledger (native input) to
carry a more specific remediation.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://opentelemetry.io/schemas/1.42.0 (dialect profile `otel-genai/1.42.0`, checked 2026-08-17)

## Digest

The `reviewed-digest` line below is the sha256 hexdigest of
`json.dumps(payload, sort_keys=True)` where `payload` is
`{"contract": {reason.value: text for every REMEDIATION entry}, "catalog": dict(DEFAULT_CATALOG.remediations)}`.
`packages/weir/tests/test_remediation_sources.py` recomputes it from the live
code and fails CI if it no longer matches - any edit to a REMEDIATION or
catalog remediation string requires re-reviewing the claim here and
recomputing this line.

reviewed-digest: 107827149dd042083798d9fe0e60ebab44fa7b88cd080c85383f953319933389
