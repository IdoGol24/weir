# Remediation string sources

Every user-facing remediation/degradation string that makes a claim about
external software behavior (an instrumentation's defaults, an env var, a
spec-mandated encoding), reviewed and sourced on 2026-08-17.

## `weir.catalog.default.DEFAULT_CATALOG.remediations["langchain"]`

Shipped string:

> tool arguments not captured - capture mechanisms vary by instrumentation
> package; for OTel GenAI instrumentations built on the util-genai layer, set
> OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental and
> OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY (content is off
> by default; weir reads span attributes)

Claim: this is the framework-keyed FALLBACK line (used when the trace carries
no instrumentation-scope evidence), so it is deliberately generic rather than
naming one package. The `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`
capture-mode env var (values `NO_CONTENT | SPAN_ONLY | EVENT_ONLY |
SPAN_AND_EVENT`) is honored by the OTel util-genai instrumentation layer only
under the experimental GenAI semconv stability mode, selected by setting
`OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental` (append
`,gen_ai_latest_experimental` if the variable already has a value); in the
default stability mode the capture-mode variable is not honored. Weir reads
span attributes, so `SPAN_ONLY` is the value that unlocks weir's view.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://pypi.org/project/opentelemetry-instrumentation-openai-v2/ (checked 2026-08-17)

Superseded claim (removed 2026-08-17): the old string said "set
`return_intermediate_steps=True` and log `intermediate_steps`". That kwarg
returns intermediate steps in the chain's own return value and has nothing
to do with `gen_ai.*` OTel span attributes - it was false and is replaced.

Superseded claim (removed 2026-08-17, truthfulness-gate finding): the
previous version of this string ("enable content capture ... set
OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY") omitted the
stability opt-in the variable actually requires, and it was keyed off a
CLI-flag guess (`--framework`) rather than instrumentation evidence recorded
on the trace. The evidence-keyed replacement is
`scope_remediations["opentelemetry.instrumentation.langchain"]` below; this
`remediations["langchain"]` entry now exists only as the fallback for traces
that carry no scope evidence.

## `weir.catalog.default.DEFAULT_CATALOG.scope_remediations["opentelemetry.instrumentation.langchain"]`

Shipped string:

> tool arguments not captured - this scope is emitted by Traceloop/OpenLLMetry's
> LangChain instrumentation, which captures content to span attributes by
> default; check TRACELOOP_TRACE_CONTENT (false disables capture) in the
> traced service's environment

Claim: the instrumentation-scope name `opentelemetry.instrumentation.langchain`
(what `get_tracer(__name__)` produces inside the
`opentelemetry-instrumentation-langchain` package) belongs to
Traceloop/OpenLLMetry's LangChain instrumentation, a DIFFERENT package from
the OTel-official `opentelemetry-instrumentation-genai-langchain` cited above
despite the similar name. Traceloop's instrumentation captures prompts,
completions, and embeddings to span attributes BY DEFAULT; setting the env var
`TRACELOOP_TRACE_CONTENT=false` disables that capture. This entry is keyed by
the exact scope name recorded on the trace (Seam-1
`TraceMetadata.instrumentation_scope`), so it is selected only when that
evidence is present and matches - never from a `--framework` guess.

Sources:
- https://github.com/traceloop/openllmetry/tree/main/packages/opentelemetry-instrumentation-langchain (checked 2026-08-17)
- https://raw.githubusercontent.com/traceloop/openllmetry/main/packages/opentelemetry-instrumentation-langchain/opentelemetry/instrumentation/langchain/__init__.py (checked 2026-08-17)

## `weir.adapters.otel._contract.REMEDIATION[DegradationReason.MISSING_CONTENT]`

Shipped string:

> content capture is off; for OTel GenAI instrumentations built on the
> util-genai layer, set OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
> and OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY to capture
> gen_ai.input.messages / gen_ai.output.messages / gen_ai.tool.call.arguments
> and unlock cross-step analysis

Claim: same env var pair/mechanism as the fallback catalog entry above
(stability opt-in required before the capture-mode variable is honored),
stated generically for any OTel GenAI instrumentation (not just LangChain);
attribute names `gen_ai.input.messages` / `gen_ai.output.messages` /
`gen_ai.tool.call.arguments` come from the pinned dialect profile
`otel-genai/1.42.0`.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://pypi.org/project/opentelemetry-instrumentation-openai-v2/ (checked 2026-08-17)
- https://github.com/open-telemetry/semantic-conventions/blob/v1.42.0/docs/gen-ai/gen-ai-spans.md (dialect profile `otel-genai/1.42.0` attribute names; checked 2026-08-17). Note: the v1.42.0 tag predates the GenAI conventions' later move to the separate `semantic-conventions-genai` repo, so this pinned-tag path is the correct historical source for what v1.42.0 actually defined - not `opentelemetry.io/schemas/1.42.0`, which is a version-transformation file (a schema-migration manifest) and documents no attributes at all.

## `weir.adapters.otel._contract.REMEDIATION[DegradationReason.NONSTANDARD_ID_ENCODING]`

Shipped string:

> span ids are not OTLP/JSON lowercase hex (base64 protojson output is the
> usual cause); linkage is unaffected, but spec-true hex ids are recommended

Claim: OTLP/JSON mandates lowercase hex trace/span ids (a deviation from
vanilla proto3 JSON, which would base64-encode `bytes` fields); vanilla
protojson encoders that are not OTLP-aware are the usual source of
base64-encoded ids in the wild. This is a wire-encoding claim, not a
gen_ai.* attribute-name claim, so it is unaffected by the semconv-repo
citation swap above.

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
- https://github.com/open-telemetry/semantic-conventions/blob/v1.42.0/docs/gen-ai/gen-ai-spans.md (dialect profile `otel-genai/1.42.0`, checked 2026-08-17). Note: the v1.42.0 tag predates the GenAI conventions' later move to the `semantic-conventions-genai` repo; `opentelemetry.io/schemas/1.42.0` is a version-transformation file and documents no attributes, so it is never the right citation for an attribute-name claim.

## `weir.gauge.ladder.capability_ladder_lines` unlock line (native-trace fallback)

Shipped string:

> to unlock cross-step analysis: enable gen_ai.input.messages,
> gen_ai.output.messages capture in your instrumentation

Claim: same content-capture mechanism and attribute names as
`MISSING_CONTENT` above, for traces with no adapter ledger (native input) to
carry a more specific remediation.

Sources:
- https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/util.html (checked 2026-08-17)
- https://github.com/open-telemetry/semantic-conventions/blob/v1.42.0/docs/gen-ai/gen-ai-spans.md (dialect profile `otel-genai/1.42.0` attribute names, checked 2026-08-17). Note: the v1.42.0 tag predates the GenAI conventions' later move to the `semantic-conventions-genai` repo; `opentelemetry.io/schemas/1.42.0` documents no attributes and is never the right citation here.

## Digest

The `reviewed-digest` line below is the sha256 hexdigest of
`json.dumps(payload, sort_keys=True)` where `payload` is
`{"contract": {reason.value: text for every REMEDIATION entry}, "catalog": dict(DEFAULT_CATALOG.remediations)}`.
`packages/weir/tests/test_remediation_sources.py` recomputes it from the live
code and fails CI if it no longer matches - any edit to a REMEDIATION or
catalog remediation string requires re-reviewing the claim here and
recomputing this line. (`scope_remediations` is advisory prose like
`remediations` - see `weir.catalog.digest`'s module docstring - and is not
part of this digest's `payload`, but every scope-remediation string is still
reviewed and sourced above by the same discipline.)

reviewed-digest: 0ffb226d0b4920713c02767f3f2ee79a9aac4b3c52bcda39162df2e56dd3a0bf
