# The reject-vs-degrade contract

Exit-2 rejects are exactly two conditions: the input is not JSON at all (neither a JSON document nor JSON Lines), or the input is JSON but not OTLP-shaped (no `resourceSpans` list found anywhere). Everything else degrades, named by one of the rows below.

| reason | remediation |
| --- | --- |
| invalid_encoding | the input is not valid UTF-8; invalid bytes were replaced with U+FFFD, which can silently alter content-mined join evidence and taint payloads - fix the exporter's encoding |
| undecodable_batch | one or more JSONL lines could not be decoded; re-export the batch or check the exporter's file rotation for mid-write truncation |
| non_trace_batches_skipped | lines that decoded but carry no resourceSpans list (logs/metrics in a mixed export, or a malformed traces batch) were skipped; export traces to their own well-formed file |
| undecodable_span | a span failed structural decode and was quarantined; check the exporter for schema-violating span serialization |
| undecodable_scope | an instrumentation scope failed structural decode and was dropped; framework identity for its spans is lost - check the exporter's scope serialization |
| orphaned_parent | a span references a parent absent from this export; include the full trace in one export (or concatenate the batches into one JSONL file) |
| duplicate_span_id | two spans share a span id; check the instrumentation's id generator or de-duplicate the export |
| missing_span_id | a span carries no id; upgrade the exporter - joins to this span cannot be trusted |
| nonstandard_id_encoding | span ids are not OTLP/JSON lowercase hex (base64 protojson output is the usual cause); linkage is unaffected, but spec-true hex ids are recommended |
| unmappable_genai_span | a GenAI span's operation could not be derived; set gen_ai.operation.name on every GenAI span |
| non_genai_spans_filtered | non-GenAI spans (http/db/plumbing) were filtered from analysis; this is normal and not a defect |
| missing_content | content capture is off; for OTel GenAI instrumentations built on the util-genai layer, set OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental and OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY to capture gen_ai.input.messages / gen_ai.output.messages / gen_ai.tool.call.arguments and unlock cross-step analysis |
| unparseable_content | a content attribute was present but not parseable; check the instrumentation's payload serialization |
| truncated_content | a content attribute appears truncated (payload limit hit); raise the exporter's attribute length limit |
| invalid_timestamp | a span timestamp was unparseable; ordering fell back to span id - fix the exporter's clock fields |
| ambiguous_join | join evidence matched multiple candidate spans, so no join was recorded; ensure tool call ids are unique per trace |
| conflicting_join_evidence | two join sources disagreed and precedence resolved it; this is the fingerprint of malformed instrumentation or attempted linkage forgery - inspect the named spans |
| unknown_dialect | the trace matched no registered dialect; it was mapped under the default profile with every node degraded - tell us which instrumentation produced it |
