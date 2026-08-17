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
- STANDING ITEM (pre-OSS-release gate): a genuinely third-party capture -
  a real collector run, a published instrumentation-library sample, or the
  first user's export - joins this corpus before release. M4's gate
  accepts this substitute; the release gate must not.
- expected_ledger.json is DERIVED from this artifact by running the adapter
  (see plan Task 16 step 3); it is regenerated only when the contract
  legitimately changes, with the diff reviewed.
