"""G1 over the adapter path, and preset inertness (spec section 7.4 / IOU 5)."""

import json

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.adapters.otel import adapt_otlp
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset

_G1_SNIPPET = """
import json, msgspec
from weir.adapters.otel import adapt_otlp
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset
plan = apply_preset(instantiate("injection-exfil", seed=1), "full")
result = adapt_otlp(json.dumps(render_otlp(plan, preset="full")).encode())
print(msgspec.json.encode(result.trace).decode())
print(msgspec.json.encode(result.degradations).decode())
"""


def test_g1_adapter_output_byte_identical_across_hash_seeds() -> None:
    assert_byte_identical_across_hash_seeds(_G1_SNIPPET)


def test_preset_label_is_inert() -> None:
    # Two inputs identical except weir.tracegen.preset must produce
    # byte-identical analysis output: the label is generation metadata and
    # everything under weir.* is untrusted producer self-description.
    plan = apply_preset(instantiate("injection-exfil", seed=1), "full")
    doc = render_otlp(plan, preset="full")
    relabeled = json.loads(json.dumps(doc))
    for attr in relabeled["resourceSpans"][0]["resource"]["attributes"]:
        if attr["key"] == "weir.tracegen.preset":
            attr["value"]["stringValue"] = "some-other-label"
    a = adapt_otlp(json.dumps(doc).encode())
    b = adapt_otlp(json.dumps(relabeled).encode())
    assert a.trace == b.trace
    assert a.degradations == b.degradations
