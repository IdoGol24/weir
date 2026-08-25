"""Preset structural assertions, derived from the profile they validate
against. A hardcoded key list would restate the profile, which is the drift
shape the repo's first law exists to kill.
"""

from typing import Any

from weir.schema.dialect import OTEL_GENAI_1_42_0, content_bearing_keys
from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import apply_preset


def _attribute_keys(preset: str) -> set[str]:
    plan = apply_preset(instantiate("injection-exfil", seed=1), preset)
    doc: dict[str, Any] = render_otlp(plan, preset=preset)
    keys: set[str] = set()
    for resource_spans in doc["resourceSpans"]:
        for scope_spans in resource_spans["scopeSpans"]:
            for span in scope_spans["spans"]:
                keys.update(attribute["key"] for attribute in span["attributes"])
    return keys


def test_default_realistic_emits_no_content_bearing_attribute() -> None:
    # The target set comes from the profile, not from a literal list here.
    assert not (_attribute_keys("default-realistic") & content_bearing_keys(OTEL_GENAI_1_42_0))


def test_default_realistic_still_carries_linkage_and_naming() -> None:
    keys = _attribute_keys("default-realistic")
    assert "gen_ai.tool.call.id" in keys
    assert "gen_ai.tool.name" in keys


def test_partial_omits_the_call_id_key_not_merely_the_substring() -> None:
    # Load-bearing subtlety: `partial` has content ON, and v1.42.0-style
    # message attributes embed tool call ids INSIDE the serialized content. A
    # substring grep would false-positive on every partial trace, so the
    # assertion is at the attribute-key level.
    assert "gen_ai.tool.call.id" not in _attribute_keys("partial")


def test_partial_keeps_content_bearing_attributes() -> None:
    assert _attribute_keys("partial") & content_bearing_keys(OTEL_GENAI_1_42_0)


def test_full_satisfies_both() -> None:
    keys = _attribute_keys("full")
    assert "gen_ai.tool.call.id" in keys
    assert keys & content_bearing_keys(OTEL_GENAI_1_42_0)


def test_every_emitted_key_is_declared_by_the_profile() -> None:
    # The emitter must not invent attributes the dialect never declared: an
    # undeclared key is a silent extension of the wire contract.
    declared = {spec.key for spec in OTEL_GENAI_1_42_0.attributes}
    for preset in ("full", "partial", "default-realistic"):
        assert _attribute_keys(preset) <= declared
