"""Dialect profiles: the wire shape of an input seam, as DATA.

The pin is `otel-genai/1.42.0`, the last VERSIONED OpenTelemetry GenAI snapshot
with a servable schema URL. As of 2026-08 no gen_ai.* attribute has ever been
marked Stable, and v1.42.0 (2026-06-12) deprecated and moved all GenAI content
to `semantic-conventions-genai`, which has cut no release and whose declared
development schema URL is not served. We target a deprecated-but-versioned
snapshot because it is the only versioned one.

The pin is therefore the FIRST ROW of a registry, not a foundation. The wild is
multi-generational: frameworks emit several convention generations at once and
instrumentations default to frozen v1.36-era behavior unless opted in, so the
OTel adapter was never going to be a single-version parser. Re-pinning is an
additive row plus a fixture regeneration, never a rewrite.

Attribute-style content only: by v1.37.0 per-message events were replaced by
`gen_ai.input.messages` / `gen_ai.output.messages` / `gen_ai.system_instructions`
attributes, and `gen_ai.system` became `gen_ai.provider.name`.
"""

from __future__ import annotations

import msgspec

from weir.schema._digest import content_digest


class AttributeSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """One attribute the dialect defines.

    `content_bearing` marks attributes carrying captured message or argument
    payloads. Validators read this flag rather than hardcoding a list, so a
    hardcoded copy can never drift from the profile it validates against.
    """

    key: str
    content_bearing: bool


class DialectProfile(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    profile_id: str
    schema_url: str
    attributes: list[AttributeSpec]

    def __post_init__(self) -> None:
        keys = [spec.key for spec in self.attributes]
        if len(set(keys)) != len(keys):
            raise ValueError("attribute keys must be unique")
        if keys != sorted(keys):
            raise ValueError("attribute keys must be sorted")


OTEL_GENAI_1_42_0 = DialectProfile(
    profile_id="otel-genai/1.42.0",
    schema_url="https://opentelemetry.io/schemas/1.42.0",
    attributes=[
        AttributeSpec(key="gen_ai.input.messages", content_bearing=True),
        AttributeSpec(key="gen_ai.operation.name", content_bearing=False),
        AttributeSpec(key="gen_ai.output.messages", content_bearing=True),
        AttributeSpec(key="gen_ai.provider.name", content_bearing=False),
        AttributeSpec(key="gen_ai.system_instructions", content_bearing=True),
        AttributeSpec(key="gen_ai.tool.call.arguments", content_bearing=True),
        AttributeSpec(key="gen_ai.tool.call.id", content_bearing=False),
        AttributeSpec(key="gen_ai.tool.call.result", content_bearing=True),
        AttributeSpec(key="gen_ai.tool.name", content_bearing=False),
    ],
)

DIALECT_REGISTRY: dict[str, DialectProfile] = {
    OTEL_GENAI_1_42_0.profile_id: OTEL_GENAI_1_42_0,
}

# Named so row one is never mistaken for the schema. Deliberately NOT in the
# registry: nothing may emit against a dialect that has no implementation.
PLANNED_DIALECTS: tuple[str, ...] = (
    "otel-genai/<first genai-repo release>",
    "otel-genai-legacy/1.36-events",
    "openllmetry/<version>",
    "openinference/<version>",
    "langfuse/<version>",
)


def content_bearing_keys(profile: DialectProfile) -> frozenset[str]:
    return frozenset(spec.key for spec in profile.attributes if spec.content_bearing)


def profile_digest(profile: DialectProfile) -> str:
    """Stamped as `weir.profile.digest` into every emitted trace. Same family
    and same skew-policy purpose as the catalog digest: facts derived under
    different dialect profiles are not comparable."""
    return content_digest(profile)


# The pseudo-profile for native Seam-1 traces, so baseline provenance is
# ALWAYS populated (M4 design section 6: no real baseline may predate the
# profile-provenance field). Not in DIALECT_REGISTRY: it is not an OTLP
# dialect and nothing may select it from wire input.
NATIVE_SEAM1 = DialectProfile(
    profile_id="native-seam1/1",
    schema_url="",
    attributes=[],
)
