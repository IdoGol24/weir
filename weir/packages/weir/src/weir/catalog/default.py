"""The bundled default catalog (C1). Layered data, no tool names in engine
code - L14's labeler and L15's taint engine consume this, never hardcode a
tool name or pattern themselves."""

from __future__ import annotations

from weir.catalog._types import Catalog, SinkSpec, SourceSpec, VerbatimEligibility

DEFAULT_CATALOG = Catalog(
    sources=[
        SourceSpec(
            name="financial_account_identifier",
            # Deliberately loose: catches IBAN-shaped tokens AND bare digit
            # runs alike as raw candidates (see SourceSpec docstring) -
            # `eligibility` below, keyed to the `iban` structure class, is
            # what tells them apart, not this pattern.
            content_pattern=r"\b[A-Z]{0,2}[0-9]{6,34}\b",
            eligibility=VerbatimEligibility(structure_class="iban"),
        ),
    ],
    sinks=[
        SinkSpec(tool_name="send_email", destination_arg_keys=["to"]),
        # A second outbound sink, so a fixture can exercise the same tainted
        # value reaching a DIFFERENT sink (a new source-to-sink pair) rather
        # than only a changed destination on the same one.
        SinkSpec(tool_name="post_to_webhook", destination_arg_keys=["url"]),
    ],
    remediations={
        "langchain": (
            "tool arguments not captured - enable full-payload logging in "
            "LangChain: set return_intermediate_steps=True and log intermediate_steps"
        ),
    },
)
