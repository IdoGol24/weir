"""OTel GenAI OTLP-JSON adapter (M4): bytes -> CanonicalTrace + ledger.

Reject-narrow: OtlpRejectError (exit-2 material) fires only for
not-JSON / not-OTLP-shaped input. Everything else degrades, named."""

from weir.adapters.otel._contract import REMEDIATION, Degradation, DegradationReason
from weir.adapters.otel._map import ADAPTER_NAME, ADAPTER_VERSION, AdapterResult, map_wire
from weir.adapters.otel._wire import OtlpRejectError, WireInput, decode_input

__all__ = [
    "ADAPTER_NAME", "ADAPTER_VERSION", "AdapterResult", "Degradation",
    "DegradationReason", "OtlpRejectError", "REMEDIATION", "WireInput",
    "adapt_otlp", "map_wire",
]


def adapt_otlp(data: bytes) -> AdapterResult:
    return map_wire(decode_input(data))
