"""Spec 7.5: the definition of done contains a trace weir did not produce.
Ingestion-level assertions only - no ground-truth findings are claimed."""

from pathlib import Path

import msgspec
from click.testing import CliRunner

from weir.adapters.otel import Degradation, DegradationReason, adapt_otlp
from weir.cli.main import main

_DIR = Path(__file__).parents[1] / "fixtures" / "foreign"
_CAPTURE = _DIR / "capture.jsonl"

_DIR2 = _DIR / "langchain-collector"
_CAPTURE2 = _DIR2 / "capture.jsonl"


def test_gauge_and_scan_never_reject_the_foreign_capture() -> None:
    runner = CliRunner()
    for command in ("gauge", "scan"):
        result = runner.invoke(main, [command, str(_CAPTURE)])
        assert result.exit_code in (0, 1), (command, result.output)


def test_ledger_snapshot_matches_the_committed_derivation() -> None:
    observed = adapt_otlp(_CAPTURE.read_bytes()).degradations
    committed = msgspec.json.decode(
        (_DIR / "expected_ledger.json").read_bytes(), type=list[Degradation]
    )
    assert observed == committed


def test_base64_ids_are_commentary_not_damage() -> None:
    result = adapt_otlp(_CAPTURE.read_bytes())
    reasons = {d.reason for d in result.degradations}
    assert DegradationReason.NONSTANDARD_ID_ENCODING in reasons
    # The explicit tool_call_id join must survive the base64 encoding.
    assert len(result.trace.joins) >= 1


def test_mutating_one_byte_breaks_the_snapshot() -> None:
    data = bytearray(_CAPTURE.read_bytes())
    # Flip one byte inside the first line's payload (not the newline).
    data[len(data) // 4] ^= 0x01
    mutated = adapt_otlp(bytes(data))
    original = adapt_otlp(_CAPTURE.read_bytes())
    assert (
        mutated.trace != original.trace
        or mutated.degradations != original.degradations
    )


# --- langchain-collector: real LangChain agent, real Traceloop instrumentation,
# real otelcol-contrib file exporter. No weir code anywhere in this pipeline.


def test_langchain_collector_gauge_and_scan_never_reject() -> None:
    runner = CliRunner()
    for command in ("gauge", "scan"):
        result = runner.invoke(main, [command, str(_CAPTURE2)])
        assert result.exit_code == 0, (command, result.output)


def test_langchain_collector_ledger_snapshot_matches_the_committed_derivation() -> None:
    observed = adapt_otlp(_CAPTURE2.read_bytes()).degradations
    committed = msgspec.json.decode(
        (_DIR2 / "expected_ledger.json").read_bytes(), type=list[Degradation]
    )
    assert observed == committed


def test_langchain_collector_derived_structure() -> None:
    result = adapt_otlp(_CAPTURE2.read_bytes())
    nodes = result.trace.nodes
    assert sorted(n.kind.value for n in nodes) == [
        "llm_call", "llm_call", "tool_result",
    ]
    assert result.trace.joins == []
    assert result.trace.metadata.instrumentation_scope == (
        "opentelemetry.instrumentation.langchain"
    )


def test_langchain_collector_mutating_one_byte_breaks_the_snapshot() -> None:
    data = bytearray(_CAPTURE2.read_bytes())
    # Flip one byte inside a span attribute value (not the newline).
    data[len(data) // 4] ^= 0x01
    mutated = adapt_otlp(bytes(data))
    original = adapt_otlp(_CAPTURE2.read_bytes())
    assert (
        mutated.trace != original.trace
        or mutated.degradations != original.degradations
    )
