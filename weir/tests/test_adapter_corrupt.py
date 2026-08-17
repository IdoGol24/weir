"""Each corpus item's expected verdict, derived from the contract row that
judges it (weir/CLAUDE.md third law). Never a crash (G9)."""

from pathlib import Path

import pytest

from weir.adapters.otel import DegradationReason, OtlpRejectError, adapt_otlp

_CORPUS = Path(__file__).parents[1] / "fixtures" / "otlp-corrupt"

_REJECTS = ("reject-not-json.txt", "reject-not-otlp.json")

_EXPECTED_REASONS: dict[str, set[DegradationReason]] = {
    "duplicate-span-id-identical.json": {DegradationReason.DUPLICATE_SPAN_ID},
    "duplicate-span-id-differing.json": {DegradationReason.DUPLICATE_SPAN_ID},
    "orphaned-parent.json": {DegradationReason.ORPHANED_PARENT},
    "base64-ids.json": {DegradationReason.NONSTANDARD_ID_ENCODING},
    "missing-span-id.json": {DegradationReason.MISSING_SPAN_ID},
    "garbage-timestamp.json": {DegradationReason.INVALID_TIMESTAMP},
    "undecodable-span.json": {DegradationReason.UNDECODABLE_SPAN},
    "missing-operation-name.json": {DegradationReason.UNMAPPABLE_GENAI_SPAN},
    "truncated-args.json": {DegradationReason.TRUNCATED_CONTENT},
    "unknown-dialect.json": {DegradationReason.UNKNOWN_DIALECT},
    "jsonl-with-bad-line.jsonl": {DegradationReason.UNDECODABLE_BATCH},
    "non-genai-span.json": {DegradationReason.NON_GENAI_SPANS_FILTERED},
    "unparseable-args.json": {DegradationReason.UNPARSEABLE_CONTENT},
    "ambiguous-explicit-id.json": {DegradationReason.AMBIGUOUS_JOIN},
    "conflicting-join-evidence.json": {DegradationReason.CONFLICTING_JOIN_EVIDENCE},
    "invalid-utf8.json": {DegradationReason.INVALID_ENCODING},
    "mixed-signals.jsonl": {DegradationReason.NON_TRACE_BATCHES_SKIPPED},
    "undecodable-scope.json": {DegradationReason.UNDECODABLE_SCOPE},
    "string-enum-kinds.json": set(),  # permissive scalar: maps cleanly
    "array-wrapped.json": set(),  # accepted wrapper: no crash, no reject
}
# Every degrade-side DegradationReason must be exercised by the corpus or by
# the committed preset fixtures (MISSING_CONTENT is exercised by
# default-realistic in tests/test_adapter_assembly.py). Pin that coverage:


def test_every_contract_row_is_exercised() -> None:
    covered = set[DegradationReason]().union(*_EXPECTED_REASONS.values()) | {
        DegradationReason.MISSING_CONTENT,  # default-realistic preset corpus
    }
    assert covered == set(DegradationReason), (
        "contract rows without a judging corpus item: "
        f"{set(DegradationReason) - covered}"
    )


@pytest.mark.parametrize("name", _REJECTS)
def test_reject_items_reject(name: str) -> None:
    with pytest.raises(OtlpRejectError):
        adapt_otlp((_CORPUS / name).read_bytes())


@pytest.mark.parametrize("name", sorted(_EXPECTED_REASONS))
def test_degrade_items_produce_their_named_reasons(name: str) -> None:
    result = adapt_otlp((_CORPUS / name).read_bytes())  # never a crash
    observed = {d.reason for d in result.degradations}
    assert _EXPECTED_REASONS[name] <= observed, (
        f"{name}: expected {_EXPECTED_REASONS[name]}, ledger has {observed}"
    )


def test_base64_linkage_survives_intact() -> None:
    # Amendment B pinned: joins match on the raw wire token, so an
    # internally-consistent base64 export keeps ALL its joins.
    result = adapt_otlp((_CORPUS / "base64-ids.json").read_bytes())
    clean = adapt_otlp(
        (_CORPUS.parent / "otlp" / "injection-exfil.full.json").read_bytes()
    )
    assert len(result.trace.joins) == len(clean.trace.joins)


def test_string_enum_kinds_join_exactly_as_the_clean_int_kind_fixture() -> None:
    # Vanilla protojson emits SPAN_KIND_* names instead of ints; the
    # permissive scalar must not quarantine (or misclassify) a single span.
    result = adapt_otlp((_CORPUS / "string-enum-kinds.json").read_bytes())
    clean = adapt_otlp(
        (_CORPUS.parent / "otlp" / "injection-exfil.full.json").read_bytes()
    )
    assert len(result.trace.joins) == len(clean.trace.joins)
