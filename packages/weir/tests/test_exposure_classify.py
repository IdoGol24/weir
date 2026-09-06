"""The pure half: surface -> value-free hits, graded by the catalog. Hits are
ordered by span order then location, and the value never enters the record."""

import json

import msgspec

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG
from weir.exposure import classify_exposure
from weir.schema.exposure import ExposureSurface

_KEY = "sk-proj-Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4"


def _attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def _scan(spans, resource=None, scope=None):
    doc = {"resourceSpans": [{
        "resource": {"attributes": resource or []},
        "scopeSpans": [{"scope": {"name": "s", "attributes": scope or []},
                        "spans": spans}],
    }]}
    surface = scan_surface(decode_input(json.dumps(doc).encode()))
    return classify_exposure(surface, DEFAULT_CATALOG)


def test_a_key_in_a_vendor_attribute_is_an_eligible_hit() -> None:
    scan = _scan([{"spanId": "aa" * 8, "name": "agent",
                   "attributes": [_attr("acme.agent.llm", f"LLM(api_key='{_KEY}')")]}])
    assert len(scan.hits) == 1
    hit = scan.hits[0]
    assert hit.source_class == "openai_api_key"
    assert hit.eligible
    assert hit.location == "attributes.acme.agent.llm"
    assert hit.span_ref == "aa" * 8
    assert hit.span_name == "agent"
    assert hit.value_len == len(_KEY)
    assert hit.prefix == "sk-proj-"
    assert hit.last4 == _KEY[-4:]
    assert hit.fingerprint is not None and len(hit.fingerprint) == 12
    assert hit.fingerprint_v == 1


def test_the_hit_never_carries_the_value() -> None:
    scan = _scan([{"spanId": "aa" * 8, "attributes": [_attr("k", _KEY)]}])
    assert _KEY not in msgspec.json.encode(scan).decode()


def test_native_input_classifies_as_not_applicable() -> None:
    scan = classify_exposure(
        ExposureSurface(applicable=False, spans_scanned=0, strings=[]), DEFAULT_CATALOG
    )
    assert not scan.applicable
    assert scan.hits == []
    assert scan.strings_scanned == 0


def test_the_credential_field_hit_is_subsumed_by_the_stronger_class() -> None:
    # api_key='sk-proj-...' matches credential_field at the key name and
    # openai_api_key at the value. One location, one claim: the strong one.
    scan = _scan([{"spanId": "aa" * 8,
                   "attributes": [_attr("acme.agent.llm", f"api_key='{_KEY}'")]}])
    assert [h.source_class for h in scan.hits] == ["openai_api_key"]


def test_a_key_name_with_an_unrecognized_value_stays_triage() -> None:
    scan = _scan([{"spanId": "aa" * 8,
                   "attributes": [_attr("cfg", "password=correcthorsebattery")]}])
    assert [(h.source_class, h.eligible) for h in scan.hits] == [("credential_field", False)]
    assert scan.hits[0].prefix == "password"
    assert scan.hits[0].last4 is None
    assert scan.hits[0].fingerprint is None


def test_short_and_masked_field_values_are_not_hits() -> None:
    scan = _scan([{"spanId": "aa" * 8, "attributes": [
        _attr("a", "token=1"), _attr("b", "secret=true"),
        _attr("c", "max_tokens: 1024"), _attr("d", "api_key='***'"),
        _attr("e", "'code': 'invalid_api_key'"),
        # Long enough to match, but entirely mask characters: a triage-only
        # class has no weaker state to demote to, so it is dropped outright.
        _attr("f", "api_key='********'"),
    ]}])
    assert scan.hits == []


def test_the_longest_class_prefix_wins_at_one_offset() -> None:
    ant = "sk-ant-api03-" + "Qh7Rk2Ls9Vn4Xb6Zt1Wc8Mp3Jd5Fg0Yu2Ae7Ri4Nk3Bv6Cx9Zm2Ws5Tq8Hj1Pl4"
    scan = _scan([{"spanId": "aa" * 8, "attributes": [_attr("k", ant)]}])
    assert [h.source_class for h in scan.hits] == ["anthropic_api_key"]
    assert scan.hits[0].eligible


def test_a_class_miss_is_never_regraded_under_another_class() -> None:
    # An sk-ant- value that fails the strict Anthropic pattern stays an
    # anthropic_api_key MISS. A miss must stay visible as a miss.
    scan = _scan([{"spanId": "aa" * 8, "attributes": [_attr("k", "sk-ant-tooshortbutmatches")]}])
    assert [(h.source_class, h.eligible) for h in scan.hits] == [("anthropic_api_key", False)]


def test_counts_are_reported_even_when_nothing_is_found() -> None:
    scan = _scan([{"spanId": "aa" * 8, "attributes": [_attr("k", "nothing here")]}])
    assert scan.applicable and scan.spans_scanned == 1 and scan.strings_scanned == 1
    assert scan.hits == []


def test_hits_are_ordered_by_span_then_location() -> None:
    # Wire order for spans ("bb" arrives first), location order within a span.
    scan = _scan([
        {"spanId": "bb" * 8, "attributes": [_attr("z", _KEY), _attr("a", _KEY)]},
        {"spanId": "aa" * 8, "attributes": [_attr("m", _KEY)]},
    ])
    assert [(h.span_ref, h.location) for h in scan.hits] == [
        ("bb" * 8, "attributes.a"), ("bb" * 8, "attributes.z"), ("aa" * 8, "attributes.m")]


def test_the_same_key_in_two_places_shares_a_fingerprint() -> None:
    scan = _scan([{"spanId": "aa" * 8, "attributes": [_attr("a", _KEY), _attr("b", _KEY)]}])
    assert len({h.fingerprint for h in scan.hits}) == 1


def test_triage_hits_dedupe_by_span_location_and_class() -> None:
    scan = _scan([{"spanId": "aa" * 8,
                   "attributes": [_attr("k", "password=onevalue and token=anothervalue")]}])
    assert len([h for h in scan.hits if h.source_class == "credential_field"]) == 1


def test_status_message_and_event_attributes_are_classified_too() -> None:
    scan = _scan([{"spanId": "aa" * 8,
                   "status": {"message": f"failed with {_KEY}"},
                   "events": [{"name": "exception",
                               "attributes": [_attr("exception.message", _KEY)]}]}])
    assert sorted(h.location for h in scan.hits) == [
        "events[0].attributes.exception.message", "status.message"]
