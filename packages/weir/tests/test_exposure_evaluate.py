"""Presence does not depend on how well the span mapped: exactly two demotion
reasons, no join clause, no degraded-node clause."""

from weir.evaluate.exposure import evaluate_exposure
from weir.exposure import ExposureHit, ExposureScan
from weir.rules_commons import RuleSpec


def _hit(**over) -> ExposureHit:
    base = dict(span_ref="aa", span_name="agent", location="attributes.k",
                source_class="openai_api_key", eligible=True, value_len=48,
                prefix="sk-proj-", last4="7Ri4", fingerprint="0123456789ab")
    base.update(over)
    return ExposureHit(**base)


def _rule(**over) -> RuleSpec:
    base = dict(id="openai-api-key-in-telemetry", version="1.0.0", stage="active",
                description="d", source_class="openai_api_key", sink_tool_name=None,
                mode="exposure", severity="high")
    base.update(over)
    return RuleSpec(**base)


def _scan(hits) -> ExposureScan:
    return ExposureScan(applicable=True, spans_scanned=1, strings_scanned=1, hits=hits)


def test_an_eligible_hit_under_an_active_rule_is_verdict_grade() -> None:
    findings = evaluate_exposure(_scan([_hit()]), [_rule()])
    assert len(findings) == 1
    assert findings[0].is_verdict_grade
    assert findings[0].demotion_reasons == []
    assert findings[0].fingerprint == "0123456789ab"
    assert findings[0].fingerprint_v == 1
    assert findings[0].severity == "high"


def test_an_ineligible_hit_is_demoted_naming_the_class() -> None:
    findings = evaluate_exposure(
        _scan([_hit(eligible=False, last4=None, fingerprint=None)]), [_rule()]
    )
    assert not findings[0].is_verdict_grade
    assert findings[0].demotion_reasons == ["value shape not eligible for openai_api_key"]


def test_a_shadow_rule_is_demoted() -> None:
    findings = evaluate_exposure(_scan([_hit()]), [_rule(stage="shadow")])
    assert not findings[0].is_verdict_grade
    assert findings[0].demotion_reasons == ["rule openai-api-key-in-telemetry in shadow stage"]


def test_a_hit_with_no_matching_rule_produces_nothing() -> None:
    assert evaluate_exposure(_scan([_hit(source_class="google_api_key")]), [_rule()]) == []


def test_flow_rules_are_ignored() -> None:
    flow = _rule(id="f", mode="verbatim", sink_tool_name="send_email")
    assert evaluate_exposure(_scan([_hit()]), [flow]) == []


def test_findings_follow_hit_order() -> None:
    hits = [_hit(location="attributes.a"), _hit(location="attributes.b")]
    findings = evaluate_exposure(_scan(hits), [_rule()])
    assert [f.location for f in findings] == ["attributes.a", "attributes.b"]
