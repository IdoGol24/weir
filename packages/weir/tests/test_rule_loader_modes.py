import json

import pytest

from weir.rules_commons.loader import load_rules


def _write(tmp_path, **over):
    base = {"id": "r", "version": "1.0.0", "stage": "active", "description": "d",
            "source_class": "financial_account_identifier", "sink_tool_name": "send_money",
            "mode": "verbatim"}
    base.update(over)
    (tmp_path / "r.json").write_bytes(json.dumps(base).encode())
    return tmp_path


def test_context_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="context"):
        load_rules(_write(tmp_path, mode="context"))


def test_provenance_requires_untrusted_origin_marker(tmp_path):
    with pytest.raises(ValueError, match="untrusted_origin"):
        load_rules(_write(tmp_path, mode="provenance", source_class="financial_account_identifier"))


def test_untrusted_origin_marker_requires_provenance_mode(tmp_path):
    with pytest.raises(ValueError, match="provenance"):
        load_rules(_write(tmp_path, mode="verbatim", source_class="untrusted_origin"))


def test_valid_provenance_rule_loads(tmp_path):
    rules = load_rules(_write(tmp_path, mode="provenance", source_class="untrusted_origin"))
    assert rules[0].mode == "provenance"


def test_valid_verbatim_rule_still_loads(tmp_path):
    rules = load_rules(_write(tmp_path))
    assert rules[0].mode == "verbatim"


def test_exposure_mode_rejects_a_sink(tmp_path):
    with pytest.raises(ValueError, match="sink_tool_name"):
        load_rules(_write(tmp_path, mode="exposure", source_class="openai_api_key",
                          sink_tool_name="send_email"))


def test_verbatim_mode_requires_a_sink(tmp_path):
    with pytest.raises(ValueError, match="sink_tool_name"):
        load_rules(_write(tmp_path, mode="verbatim", sink_tool_name=None))


def test_exposure_rule_with_unknown_source_class_names_the_mistake(tmp_path):
    with pytest.raises(ValueError, match="not in the catalog"):
        load_rules(_write(tmp_path, mode="exposure", sink_tool_name=None,
                          source_class="openai_api_kye"))


def test_exposure_rule_must_name_an_exposure_class(tmp_path):
    with pytest.raises(ValueError, match="exposure: true"):
        load_rules(_write(tmp_path, mode="exposure", sink_tool_name=None,
                          source_class="financial_account_identifier"))


def test_a_valid_exposure_rule_loads(tmp_path):
    rules = load_rules(_write(tmp_path, mode="exposure", sink_tool_name=None,
                              source_class="openai_api_key"))
    assert rules[0].mode == "exposure"
    assert rules[0].sink_tool_name is None
    assert rules[0].severity == "high"


def test_an_unknown_severity_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="severity"):
        load_rules(_write(tmp_path, severity="critical"))


def test_bundled_rules_are_the_expected_eight():
    rules = load_rules()
    assert {r.id for r in rules} == {
        "injection-exfil-to-outbound-sink",
        "github-token-to-outbound-sink",
        "openai-api-key-in-telemetry",
        "anthropic-api-key-in-telemetry",
        "aws-access-key-in-telemetry",
        "google-api-key-in-telemetry",
        "github-token-in-telemetry",
        "credential-field-in-telemetry",
    }
    assert all(r.severity == "high" for r in rules)
