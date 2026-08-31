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
