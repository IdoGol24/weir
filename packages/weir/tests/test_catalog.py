from weir.catalog import DEFAULT_CATALOG, is_iban_structured, is_verbatim_eligible

# Same locked demo secret planted in weir_tracegen's injection-exfil scenario
# (packages/weir-tracegen/src/weir_tracegen/scenarios/_common.py:PLANTED_IBAN).
# Not imported directly to avoid a weir -> weir_tracegen test dependency for
# what is really just a literal fixture value.
PLANTED_IBAN = "DE89370400440532013000"

_FINANCIAL_ACCOUNT_SOURCE = next(
    s for s in DEFAULT_CATALOG.sources if s.name == "financial_account_identifier"
)


def test_planted_iban_is_structurally_valid() -> None:
    assert is_iban_structured(PLANTED_IBAN) is True


def test_tampered_check_digits_are_rejected() -> None:
    tampered = "DE88370400440532013000"  # check digits 89 -> 88
    assert is_iban_structured(tampered) is False


def test_tampered_bban_is_rejected() -> None:
    tampered = PLANTED_IBAN[:-1] + ("1" if PLANTED_IBAN[-1] != "1" else "2")
    assert is_iban_structured(tampered) is False


def test_bare_numeral_is_not_iban_structured() -> None:
    assert is_iban_structured("18134063") is False


def test_non_de_iban_shape_without_registered_length_is_rejected() -> None:
    # GB IBANs are 22 chars too but have a different registered length in
    # general (this demo only registers DE) - an unregistered country must
    # never silently pass.
    assert is_iban_structured("GB29NWBK60161331926819") is False


def test_planted_iban_clears_verbatim_eligibility_floor() -> None:
    assert is_verbatim_eligible(PLANTED_IBAN, _FINANCIAL_ACCOUNT_SOURCE) is True


def test_bare_numeral_fails_verbatim_eligibility_floor() -> None:
    assert is_verbatim_eligible("18134063", _FINANCIAL_ACCOUNT_SOURCE) is False


def test_tampered_iban_fails_verbatim_eligibility_floor() -> None:
    # Same length as a real IBAN (22 chars) - proves eligibility is keyed to
    # the `iban` structure class, not merely to a length threshold that a
    # tampered-but-long lookalike would clear by accident.
    tampered = "DE88370400440532013000"
    assert is_verbatim_eligible(tampered, _FINANCIAL_ACCOUNT_SOURCE) is False


def test_default_catalog_has_send_email_sink_with_destination_key() -> None:
    sink_names = {s.tool_name: s for s in DEFAULT_CATALOG.sinks}
    assert "send_email" in sink_names
    assert "to" in sink_names["send_email"].destination_arg_keys


def test_default_catalog_has_a_remediation_line() -> None:
    assert DEFAULT_CATALOG.remediations  # non-empty
    for line in DEFAULT_CATALOG.remediations.values():
        assert line.strip()
