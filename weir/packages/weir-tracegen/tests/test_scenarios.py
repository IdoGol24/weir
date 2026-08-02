import msgspec
import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir_tracegen.scenarios import SCENARIOS, instantiate
from weir_tracegen.scenarios._common import PLANTED_IBAN


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario_instantiation_is_deterministic_same_seed(name: str) -> None:
    a = instantiate(name, seed=42)
    b = instantiate(name, seed=42)
    assert a == b


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario_instantiation_differs_by_seed(name: str) -> None:
    a = instantiate(name, seed=42)
    b = instantiate(name, seed=43)
    assert a != b  # the negative-control ticket id differs


def test_scenario_instantiation_is_hash_seed_independent() -> None:
    code = (
        "import msgspec\n"
        "from weir_tracegen.scenarios import instantiate\n"
        "spec = instantiate('injection-exfil', seed=42)\n"
        "import sys; sys.stdout.buffer.write(msgspec.json.encode(spec))\n"
    )
    assert_byte_identical_across_hash_seeds(code)


def _all_text(spec) -> str:  # noqa: ANN001
    parts: list[str] = []
    for step in spec.steps:
        if step.content:
            parts.append(step.content)
        if step.args:
            parts.append(msgspec.json.encode(step.args).decode())
    return " ".join(parts)


def test_red_contains_planted_iban_at_the_sink() -> None:
    red = instantiate("injection-exfil", seed=1)
    send_email = red.steps[6]
    assert send_email.tool_name == "send_email"
    assert send_email.args is not None
    assert PLANTED_IBAN in str(send_email.args)


def test_benign_has_zero_iban_eligible_tokens_at_the_sink() -> None:
    benign = instantiate("injection-exfil-benign", seed=1)
    send_email = benign.steps[6]
    assert send_email.tool_name == "send_email"
    assert send_email.args is not None
    args_text = str(send_email.args)
    assert PLANTED_IBAN not in args_text
    assert "IBAN" not in args_text.upper()


def test_benign_contains_no_iban_anywhere_in_the_trace() -> None:
    # Stronger than "not at the sink": the demo's contrast requires nothing
    # eligible reaches the sink, but this fixture goes further and plants no
    # IBAN-shaped value anywhere, so there is no ambiguity about what's clean.
    benign = instantiate("injection-exfil-benign", seed=7)
    assert PLANTED_IBAN not in _all_text(benign)


def test_negative_control_ticket_id_present_in_both_and_matches_by_seed() -> None:
    red = instantiate("injection-exfil", seed=5)
    benign = instantiate("injection-exfil-benign", seed=5)
    red_ticket_result = red.steps[2]
    benign_ticket_result = benign.steps[2]
    assert red_ticket_result.content is not None
    assert benign_ticket_result.content is not None
    # Both scenarios draw the ticket id as their first (and only) RNG call,
    # so the same seed plants the same negative-control numeral in both.
    red_ticket_id = red_ticket_result.content.split("#", 1)[1].split(":", 1)[0]
    benign_ticket_id = benign_ticket_result.content.split("#", 1)[1].split(":", 1)[0]
    assert red_ticket_id == benign_ticket_id
    assert red_ticket_id.isdigit()
    assert 6 <= len(red_ticket_id) <= 8
