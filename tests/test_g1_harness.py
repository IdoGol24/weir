import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds


def test_deterministic_code_passes_g1() -> None:
    assert_byte_identical_across_hash_seeds("print(sorted(['b', 'a', 'c']))")


def test_hash_order_dependent_code_is_caught_by_g1() -> None:
    with pytest.raises(AssertionError, match="G1 violation"):
        assert_byte_identical_across_hash_seeds("print(list({'b', 'a', 'c'}))")
