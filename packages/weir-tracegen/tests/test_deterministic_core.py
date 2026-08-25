from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir_tracegen._clock import SeededClock
from weir_tracegen._rng import SeededRng


def test_rng_same_seed_same_sequence() -> None:
    a = SeededRng(42)
    b = SeededRng(42)
    assert [a.randint(0, 1_000_000) for _ in range(10)] == [
        b.randint(0, 1_000_000) for _ in range(10)
    ]


def test_rng_different_seed_differs() -> None:
    a = SeededRng(42)
    b = SeededRng(43)
    assert [a.randint(0, 1_000_000) for _ in range(10)] != [
        b.randint(0, 1_000_000) for _ in range(10)
    ]


def test_clock_same_construction_same_sequence() -> None:
    a = SeededClock()
    b = SeededClock()
    assert [a.tick() for _ in range(5)] == [b.tick() for _ in range(5)]


def test_clock_ticks_strictly_increase() -> None:
    clock = SeededClock()
    ticks = [clock.tick() for _ in range(5)]
    assert ticks == sorted(ticks)
    assert len(set(ticks)) == len(ticks)


def test_deterministic_core_is_hash_seed_independent() -> None:
    code = (
        "from weir_tracegen._rng import SeededRng\n"
        "from weir_tracegen._clock import SeededClock\n"
        "rng = SeededRng(42)\n"
        "clock = SeededClock()\n"
        "print([clock.tick() for _ in range(3)], [rng.randint(0, 1_000_000) for _ in range(5)])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
