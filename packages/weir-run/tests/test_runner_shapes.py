"""Canary values against docs/canary.md "Canary values".

Provider shapes are judged by weir's own catalog: each shaped value must
pass its class's eligibility pattern and none of its reject patterns, read
from the committed catalog file (the runner never imports weir).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from weir_run.shapes import (
    BANNED_WORDS,
    SHAPES,
    ByteSource,
    acceptable,
    generate,
    overlaps,
    shaped,
)

CATALOG = (
    Path(__file__).parents[2] / "weir" / "src" / "weir" / "catalog" / "bundled" / "catalog.json"
)
CLASS_OF_SHAPE = {
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
    "github": "github_token",
    "google": "google_api_key",
    "aws-access-key-id": "aws_access_key_id",
}


def _catalog_class(name: str) -> dict[str, Any]:
    sources: list[dict[str, Any]] = json.loads(CATALOG.read_text())["sources"]
    return next(s for s in sources if s["name"] == name)


def test_every_provider_shape_maps_to_a_catalog_class() -> None:
    assert set(SHAPES) - {"generic"} == set(CLASS_OF_SHAPE)


@pytest.mark.parametrize("shape", sorted(CLASS_OF_SHAPE))
def test_shaped_values_are_keys_to_weirs_catalog(shape: str) -> None:
    eligibility = _catalog_class(CLASS_OF_SHAPE[shape])["eligibility"]
    make = shaped(ByteSource(), shape)
    for _ in range(50):
        value = make()
        assert re.fullmatch(eligibility["pattern"], value)
        assert not any(re.fullmatch(r, value) for r in eligibility["reject_patterns"])
        assert len(set(value)) >= eligibility["min_distinct_chars"]


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_bodies_use_only_alphanumerics_after_the_prefix(shape: str) -> None:
    value = shaped(ByteSource(), shape)()
    prefix = SHAPES[shape].prefix
    assert value.startswith(prefix)
    assert re.fullmatch(r"[A-Za-z0-9]+", value[len(prefix) :])
    # JSON and URL escaping leave such a value unchanged.
    assert json.dumps(value) == f'"{value}"'


def test_generic_values_carry_no_provider_prefix() -> None:
    prefixes = [s.prefix for s in SHAPES.values() if s.prefix]
    value = shaped(ByteSource(), "generic")()
    assert not any(value.startswith(p) for p in prefixes)


def test_values_are_fresh_from_the_csprng() -> None:
    values = {shaped(ByteSource(), "generic")() for _ in range(20)}
    assert len(values) == 20


def test_a_seed_reproduces_the_stream_and_another_seed_does_not() -> None:
    def stream(seed: int) -> list[str]:
        make = shaped(ByteSource(seed), "openai")
        return [make() for _ in range(3)]

    assert stream(7) == stream(7)
    assert stream(7) != stream(8)
    assert len(set(stream(7))) == 3


@pytest.mark.parametrize("word", BANNED_WORDS)
def test_banned_words_are_rejected_in_any_case(word: str) -> None:
    assert not acceptable(f"Ab3{word.lower()}9Zk2", [], [])
    assert not acceptable(f"Ab3{word}9Zk2", [], [])


def test_generate_redraws_until_acceptable() -> None:
    draws = iter(["xxTESTxxxxxxxxxxxxxx", "takenvalue0000000000", "freshvalue1111111111"])
    assert generate(lambda: next(draws), ["takenvalue0000000000"], []) == "freshvalue1111111111"


def test_a_value_sharing_an_8_character_run_with_an_id_is_rejected() -> None:
    # Exactly 8 shared characters (QUICKSTA) is a run; 7 (QUICKST) is not.
    assert overlaps("ab12QUICKSTAzz", "flow.QUICKSTART")
    assert not acceptable("ab12QUICKSTAzz", [], ["flow.QUICKSTART"])
    assert not overlaps("ab12QUICKSTzzzzz", "flow.QUICKSTART")
    assert acceptable("ab12QUICKSTzzzzz", [], ["flow.QUICKSTART"])
