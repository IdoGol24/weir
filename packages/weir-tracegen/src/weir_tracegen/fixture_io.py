"""Fixture rendering, shared by the one-off generation step and the CI
drift-check test so they can never diverge (§6: fixtures are committed,
never hand-edited; CI regenerates from seeds and fails on any diff)."""

from __future__ import annotations

import json

import msgspec

from weir.schema.trace import CanonicalTrace


def render_fixture_json(trace: CanonicalTrace) -> str:
    return json.dumps(msgspec.to_builtins(trace, str_keys=True), indent=2) + "\n"
