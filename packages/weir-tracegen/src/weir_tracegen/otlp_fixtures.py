"""Renders the committed OTLP corpus: every demo scenario at every preset.

Shared by the one-off generation command and the CI drift test so the two can
never diverge, the same discipline as fixture_io.render_fixture_json.
"""

from __future__ import annotations

import json
from pathlib import Path

from weir_tracegen.otlp import render_otlp
from weir_tracegen.scenarios import instantiate
from weir_tracegen.scenarios.presets import PRESETS, apply_preset

_SEED = 1
_SCENARIOS = ("injection-exfil", "injection-exfil-benign")


def render_all() -> dict[str, str]:
    files: dict[str, str] = {}
    for scenario in _SCENARIOS:
        for preset in sorted(PRESETS):
            plan = apply_preset(instantiate(scenario, seed=_SEED), preset)
            document = render_otlp(plan, preset=preset)
            rel = f"otlp/{scenario}.{preset}.json"
            files[rel] = json.dumps(document, indent=2, sort_keys=True) + "\n"
    return files


def write_all(fixtures_dir: Path) -> None:
    """`fixtures_dir` is the repo's `weir/fixtures/` directory; render_all's
    keys are relative to it. LF newlines so committed bytes do not depend on
    the platform."""
    for rel, content in render_all().items():
        path = fixtures_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
