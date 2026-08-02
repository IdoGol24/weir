"""Rule loader (C2), local/unsigned path only (L11).

Provenance-mandatory and fixtures-required rejection gates, and signed-bundle
verification, are deferred (execution-plan L11-full / L32) — a demo rule
only needs to load and evaluate, not pass the commons contribution gate.
Every rule is a data file loaded from disk; none are ever fabricated in code
(constitution #4).
"""

from __future__ import annotations

from pathlib import Path

import msgspec

from weir.rules_commons._types import RuleSpec

_BUNDLED_RULES_DIR = Path(__file__).parent / "bundled"


def load_rules(rules_dir: Path | None = None) -> list[RuleSpec]:
    directory = rules_dir if rules_dir is not None else _BUNDLED_RULES_DIR
    rules = [
        msgspec.json.decode(path.read_bytes(), type=RuleSpec) for path in directory.glob("*.json")
    ]
    # Stable global ordering (C2) — never the filesystem's own iteration
    # order, which isn't guaranteed deterministic across platforms.
    return sorted(rules, key=lambda r: r.id)
