"""Rule loader (C2), local/unsigned path only (L11).

Provenance-mandatory and fixtures-required rejection gates, and signed-bundle
verification, are deferred (execution-plan L11-full / L32) - a demo rule
only needs to load and evaluate, not pass the commons contribution gate.
Every rule is a data file loaded from disk; none are ever fabricated in code
(constitution #4).
"""

from __future__ import annotations

from pathlib import Path

import msgspec

from weir.rules_commons._types import RuleSpec

_BUNDLED_RULES_DIR = Path(__file__).parent / "bundled"

UNTRUSTED_ORIGIN = "untrusted_origin"
_ALLOWED_MODES = {"verbatim", "provenance"}


def load_rules(rules_dir: Path | None = None) -> list[RuleSpec]:
    directory = rules_dir if rules_dir is not None else _BUNDLED_RULES_DIR
    rules = [
        msgspec.json.decode(path.read_bytes(), type=RuleSpec) for path in directory.glob("*.json")
    ]
    for r in rules:
        if r.mode not in _ALLOWED_MODES:
            raise ValueError(
                f"rule {r.id!r}: mode {r.mode!r} is not wired "
                f"(allowed: {sorted(_ALLOWED_MODES)})"
            )
        marker = r.source_class == UNTRUSTED_ORIGIN
        prov = r.mode == "provenance"
        if prov and not marker:
            raise ValueError(
                f"rule {r.id!r}: mode 'provenance' requires source_class 'untrusted_origin'"
            )
        if marker and not prov:
            raise ValueError(
                f"rule {r.id!r}: source_class 'untrusted_origin' is valid only with mode 'provenance'"
            )
    # Stable global ordering (C2) - never the filesystem's own iteration
    # order, which isn't guaranteed deterministic across platforms.
    return sorted(rules, key=lambda r: r.id)
