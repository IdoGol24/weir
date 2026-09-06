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

from weir.catalog import DEFAULT_CATALOG, Catalog
from weir.rules_commons._types import RuleSpec

_BUNDLED_RULES_DIR = Path(__file__).parent / "bundled"

UNTRUSTED_ORIGIN = "untrusted_origin"
_ALLOWED_MODES = {"verbatim", "provenance", "exposure"}
_SEVERITIES = {"high", "medium", "low"}
_SINK_MODES = {"verbatim", "provenance"}


def load_rules(rules_dir: Path | None = None, *, catalog: Catalog | None = None) -> list[RuleSpec]:
    directory = rules_dir if rules_dir is not None else _BUNDLED_RULES_DIR
    rules = [
        msgspec.json.decode(path.read_bytes(), type=RuleSpec) for path in directory.glob("*.json")
    ]
    sources = {s.name: s for s in (catalog if catalog is not None else DEFAULT_CATALOG).sources}
    for r in rules:
        if r.mode not in _ALLOWED_MODES:
            raise ValueError(
                f"rule {r.id!r}: mode {r.mode!r} is not wired (allowed: {sorted(_ALLOWED_MODES)})"
            )
        if r.severity not in _SEVERITIES:
            raise ValueError(
                f"rule {r.id!r}: severity {r.severity!r} is not one of {sorted(_SEVERITIES)}"
            )
        if r.mode in _SINK_MODES and r.sink_tool_name is None:
            raise ValueError(f"rule {r.id!r}: mode {r.mode!r} requires a sink_tool_name")
        if r.mode == "exposure":
            if r.sink_tool_name is not None:
                raise ValueError(
                    f"rule {r.id!r}: mode 'exposure' is a presence claim about one "
                    "location and must not name a sink_tool_name"
                )
            source = sources.get(r.source_class)
            if source is None:
                raise ValueError(
                    f"rule {r.id!r}: source_class {r.source_class!r} is not in the catalog"
                )
            if not source.exposure:
                raise ValueError(
                    f"rule {r.id!r}: mode 'exposure' requires a source class with "
                    f"exposure: true; {r.source_class!r} is not one"
                )
        marker = r.source_class == UNTRUSTED_ORIGIN
        prov = r.mode == "provenance"
        if prov and not marker:
            raise ValueError(
                f"rule {r.id!r}: mode 'provenance' requires source_class 'untrusted_origin'"
            )
        if marker and not prov:
            raise ValueError(
                f"rule {r.id!r}: source_class 'untrusted_origin' is valid only with "
                "mode 'provenance'"
            )
    # Stable global ordering (C2) - never the filesystem's own iteration
    # order, which isn't guaranteed deterministic across platforms.
    return sorted(rules, key=lambda r: r.id)
