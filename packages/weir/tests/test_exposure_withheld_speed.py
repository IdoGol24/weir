"""Withholding the names that hold a matched value keeps a scan linear in
the size of the export.

An export can carry one distinct credential per span, so a scan can match
as many values as it has spans. Checking every printed name against every
encoded form of every one of them one by one made a scan cost the square
of its size: 2000 spans that each carry their own token took tens of
seconds. The guard times the real scan of one export and of one 4 times its
size, and compares them, so it holds on a slow or a fast machine alike.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from weir.adapters.otel import decode_input
from weir.adapters.otel.exposure import scan_surface
from weir.catalog import DEFAULT_CATALOG
from weir.exposure import ExposureHit, classify_exposure
from weir.schema.exposure import ExposureSurface

_SPANS = 200
_GROWTH = 4
# A linear scan of the larger export takes about _GROWTH times as long; one
# that checks every name against every value's forms takes about _GROWTH
# squared times as long.
_MAX_RATIO = 2.0 * _GROWTH
_REPEATS = 3


def _surface(spans: int) -> ExposureSurface:
    """`spans` spans, each with its own token in a URL query."""
    doc = {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "spanId": f"{i:016x}",
                                "name": "GET /v1/models",
                                "attributes": [
                                    {
                                        "key": "url.full",
                                        "value": {
                                            "stringValue": "https://api.provider.invalid/v1"
                                            f"?token={f'{i:032x}'[::-1]}"
                                        },
                                    }
                                ],
                            }
                            for i in range(spans)
                        ]
                    }
                ]
            }
        ]
    }
    return scan_surface(decode_input(json.dumps(doc).encode()))


def _best_time(run: Callable[[], list[ExposureHit]]) -> float:
    best = float("inf")
    for _ in range(_REPEATS):
        start = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - start)
    return best


def test_a_value_per_span_scans_in_time_linear_in_the_export() -> None:
    small, large = _surface(_SPANS), _surface(_SPANS * _GROWTH)

    def scan(surface: ExposureSurface) -> Callable[[], list[ExposureHit]]:
        return lambda: classify_exposure(surface, DEFAULT_CATALOG).hits

    assert len(scan(small)()) == _SPANS
    assert len(scan(large)()) == _SPANS * _GROWTH
    ratio = _best_time(scan(large)) / _best_time(scan(small))
    assert ratio < _MAX_RATIO, f"{_GROWTH}x the spans took {ratio:.1f}x as long"
