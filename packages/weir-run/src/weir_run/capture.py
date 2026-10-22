"""The capture directory the judge reads (docs/canary.md, "The capture").

    capture/otlp/<signal>.jsonl   telemetry files (--otlp): one decompressed
                                  OTLP/JSON export request per line
    capture/swept/...             swept files: every other telemetry body and
                                  each flow's stdout and stderr, one file each

The roles are fixed by directory, never guessed from content.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

SIGNALS = ("traces", "logs", "metrics")


def safe_name(text: str) -> str:
    """A file-name segment: id characters other than [A-Za-z0-9._-] become `_`."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


class Capture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.otlp = root / "otlp"
        self.swept = root / "swept"
        self.otlp.mkdir(parents=True)
        self.swept.mkdir(parents=True)
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def otlp_line(self, signal: str, line: bytes) -> None:
        if signal not in SIGNALS or b"\n" in line:
            raise ValueError("an OTLP capture line is one export request of a known signal")
        with self._lock, (self.otlp / f"{signal}.jsonl").open("ab") as f:
            f.write(line + b"\n")

    def swept_file(self, stem: str, data: bytes, suffix: str = ".body") -> str:
        """Write one swept file and return its name under capture/swept."""
        safe = safe_name(stem)
        with self._lock:
            n = self._counts.get(safe, 0) + 1
            self._counts[safe] = n
            name = f"{safe}-{n}{suffix}"
            (self.swept / name).write_bytes(data)
        return name

    def flow_streams(self, index: int, flow_id: str) -> tuple[Path, Path]:
        stem = f"flow-{index:02d}-{safe_name(flow_id)}"
        return self.swept / f"{stem}.stdout", self.swept / f"{stem}.stderr"
