"""In-memory credential values. They never leave the process.

`KnownValues` is the one object in the inventory that holds values, for an
in-process consumer that must match them (the redaction hook). It is built so
that the usual ways a value escapes by accident do not work on it: its repr
shows a count only, it refuses to pickle, and it is not a msgspec Struct, so
it cannot be encoded into a report, a cache or a log line.
"""

from __future__ import annotations

from collections.abc import Iterator


class KnownValues:
    __slots__ = ("_values",)

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, credential_id: str) -> str | None:
        return self._values.get(credential_id)

    def items(self) -> Iterator[tuple[str, str]]:
        """(credential id, value) pairs, sorted by id."""
        for credential_id in sorted(self._values):
            yield credential_id, self._values[credential_id]

    def __len__(self) -> int:
        return len(self._values)

    def __contains__(self, credential_id: object) -> bool:
        return credential_id in self._values

    def __repr__(self) -> str:
        return f"<KnownValues: {len(self._values)} values>"

    __str__ = __repr__

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("KnownValues holds credential values and cannot be pickled")
