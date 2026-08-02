"""R5.9 structure-class matchers (catalog data, fixture-gated).

For this demo slice only the `iban` class is implemented — the real ISO
13616 signature (2-alpha country + 2 check digits + country-length BBAN),
verified by mod-97 checksum, not a loose regex — so no incidental digit
string in either fixture accidentally clears it.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_IBAN_SHAPE = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$")

# ISO 3166-1 alpha-2 country -> registered IBAN length. Adding a country is a
# catalog-data edit, not a code change (constitution #4) — the demo only
# needs DE, the locked planted secret's country.
_IBAN_LENGTH_BY_COUNTRY: dict[str, int] = {
    "DE": 22,
}


def _mod97_checksum(iban: str) -> int:
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)  # letters -> 10..35
    return int(digits) % 97


def is_iban_structured(value: str) -> bool:
    """ISO 13616: shape, registered length for the country, and mod-97 == 1."""
    candidate = value.strip().upper().replace(" ", "")
    if not _IBAN_SHAPE.fullmatch(candidate):
        return False
    expected_length = _IBAN_LENGTH_BY_COUNTRY.get(candidate[:2])
    if expected_length is None or len(candidate) != expected_length:
        return False
    return _mod97_checksum(candidate) == 1


STRUCTURE_CLASSES: dict[str, Callable[[str], bool]] = {
    "iban": is_iban_structured,
}
