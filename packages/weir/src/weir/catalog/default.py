"""The bundled default catalog (C1).

The catalog itself lives in `bundled/catalog.json`. It used to be a Python
literal here, which made constitution #4's "catalogs are data, never code"
aspirational: adding a source class meant editing engine source. Keep it that
way - if you are about to add a source-spec literal to this module, edit the
JSON instead.

Adding a source class needs three things, not one:

1. The entry in `bundled/catalog.json`. Use `eligibility.pattern` unless the
   type has a real checksum (IBAN's mod-97, PAN's Luhn), which needs a
   `structure_class` validator in `structure_classes.py`.
2. A fixture where the value reaches a sink and the finding fires.
3. **A near-miss fixture that clears `content_pattern` and fails eligibility,
   and must NOT fire.** `content_pattern` is deliberately loose, so without
   the near-miss nothing proves eligibility is discriminating rather than
   waving everything through.

Three false-positive classes are worth knowing. A structural near-miss is what
(3) catches. A structurally valid but non-secret value is not - weir's own demo
secret is the well-known German test IBAN, and 4111111111111111 passes Luhn -
so a production class wants a known-test-value denylist, which is catalog data.
A legitimate flow (an invoice IBAN emailed to its own account holder) cannot be
caught by structure at all; that is what guards are for, and guards are unbuilt,
so weir over-reports on any type whose flow is sometimes authorized.
"""

from __future__ import annotations

from weir.catalog._types import Catalog
from weir.catalog.loader import load_catalog

DEFAULT_CATALOG: Catalog = load_catalog()
