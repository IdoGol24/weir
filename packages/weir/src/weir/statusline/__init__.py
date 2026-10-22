"""`weir statusline`: a Claude Code status-line segment and the /weir
session report, built on `weir audit` (docs/statusline.md).

Display only, local and offline: it reads the session files Claude Code
names, with the inventory's keyed fingerprints, and prints counts and
places, never a value.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from weir.audit import Inputs
from weir.audit.matching import Matcher

WITHHELD_SETTING = "[withheld: it holds an inventoried credential]"
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def valid_session_id(session_id: str) -> bool:
    """A session id names one file and one directory: no separator and no
    leading dot."""
    return bool(_SESSION_ID.fullmatch(session_id))


def withholder(inputs: Inputs) -> Callable[[str], str]:
    """Withhold a string (an existing status line command, say) that holds
    an inventoried credential in any form the audit matches."""
    matcher = Matcher(inputs.key, set(inputs.by_fingerprint))
    return lambda text: WITHHELD_SETTING if matcher.find(text) else text
