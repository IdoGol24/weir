"""The fingerprint key file is its owner's alone (docs/inventory.md, `--key`).

Anyone who can read the key can test a guess against every fingerprint
made under it, so a key file another user owns, or that others can read or
write, is refused, never used and never silently repaired: the person
decides who else had it.
"""

from __future__ import annotations

import os
import stat


def key_file_problem(st: os.stat_result) -> str | None:
    """Why a key file with this status is not private to the running user,
    or None. Only POSIX systems have the owner and mode bits this checks."""
    if os.name != "posix":
        return None
    if st.st_uid != os.getuid():
        return f"is owned by another user (uid {st.st_uid})"
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        return f"is readable or writable by others (mode {mode:04o}); make it 0600 to use it"
    return None
