"""Keyed fingerprints: HMAC-SHA256 under a local key.

A plain hash of a weak password is a dictionary target, so nothing the
inventory stores is an unkeyed hash. The key is 32 bytes from `secrets`,
written once as hex to a file only the owner can read, and never leaves the
machine. The same key always yields the same fingerprint for the same value,
which is what rotation detection needs: a changed fingerprint means a changed
value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

FINGERPRINT_VERSION = 1
_KEY_BYTES = 32


class FingerprintKeyError(Exception):
    """The fingerprint key file exists but cannot be used."""


def load_or_create_key(path: Path) -> bytes:
    """Read the local key, creating it (mode 0600, parent 0700) when missing.

    A key file that exists but is not exactly 64 hex characters is an error,
    never silently replaced: replacing it would change every fingerprint and
    read as "every credential rotated".
    """
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return _create_key(path)
    except (OSError, UnicodeDecodeError) as exc:
        raise FingerprintKeyError(f"cannot read fingerprint key {path}: {exc}") from exc
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise FingerprintKeyError(f"fingerprint key {path} is not hex") from exc
    if len(key) != _KEY_BYTES:
        raise FingerprintKeyError(f"fingerprint key {path} is not {_KEY_BYTES} bytes")
    return key


def _create_key(path: Path) -> bytes:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_BYTES)
    # O_EXCL: two runs racing to create the key must not each write one and
    # leave fingerprints from the loser that no longer verify.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return load_or_create_key(path)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key.hex() + "\n")
    return key


def fingerprint(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()
