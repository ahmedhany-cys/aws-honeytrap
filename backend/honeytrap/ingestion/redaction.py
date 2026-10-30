"""Handling of attacker-supplied passwords, which we treat as sensitive captured data.

Clear-text passwords exist only in the raw Cowrie log (restricted S3 prefix,
short retention). Everything downstream of the parser sees:

* a masked form for display (``1****6``),
* the length,
* a keyed HMAC-SHA256 fingerprint, so analysts can correlate reuse of the same
  password or username:password pair without storing it. A plain SHA-256 of a
  wordlist password is reversible with a lookup table; a keyed HMAC is not,
  as long as the key stays secret.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

log = logging.getLogger(__name__)

ENV_KEY = "HONEYTRAP_HMAC_KEY"
_DEV_KEY = "honeytrap-local-development-key-not-for-production"
_warned = False


class Redactor:
    def __init__(self, key: str | bytes | None = None) -> None:
        if key is None:
            key = os.environ.get(ENV_KEY)
        if not key:
            global _warned
            if not _warned:
                log.warning("%s not set; using the local development HMAC key", ENV_KEY)
                _warned = True
            key = _DEV_KEY
        self._key = key.encode() if isinstance(key, str) else key

    def fingerprint(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:16]

    def credential_fingerprint(self, username: str, password: str) -> str:
        return self.fingerprint(f"{username}\x00{password}")

    @staticmethod
    def mask(value: str) -> str:
        if len(value) <= 2:
            return "*" * len(value)
        if len(value) <= 4:
            return value[0] + "*" * (len(value) - 1)
        return value[0] + "*" * (len(value) - 2) + value[-1]
