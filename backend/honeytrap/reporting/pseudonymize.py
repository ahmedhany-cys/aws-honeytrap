"""Pseudonymise public IPv4 addresses for screenshots, exports and reports that leave the team.

``185.220.101.7`` becomes ``185.220.x.x·3f2a``: the /16 stays visible for context,
and the suffix (a keyed HMAC with a random per-process key) keeps attackers
distinguishable without being reversible. With only the /16 known, a plain hash
of the remaining 65,536 candidates could be brute-forced; a secret key can't.
Private, loopback and documentation addresses are left untouched.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from typing import Any

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


class IPPseudonymizer:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)
        self._cache: dict[str, str] = {}

    def ip(self, value: str) -> str:
        if value in self._cache:
            return self._cache[value]
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        if not addr.is_global or addr.version != 4:
            return value
        a, b, _, _ = value.split(".")
        tag = hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:4]
        self._cache[value] = f"{a}.{b}.x.x·{tag}"
        return self._cache[value]

    def text(self, value: str) -> str:
        return _IPV4.sub(lambda m: self.ip(m.group(0)), value)

    def obj(self, value: Any) -> Any:
        """Pseudonymise every IPv4 inside a JSON-serialisable structure (keys included)."""
        return json.loads(self.text(json.dumps(value)))
