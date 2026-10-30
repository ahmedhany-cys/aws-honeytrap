"""Optional threat-intelligence providers. All are free-tier compatible and all are optional.

A provider that is not configured returns ``{"status": "not_configured"}``. A
provider never invents data: on any error the result says so and carries no
reputation fields.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable
from typing import Any

HttpGet = Callable[[str, dict[str, str], float], tuple[int, bytes]]


def urllib_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("enrichment providers only call https:// endpoints")
    request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 - scheme checked above
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


class Provider:
    name = "provider"

    def __init__(self, http_get: HttpGet = urllib_get, timeout: float = 5.0) -> None:
        self.http_get = http_get
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        raise NotImplementedError

    def lookup(self, ip: str) -> dict[str, Any]:
        if not self.configured:
            return {"status": "not_configured"}
        try:
            return self._lookup(ip)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:200]}

    def _lookup(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError


class AbuseIPDB(Provider):
    """https://docs.abuseipdb.com/#check-endpoint - free plan: 1,000 checks/day."""

    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key if api_key is not None else os.environ.get("ABUSEIPDB_API_KEY", "")

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _lookup(self, ip: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        status, body = self.http_get(f"{self.URL}?{query}",
                                     {"Key": self.api_key, "Accept": "application/json"}, self.timeout)
        if status == 429:
            return {"status": "rate_limited"}
        if status != 200:
            return {"status": "error", "error": f"HTTP {status}"}
        data = json.loads(body)["data"]
        return {
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
        }


class VirusTotal(Provider):
    """https://docs.virustotal.com/reference/ip-info - public API: 4 req/min, 500/day."""

    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/ip_addresses/"
    PER_MINUTE = 4

    def __init__(self, api_key: str | None = None, clock: Callable[[], float] = time.monotonic, **kwargs) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key if api_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.clock = clock
        self._calls: deque[float] = deque()

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _lookup(self, ip: str) -> dict[str, Any]:
        now = self.clock()
        while self._calls and now - self._calls[0] > 60:
            self._calls.popleft()
        if len(self._calls) >= self.PER_MINUTE:
            # Do not sleep inside a Lambda; leave it uncached so a later run retries.
            return {"status": "rate_limited"}
        self._calls.append(now)
        status, body = self.http_get(self.URL + urllib.parse.quote(ip),
                                     {"x-apikey": self.api_key, "Accept": "application/json"}, self.timeout)
        if status == 429:
            return {"status": "rate_limited"}
        if status == 404:
            return {"status": "ok", "found": False}
        if status != 200:
            return {"status": "error", "error": f"HTTP {status}"}
        attrs = json.loads(body)["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status": "ok",
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "country_code": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
        }


class GeoIP(Provider):
    """Local MaxMind GeoLite2 database (free licence key required to download it).

    Set HONEYTRAP_GEOIP_CITY_DB (and optionally HONEYTRAP_GEOIP_ASN_DB) to .mmdb paths.
    Requires the optional ``maxminddb`` package.
    """

    name = "geoip"

    def __init__(self, city_db: str | None = None, asn_db: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.city_db = city_db if city_db is not None else os.environ.get("HONEYTRAP_GEOIP_CITY_DB", "")
        self.asn_db = asn_db if asn_db is not None else os.environ.get("HONEYTRAP_GEOIP_ASN_DB", "")
        self._readers: dict[str, Any] = {}

    @property
    def configured(self) -> bool:
        if not self.city_db or not os.path.exists(self.city_db):
            return False
        try:
            import maxminddb  # noqa: F401
        except ImportError:
            return False
        return True

    def _reader(self, path: str):
        import maxminddb

        if path not in self._readers:
            self._readers[path] = maxminddb.open_database(path)
        return self._readers[path]

    def _lookup(self, ip: str) -> dict[str, Any]:
        record = self._reader(self.city_db).get(ip) or {}
        if not record:
            return {"status": "ok", "found": False}
        location = record.get("location", {})
        result = {
            "status": "ok",
            "found": True,
            "country_code": record.get("country", {}).get("iso_code"),
            "country": record.get("country", {}).get("names", {}).get("en"),
            "city": record.get("city", {}).get("names", {}).get("en"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
        }
        if self.asn_db and os.path.exists(self.asn_db):
            asn = self._reader(self.asn_db).get(ip) or {}
            result["asn"] = asn.get("autonomous_system_number")
            result["as_org"] = asn.get("autonomous_system_organization")
        return result
