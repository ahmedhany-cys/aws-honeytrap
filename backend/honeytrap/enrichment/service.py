"""Enrichment orchestration with caching and strict 'no data invented' semantics."""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from honeytrap.enrichment.providers import AbuseIPDB, GeoIP, Provider, VirusTotal

log = logging.getLogger(__name__)

# Results with these statuses are transient and are not cached.
_TRANSIENT = {"rate_limited", "error"}


class Cache(Protocol):
    def get(self, ip: str) -> dict[str, Any] | None: ...
    def put(self, ip: str, value: dict[str, Any]) -> None: ...


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}

    def get(self, ip: str) -> dict[str, Any] | None:
        return self.data.get(ip)

    def put(self, ip: str, value: dict[str, Any]) -> None:
        self.data[ip] = value


class LocalJsonCache:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, ip: str) -> Path:
        return self.directory / f"{ip.replace(':', '_')}.json"

    def get(self, ip: str) -> dict[str, Any] | None:
        path = self._path(ip)
        return json.loads(path.read_text()) if path.exists() else None

    def put(self, ip: str, value: dict[str, Any]) -> None:
        self._path(ip).write_text(json.dumps(value, indent=2))


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


class EnrichmentService:
    def __init__(
        self,
        providers: list[Provider] | None = None,
        cache: Cache | None = None,
        ttl_hours: float = 24,
        clock=_now,
    ) -> None:
        self.providers = providers if providers is not None else [AbuseIPDB(), VirusTotal(), GeoIP()]
        self.cache = cache or MemoryCache()
        self.ttl = timedelta(hours=ttl_hours)
        self.clock = clock
        self.lookups = 0

    def _fresh(self, cached: dict[str, Any]) -> bool:
        try:
            fetched = datetime.fromisoformat(cached["fetched_at"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            return False
        return self.clock() - fetched < self.ttl

    def enrich(self, ip: str) -> dict[str, Any]:
        if not is_public_ip(ip):
            return {"ip": ip, "status": "skipped_non_public",
                    "note": "private, loopback, reserved or documentation address - no lookup performed",
                    "sources": {}}
        cached = self.cache.get(ip)
        if cached and self._fresh(cached):
            return {**cached, "cache": "hit"}

        sources = {p.name: p.lookup(ip) for p in self.providers}
        self.lookups += 1
        statuses = {s["status"] for s in sources.values()}
        if statuses == {"not_configured"}:
            overall = "not_configured"
        elif "ok" in statuses:
            overall = "ok"
        else:
            overall = "unavailable"
        result = {
            "ip": ip,
            "status": overall,
            "fetched_at": self.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sources": sources,
        }
        if not statuses & _TRANSIENT:
            self.cache.put(ip, result)
        return {**result, "cache": "miss"}

    def enrich_many(self, ips: list[str], limit: int | None = None) -> dict[str, dict[str, Any]]:
        out = {}
        for ip in dict.fromkeys(ips):
            if limit is not None and self.lookups >= limit and is_public_ip(ip) and not self.cache.get(ip):
                out[ip] = {"ip": ip, "status": "deferred", "note": "per-run lookup limit reached", "sources": {}}
                continue
            out[ip] = self.enrich(ip)
        return out


def summarise(enrichment: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten an enrichment record into the fields the dashboard and severity logic use."""
    if not enrichment:
        return {"enrichment_status": "none"}
    src = enrichment.get("sources", {})
    abuse = src.get("abuseipdb", {})
    vt = src.get("virustotal", {})
    geo = src.get("geoip", {})
    synthetic = enrichment.get("status") == "synthetic"
    return {
        "enrichment_status": enrichment.get("status"),
        "abuse_confidence_score": abuse.get("abuse_confidence_score") if abuse.get("status") in ("ok", "synthetic") else None,
        "abuse_total_reports": abuse.get("total_reports"),
        "vt_malicious": vt.get("malicious") if vt.get("status") in ("ok", "synthetic") else None,
        "country_code": geo.get("country_code") or abuse.get("country_code") or vt.get("country_code"),
        "country": geo.get("country"),
        "city": geo.get("city"),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "isp": abuse.get("isp") or vt.get("as_owner") or geo.get("as_org"),
        "synthetic_enrichment": synthetic,
    }
