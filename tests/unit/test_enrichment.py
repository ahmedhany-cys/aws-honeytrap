import json
from datetime import datetime, timedelta, timezone

import pytest

from honeytrap.enrichment.providers import AbuseIPDB, GeoIP, VirusTotal, urllib_get
from honeytrap.enrichment.service import EnrichmentService, LocalJsonCache, MemoryCache, is_public_ip, summarise

PUBLIC = "8.8.8.8"


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        return self.responses.pop(0)


def abuse_ok(score=85):
    return 200, json.dumps({"data": {"abuseConfidenceScore": score, "totalReports": 42, "countryCode": "NL",
                                     "isp": "Example ISP", "usageType": "Data Center/Web Hosting/Transit",
                                     "isTor": False}}).encode()


def vt_ok(malicious=6):
    return 200, json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "harmless": 60},
                                                    "country": "NL", "as_owner": "Example AS"}}}).encode()


@pytest.mark.parametrize("ip,public", [("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False),
                                       ("192.0.2.5", False), ("203.0.113.9", False), ("198.51.100.1", False),
                                       ("2001:db8::1", False), ("not-an-ip", False)])
def test_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_non_public_ip_is_never_looked_up():
    http = FakeHttp([])
    svc = EnrichmentService(providers=[AbuseIPDB(api_key="k", http_get=http)])
    result = svc.enrich("192.0.2.10")
    assert result["status"] == "skipped_non_public" and result["sources"] == {}
    assert http.calls == []


def test_unconfigured_providers_report_not_configured():
    svc = EnrichmentService(providers=[AbuseIPDB(api_key=""), VirusTotal(api_key=""), GeoIP(city_db="")])
    result = svc.enrich(PUBLIC)
    assert result["status"] == "not_configured"
    assert summarise(result)["abuse_confidence_score"] is None


def test_abuseipdb_parsing_and_headers():
    http = FakeHttp([abuse_ok()])
    result = AbuseIPDB(api_key="secret", http_get=http).lookup(PUBLIC)
    assert result["status"] == "ok" and result["abuse_confidence_score"] == 85
    url, headers = http.calls[0]
    assert url.startswith("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8")
    assert headers["Key"] == "secret"


def test_virustotal_parsing():
    result = VirusTotal(api_key="k", http_get=FakeHttp([vt_ok()])).lookup(PUBLIC)
    assert result["malicious"] == 6 and result["found"] is True


def test_provider_errors_carry_no_reputation_data():
    result = AbuseIPDB(api_key="k", http_get=FakeHttp([(500, b"oops")])).lookup(PUBLIC)
    assert result == {"status": "error", "error": "HTTP 500"}

    def boom(*_):
        raise TimeoutError("slow")
    result = AbuseIPDB(api_key="k", http_get=boom).lookup(PUBLIC)
    assert result["status"] == "error" and "abuse_confidence_score" not in result


def test_rate_limited_results_are_not_cached():
    cache = MemoryCache()
    http = FakeHttp([(429, b""), abuse_ok()])
    svc = EnrichmentService(providers=[AbuseIPDB(api_key="k", http_get=http)], cache=cache)
    assert svc.enrich(PUBLIC)["status"] == "unavailable"
    assert cache.get(PUBLIC) is None
    assert svc.enrich(PUBLIC)["status"] == "ok"
    assert cache.get(PUBLIC)["status"] == "ok"


def test_cache_ttl(tmp_path):
    now = [datetime(2026, 10, 30, tzinfo=timezone.utc)]
    http = FakeHttp([abuse_ok(10), abuse_ok(99)])
    svc = EnrichmentService(providers=[AbuseIPDB(api_key="k", http_get=http)], cache=LocalJsonCache(tmp_path),
                            ttl_hours=24, clock=lambda: now[0])
    assert svc.enrich(PUBLIC)["cache"] == "miss"
    assert svc.enrich(PUBLIC)["cache"] == "hit"
    assert len(http.calls) == 1
    now[0] += timedelta(hours=25)
    refreshed = svc.enrich(PUBLIC)
    assert refreshed["cache"] == "miss"
    assert refreshed["sources"]["abuseipdb"]["abuse_confidence_score"] == 99


def test_virustotal_client_side_rate_limit():
    t = [0.0]
    vt = VirusTotal(api_key="k", http_get=FakeHttp([vt_ok()] * 5), clock=lambda: t[0])
    statuses = [vt.lookup(PUBLIC)["status"] for _ in range(5)]
    assert statuses == ["ok"] * 4 + ["rate_limited"]
    t[0] = 61
    assert vt.lookup(PUBLIC)["status"] == "ok"


def test_lookup_limit_defers_extra_ips():
    http = FakeHttp([abuse_ok()] * 3)
    svc = EnrichmentService(providers=[AbuseIPDB(api_key="k", http_get=http)])
    out = svc.enrich_many(["8.8.8.8", "1.1.1.1", "9.9.9.9", "192.0.2.1"], limit=2)
    assert [out[ip]["status"] for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "192.0.2.1")] == \
        ["ok", "ok", "deferred", "skipped_non_public"]


def test_only_https_endpoints_are_called():
    with pytest.raises(ValueError):
        urllib_get("http://api.abuseipdb.com/x", {}, 1)
    with pytest.raises(ValueError):
        urllib_get("file:///etc/passwd", {}, 1)


def test_summarise_flags_synthetic():
    record = {"status": "synthetic", "sources": {"abuseipdb": {"status": "synthetic", "abuse_confidence_score": 50},
                                                 "geoip": {"status": "synthetic", "country_code": "DE"}}}
    s = summarise(record)
    assert s["synthetic_enrichment"] is True and s["country_code"] == "DE" and s["abuse_confidence_score"] == 50
