"""Run the rule set, apply enrichment-based severity escalation and build attacker profiles."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from honeytrap.config import default_config
from honeytrap.detection.rules import RULES, RuleContext
from honeytrap.enrichment.service import summarise
from honeytrap.models import Alert, Event, Severity

SEVERITY_WEIGHT = {
    Severity.INFORMATIONAL: 1, Severity.LOW: 5, Severity.MEDIUM: 12,
    Severity.HIGH: 25, Severity.CRITICAL: 40,
}


def evaluate(events: list[Event], config: dict | None = None, rule_ids: list[str] | None = None) -> list[Alert]:
    """Evaluate all (or the selected) rules. Each data origin is evaluated in isolation."""
    config = config or default_config()
    by_origin: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_origin[event.data_origin].append(event)

    alerts: dict[str, Alert] = {}
    for origin_events in by_origin.values():
        ctx = RuleContext(events=list(origin_events), config=config)
        for rule_id, (_, fn) in sorted(RULES.items()):
            if rule_ids and rule_id not in rule_ids:
                continue
            for alert in fn(ctx):
                alerts[alert.alert_id] = alert
    return sorted(alerts.values(), key=lambda a: (a.first_seen, a.rule_id))


def apply_enrichment(alerts: list[Alert], enrichment: dict[str, dict[str, Any]], config: dict | None = None) -> None:
    """Escalate alert severity one level per strong, *real* reputation signal.

    Synthetic enrichment (demo data) is shown on the dashboard but never escalates.
    """
    cfg = (config or default_config())["severity"]
    for alert in alerts:
        info = summarise(enrichment.get(alert.src_ip or ""))
        if info.get("synthetic_enrichment"):
            continue
        reasons = []
        score = info.get("abuse_confidence_score")
        if score is not None and score >= cfg["abuseipdb_escalation_score"]:
            reasons.append(f"AbuseIPDB confidence {score} >= {cfg['abuseipdb_escalation_score']}")
        vt = info.get("vt_malicious")
        if vt is not None and vt >= cfg["virustotal_escalation_malicious"]:
            reasons.append(f"{vt} VirusTotal engines flag the IP as malicious")
        if reasons and not any(r.startswith("escalated:") for r in alert.severity_reasons):
            new = alert.severity_level.escalate(1)
            if new != alert.severity_level:
                alert.severity = new.label
                alert.severity_reasons.append("escalated: " + "; ".join(reasons))


def should_notify(alert: Alert, config: dict | None = None) -> bool:
    threshold = Severity.parse((config or default_config())["severity"]["notify_min_severity"])
    return alert.severity_level >= threshold


def actor_type(stats: dict[str, Any], classifications: set[str]) -> str:
    if classifications & {"malware-retrieval", "download", "resource-hijacking"}:
        return "Malware dropper / bot loader"
    if classifications & {"persistence", "defense-evasion", "tunneling"} or stats["commands"] >= 5:
        return "Interactive intruder"
    if stats["commands"] > 0:
        return "Automated post-login script"
    if stats["login_attempts"] > 0:
        return "Credential brute-forcer"
    return "Scanner / probe"


def risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Informational"


def build_profiles(events: list[Event], alerts: list[Alert],
                   enrichment: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """One row per (source IP, data origin) for the attacker-investigation views."""
    enrichment = enrichment or {}
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        grouped[(e.src_ip, e.data_origin)].append(e)
    alerts_by_ip: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for a in alerts:
        for ip in ([a.src_ip] if a.src_ip else a.related_ips):
            alerts_by_ip[(ip, a.data_origin)].append(a)

    profiles = []
    for (ip, origin), evs in grouped.items():
        types = Counter(e.event_type for e in evs)
        ip_alerts = alerts_by_ip.get((ip, origin), [])
        stats = {
            "sessions": len({e.session_id for e in evs if e.session_id}),
            "login_attempts": types["cowrie.login.failed"] + types["cowrie.login.success"],
            "failed_logins": types["cowrie.login.failed"],
            "successful_logins": types["cowrie.login.success"],
            "commands": types["cowrie.command.input"],
            "downloads": sum(v for k, v in types.items() if k.startswith("cowrie.session.file_")),
        }
        info = summarise(enrichment.get(ip))
        score = sum(SEVERITY_WEIGHT[a.severity_level] for a in ip_alerts)
        if info.get("abuse_confidence_score") and not info.get("synthetic_enrichment"):
            score += int(info["abuse_confidence_score"] * 0.2)
        score = min(100, score)
        severities = Counter(a.severity for a in ip_alerts)
        profiles.append({
            "src_ip": ip,
            "data_origin": origin,
            "first_seen": min(e.timestamp for e in evs),
            "last_seen": max(e.timestamp for e in evs),
            "events": len(evs),
            **stats,
            "protocols": sorted({e.protocol for e in evs if e.protocol}),
            "alerts": len(ip_alerts),
            "max_severity": max((a.severity_level for a in ip_alerts), default=Severity.INFORMATIONAL).label,
            "alerts_by_severity": dict(severities),
            "techniques": sorted({t.technique_id for a in ip_alerts for t in a.techniques}),
            "risk_score": score,
            "risk_level": risk_level(score),
            "actor_type": actor_type(stats, {a.classification for a in ip_alerts}),
            **info,
        })
    return sorted(profiles, key=lambda p: (-p["risk_score"], p["src_ip"]))
