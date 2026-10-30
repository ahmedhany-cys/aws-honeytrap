"""Detection rules.

Every rule is a function ``(ctx) -> list[Alert]``. Rules only see events of a
single data origin (the engine partitions first), so a simulated event can
never contribute to an alert about live traffic or the other way round.

Alert IDs are deterministic: sha256(rule | entity | window start). Re-running a
rule over a larger window updates the same alert instead of creating a new one.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from honeytrap.detection.commands import BEHAVIOURS, Behaviour, classify, extract_urls
from honeytrap.ingestion.parser import parse_timestamp
from honeytrap.mitre.catalog import map_technique
from honeytrap.models import Alert, Event, Severity, TechniqueMapping

MAX_EVIDENCE_IDS = 50


@dataclass
class RuleContext:
    events: list[Event]
    config: dict
    by_ip: dict[str, list[Event]] = field(default_factory=dict)
    by_session: dict[str, list[Event]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.events.sort(key=lambda e: (e.timestamp, e.event_id))
        by_ip: dict[str, list[Event]] = defaultdict(list)
        by_session: dict[str, list[Event]] = defaultdict(list)
        for event in self.events:
            by_ip[event.src_ip].append(event)
            if event.session_id:
                by_session[event.session_id].append(event)
        self.by_ip = dict(by_ip)
        self.by_session = dict(by_session)


# --------------------------------------------------------------------------- helpers

def window_start(timestamp: str, minutes: float) -> str:
    epoch = parse_timestamp(timestamp).timestamp()
    size = minutes * 60
    start = datetime.fromtimestamp(epoch - (epoch % size), tz=timezone.utc)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def bucket(events: Iterable[Event], minutes: float) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        out[window_start(event.timestamp, minutes)].append(event)
    return out


def alert_id(rule_id: str, entity: str, key: str) -> str:
    return hashlib.sha256(f"{rule_id}|{entity}|{key}".encode()).hexdigest()[:20]


def make_alert(
    *,
    rule: RuleMeta,
    entity: str,
    key: str,
    events: list[Event],
    summary: str,
    severity: Severity,
    techniques: list[TechniqueMapping],
    evidence: dict,
    severity_reasons: list[str] | None = None,
    src_ip: str | None = None,
    related_ips: list[str] | None = None,
) -> Alert:
    ips = sorted({e.src_ip for e in events})
    return Alert(
        alert_id=alert_id(rule.rule_id, entity, key),
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=severity.label,
        entity=entity,
        src_ip=src_ip if src_ip is not None else (ips[0] if len(ips) == 1 else None),
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        summary=summary,
        data_origin=events[0].data_origin,
        session_ids=sorted({e.session_id for e in events if e.session_id})[:50],
        related_ips=related_ips if related_ips is not None else ips,
        evidence_event_ids=[e.event_id for e in events][:MAX_EVIDENCE_IDS],
        evidence=evidence,
        techniques=techniques,
        severity_reasons=severity_reasons or [f"base severity for {rule.rule_id}"],
        classification=rule.classification,
    )


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    classification: str
    description: str


RULES: dict[str, tuple[RuleMeta, Callable[[RuleContext], list[Alert]]]] = {}


def rule(rule_id: str, name: str, classification: str, description: str):
    def register(fn):
        RULES[rule_id] = (RuleMeta(rule_id, name, classification, description), fn)
        return fn
    return register


def _meta(rule_id: str) -> RuleMeta:
    return RULES[rule_id][0]


def _failed_logins(events: Iterable[Event]) -> list[Event]:
    return [e for e in events if e.event_type == "cowrie.login.failed"]


def _logins(events: Iterable[Event]) -> list[Event]:
    return [e for e in events if e.event_type in ("cowrie.login.failed", "cowrie.login.success")]


def _top(counter: Counter, n: int = 5) -> list[list]:
    return [[k, v] for k, v in counter.most_common(n)]


# --------------------------------------------------------------------------- authentication

@rule("HT-AUTH-001", "SSH/Telnet brute force", "brute-force",
      "Many failed logins from one source IP inside a tumbling window.")
def brute_force(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["brute_force"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        for start, window in bucket(_failed_logins(events), cfg["window_minutes"]).items():
            if len(window) < cfg["failed_logins"]:
                continue
            users = Counter(e.username for e in window)
            focused = sum(c for _, c in users.most_common(3)) / len(window) >= 0.8
            evidence_line = (f"{len(window)} failed logins from {ip} in {cfg['window_minutes']} min "
                             f"against {len(users)} username(s): {', '.join(u for u, _ in users.most_common(5))}")
            techniques = [map_technique("T1110", confidence="high", evidence=[evidence_line])]
            if focused:
                techniques.append(map_technique(
                    "T1110.001", confidence="medium",
                    evidence=[f"{len(window)} attempts concentrated on {len(users)} account(s); "
                              "many passwords per account indicates password guessing"]))
            high = len(window) >= cfg["high_severity_failed_logins"]
            alerts.append(make_alert(
                rule=_meta("HT-AUTH-001"), entity=f"ip:{ip}", key=start, events=window,
                summary=f"{len(window)} failed logins from {ip} within {cfg['window_minutes']} minutes",
                severity=Severity.HIGH if high else Severity.MEDIUM,
                severity_reasons=[f">= {cfg['high_severity_failed_logins']} failed logins" if high
                                  else f">= {cfg['failed_logins']} failed logins"],
                techniques=techniques,
                evidence={"failed_logins": len(window), "window_start": start,
                          "distinct_usernames": len(users), "top_usernames": _top(users),
                          "protocols": sorted({e.protocol or "unknown" for e in window})},
            ))
    return alerts


@rule("HT-AUTH-002", "Password spraying", "credential-stuffing",
      "One password tried against many different usernames from one IP.")
def password_spraying(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["password_spraying"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        for start, window in bucket(_logins(events), cfg["window_minutes"]).items():
            by_password: dict[str, list[Event]] = defaultdict(list)
            for e in window:
                if e.password_fingerprint:
                    by_password[e.password_fingerprint].append(e)
            for fp, attempts in by_password.items():
                users = sorted({e.username for e in attempts})
                if len(users) < cfg["distinct_usernames"]:
                    continue
                masked = attempts[0].password_masked
                alerts.append(make_alert(
                    rule=_meta("HT-AUTH-002"), entity=f"ip:{ip}", key=f"{start}|{fp}", events=attempts,
                    summary=f"Password {masked} sprayed across {len(users)} usernames from {ip}",
                    severity=Severity.MEDIUM,
                    techniques=[map_technique("T1110.003", confidence="high", evidence=[
                        f"password fingerprint {fp} ({masked}) used for {len(users)} usernames: {', '.join(users[:8])}"])],
                    evidence={"password_masked": masked, "password_fingerprint": fp,
                              "usernames": users[:25], "attempts": len(attempts), "window_start": start},
                ))
    return alerts


@rule("HT-AUTH-003", "Repeated credential combination", "brute-force",
      "The same username:password pair retried from one IP.")
def repeated_credentials(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["repeated_credentials"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        for start, window in bucket(_logins(events), cfg["window_minutes"]).items():
            pairs: dict[str, list[Event]] = defaultdict(list)
            for e in window:
                if e.credential_fingerprint:
                    pairs[e.credential_fingerprint].append(e)
            repeated = {fp: evs for fp, evs in pairs.items() if len(evs) >= cfg["repeats"]}
            if not repeated:
                continue
            flat = sorted((e for evs in repeated.values() for e in evs), key=lambda e: e.timestamp)
            detail = [{"credential_fingerprint": fp, "username": evs[0].username,
                       "password_masked": evs[0].password_masked, "attempts": len(evs)}
                      for fp, evs in sorted(repeated.items(), key=lambda kv: -len(kv[1]))]
            alerts.append(make_alert(
                rule=_meta("HT-AUTH-003"), entity=f"ip:{ip}", key=start, events=flat,
                summary=f"{len(repeated)} credential pair(s) retried >= {cfg['repeats']} times from {ip}",
                severity=Severity.LOW,
                techniques=[map_technique("T1110", confidence="medium", evidence=[
                    f"{d['username']}/{d['password_masked']} tried {d['attempts']} times" for d in detail[:5]])],
                evidence={"repeated_pairs": detail[:20], "window_start": start},
            ))
    return alerts


@rule("HT-AUTH-004", "Credential stuffing pattern", "credential-stuffing",
      "Many distinct username:password pairs, few repeats - consistent with a combo list.")
def credential_stuffing(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["credential_stuffing"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        for start, window in bucket(_logins(events), cfg["window_minutes"]).items():
            pairs = Counter(e.credential_fingerprint for e in window if e.credential_fingerprint)
            users = {e.username for e in window}
            if not pairs or len(pairs) < cfg["distinct_pairs"] or len(users) < cfg["distinct_usernames"]:
                continue
            attempts = sum(pairs.values())
            repeat_ratio = 1 - len(pairs) / attempts
            if repeat_ratio > cfg["max_repeat_ratio"]:
                continue
            alerts.append(make_alert(
                rule=_meta("HT-AUTH-004"), entity=f"ip:{ip}", key=start, events=window,
                summary=f"{len(pairs)} distinct credential pairs across {len(users)} usernames from {ip}",
                severity=Severity.MEDIUM,
                techniques=[map_technique("T1110.004", confidence="low", evidence=[
                    f"{len(pairs)} distinct pairs, {len(users)} usernames, repeat ratio {repeat_ratio:.2f}; "
                    "pattern matches a combo list, but the honeypot cannot prove the pairs came from a breach"])],
                evidence={"distinct_pairs": len(pairs), "distinct_usernames": len(users),
                          "attempts": attempts, "repeat_ratio": round(repeat_ratio, 3), "window_start": start},
            ))
    return alerts


@rule("HT-AUTH-005", "Credential pair shared across IPs", "credential-stuffing",
      "The same username:password pair attempted from several source IPs (shared wordlist / botnet).")
def shared_credentials(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["shared_credentials"]
    alerts = []
    for start, window in bucket(_logins(ctx.events), cfg["window_hours"] * 60).items():
        pairs: dict[str, list[Event]] = defaultdict(list)
        for e in window:
            if e.credential_fingerprint:
                pairs[e.credential_fingerprint].append(e)
        for fp, evs in pairs.items():
            ips = sorted({e.src_ip for e in evs})
            if len(ips) < cfg["distinct_ips"]:
                continue
            label = f"{evs[0].username}/{evs[0].password_masked}"
            alerts.append(make_alert(
                rule=_meta("HT-AUTH-005"), entity=f"credential:{fp}", key=start, events=evs,
                summary=f"Credential pair {label} attempted from {len(ips)} different IPs",
                severity=Severity.INFORMATIONAL, related_ips=ips,
                severity_reasons=["campaign intelligence: shared wordlist / botnet indicator"],
                techniques=[map_technique("T1110", confidence="medium", evidence=[
                    f"pair {label} (fingerprint {fp}) seen from {len(ips)} IPs: {', '.join(ips[:6])}"])],
                evidence={"credential_fingerprint": fp, "username": evs[0].username,
                          "password_masked": evs[0].password_masked, "distinct_ips": len(ips),
                          "attempts": len(evs), "window_start": start},
            ))
    return alerts


@rule("HT-AUTH-006", "Successful honeypot login", "successful-login",
      "An attacker authenticated to the emulated shell with credentials the decoy accepts.")
def successful_login(ctx: RuleContext) -> list[Alert]:
    defaults = {u.lower() for u in ctx.config["successful_login"]["default_account_names"]}
    alerts = []
    for session_id, events in ctx.by_session.items():
        success = [e for e in events if e.event_type == "cowrie.login.success"]
        if not success:
            continue
        login = success[0]
        line = f"session {session_id}: login as {login.username} with password {login.password_masked} accepted"
        techniques = [map_technique("T1078", confidence="medium", evidence=[line])]
        if (login.username or "").lower() in defaults:
            techniques.append(map_technique("T1078.001", confidence="medium", evidence=[
                f"'{login.username}' is a default/well-known account name"]))
        alerts.append(make_alert(
            rule=_meta("HT-AUTH-006"), entity=f"session:{session_id}", key=session_id, events=success,
            summary=f"{login.src_ip} logged in to the decoy as {login.username} over {login.protocol or 'ssh'}",
            severity=Severity.MEDIUM, techniques=techniques,
            evidence={"username": login.username, "password_masked": login.password_masked,
                      "protocol": login.protocol, "session_id": session_id},
        ))
    return alerts


# --------------------------------------------------------------------------- network / session

@rule("HT-NET-001", "High-frequency connection attempts", "scanning",
      "Connection rate from one IP above threshold - automated scanning or brute-force tooling.")
def high_frequency(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["high_frequency"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        connects = [e for e in events if e.event_type == "cowrie.session.connect"]
        for start, window in bucket(connects, cfg["window_minutes"]).items():
            if len(window) < cfg["connections"]:
                continue
            ports = Counter(e.dst_port for e in window)
            alerts.append(make_alert(
                rule=_meta("HT-NET-001"), entity=f"ip:{ip}", key=start, events=window,
                summary=f"{len(window)} connections from {ip} in {cfg['window_minutes']} minute(s)",
                severity=Severity.LOW,
                techniques=[map_technique("T1595", confidence="medium", evidence=[
                    f"{len(window)} TCP sessions opened in {cfg['window_minutes']} min to ports "
                    f"{', '.join(str(p) for p in ports)}"])],
                evidence={"connections": len(window), "window_start": start,
                          "destination_ports": _top(ports)},
            ))
    return alerts


@rule("HT-NET-002", "Multiple sessions from same IP", "repeated-sessions",
      "Repeat visits from one IP within the window.")
def multiple_sessions(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.config["multiple_sessions"]
    alerts = []
    for ip, events in ctx.by_ip.items():
        for start, window in bucket(events, cfg["window_hours"] * 60).items():
            sessions = {e.session_id for e in window if e.session_id}
            if len(sessions) < cfg["sessions"]:
                continue
            successful = {e.session_id for e in window if e.event_type == "cowrie.login.success"}
            connects = [e for e in window if e.event_type == "cowrie.session.connect"] or window
            alerts.append(make_alert(
                rule=_meta("HT-NET-002"), entity=f"ip:{ip}", key=start, events=connects,
                summary=f"{len(sessions)} sessions from {ip} in {cfg['window_hours']}h"
                        + (f", {len(successful)} with a successful login" if successful else ""),
                severity=Severity.MEDIUM if successful else Severity.LOW,
                severity_reasons=["repeat sessions include successful logins" if successful
                                  else f">= {cfg['sessions']} sessions"],
                techniques=[],
                evidence={"sessions": len(sessions), "sessions_with_login": len(successful),
                          "window_start": start},
            ))
    return alerts


@rule("HT-NET-003", "SSH tunnelling attempt", "tunneling",
      "direct-tcpip forwarding request: attacker tried to proxy traffic through the decoy.")
def tunnel_attempt(ctx: RuleContext) -> list[Alert]:
    alerts = []
    for session_id, events in ctx.by_session.items():
        requests = [e for e in events if e.event_type == "cowrie.direct-tcpip.request"]
        if not requests:
            continue
        destinations = sorted({e.tunnel_destination or "unknown" for e in requests})
        line = f"{len(requests)} direct-tcpip request(s) to {', '.join(destinations[:5])}"
        alerts.append(make_alert(
            rule=_meta("HT-NET-003"), entity=f"session:{session_id}", key=session_id, events=requests,
            summary=f"{requests[0].src_ip} tried to tunnel through the decoy to {destinations[0]}",
            severity=Severity.MEDIUM,
            techniques=[map_technique("T1090", confidence="high", evidence=[line]),
                        map_technique("T1572", confidence="medium", evidence=[line])],
            evidence={"destinations": destinations[:20], "requests": len(requests)},
        ))
    return alerts


# --------------------------------------------------------------------------- shell activity

def _session_behaviours(events: list[Event]) -> tuple[list[Event], dict[str, list[tuple[Behaviour, Event]]]]:
    commands = [e for e in events if e.event_type == "cowrie.command.input" and e.command]
    hits: dict[str, list[tuple[Behaviour, Event]]] = defaultdict(list)
    for e in commands:
        for b in classify(e.command):
            hits[b.group].append((b, e))
    return commands, hits


def _techniques_from(hits: list[tuple[Behaviour, Event]]) -> list[TechniqueMapping]:
    by_tid: dict[str, list[tuple[Behaviour, Event]]] = defaultdict(list)
    for b, e in hits:
        by_tid[b.technique_id].append((b, e))
    out = []
    for tid, items in by_tid.items():
        confidence = "high" if any(b.confidence == "high" for b, _ in items) else "medium"
        evidence = list(dict.fromkeys(f"$ {e.command}" for _, e in items))
        out.append(map_technique(tid, confidence=confidence, evidence=evidence))
    return out


_COMMAND_RULES = {
    # group: (rule_id, severity)
    "discovery": ("HT-CMD-001", Severity.LOW),
    "execution": ("HT-CMD-002", Severity.MEDIUM),
    "persistence": ("HT-CMD-003", Severity.HIGH),
    "evasion": ("HT-CMD-004", Severity.MEDIUM),
    "credential": ("HT-CMD-005", Severity.MEDIUM),
    "lateral": ("HT-CMD-006", Severity.HIGH),
    "impact": ("HT-CMD-007", Severity.HIGH),
}


def _command_rule(group: str):
    rule_id, base = _COMMAND_RULES[group]

    def evaluate(ctx: RuleContext) -> list[Alert]:
        alerts = []
        for session_id, events in ctx.by_session.items():
            _, hits = _session_behaviours(events)
            group_hits = hits.get(group)
            if not group_hits:
                continue
            severity, reasons = base, [f"base severity for {rule_id}"]
            techniques = _techniques_from(group_hits)
            if group == "discovery":
                threshold = ctx.config["discovery"]["medium_severity_techniques"]
                if len(techniques) >= threshold:
                    severity, reasons = Severity.MEDIUM, [f">= {threshold} distinct discovery techniques"]
            if group == "evasion" and any(b.behaviour_id in ("firewall_tamper", "security_tool_kill")
                                          for b, _ in group_hits):
                severity, reasons = Severity.HIGH, ["attempted to impair host defences"]
            hit_events = sorted({e.event_id: e for _, e in group_hits}.values(), key=lambda e: e.timestamp)
            behaviours = sorted({b.description for b, _ in group_hits})
            alerts.append(make_alert(
                rule=_meta(rule_id), entity=f"session:{session_id}", key=session_id, events=hit_events,
                summary=f"{hit_events[0].src_ip}: {'; '.join(behaviours)}",
                severity=severity, severity_reasons=reasons, techniques=techniques,
                evidence={"commands": [e.command for e in hit_events][:25], "behaviours": behaviours},
            ))
        return alerts

    return evaluate


for _group, (_rid, _sev) in _COMMAND_RULES.items():
    _names = {
        "discovery": ("Reconnaissance / discovery commands", "reconnaissance",
                      "System, user, network or process discovery inside the emulated shell."),
        "execution": ("Suspicious shell execution", "suspicious-shell",
                      "Decoding payloads, piping into a shell, executing from /tmp or chmod +x."),
        "persistence": ("Persistence attempt", "persistence",
                        "SSH key, cron, account, systemd, rc-script or password changes."),
        "evasion": ("Defense evasion / impairment", "defense-evasion",
                    "History clearing, log/file deletion, firewall or security tool tampering."),
        "credential": ("Credential access attempt", "credential-access",
                       "Reading /etc/shadow or searching files for secrets."),
        "lateral": ("Network scanning from the honeypot", "scanning",
                    "Attacker tried to use the decoy to discover or scan other hosts."),
        "impact": ("Cryptominer / resource hijacking", "resource-hijacking",
                   "Miner binaries, pool URLs or miner flags in commands."),
    }[_group]
    rule(_rid, *_names)(_command_rule(_group))


# --------------------------------------------------------------------------- downloads

def _download_activity(events: list[Event]):
    commands, hits = _session_behaviours(events)
    download_cmds = [e for b, e in hits.get("ingress", [])]
    file_events = [e for e in events if e.category == "download"]
    return commands, hits, download_cmds, file_events


_OUTCOME = {
    "cowrie.session.file_download": "downloaded",
    "cowrie.session.file_download.failed": "download_failed",
    "cowrie.session.file_upload": "uploaded",
}


@rule("HT-DL-001", "Download / ingress tool transfer attempt", "download",
      "wget/curl/tftp/scp in the shell, or a Cowrie file download/upload event.")
def download_attempt(ctx: RuleContext) -> list[Alert]:
    alerts = []
    for session_id, events in ctx.by_session.items():
        _, _, download_cmds, file_events = _download_activity(events)
        if not download_cmds and not file_events:
            continue
        urls = list(dict.fromkeys(
            [u for e in download_cmds for u in extract_urls(e.command)] + [e.url for e in file_events if e.url]))
        hashes = sorted({e.file_sha256 for e in file_events if e.file_sha256})
        outcomes = Counter(_OUTCOME.get(e.event_type, "other") for e in file_events)
        evidence_lines = [f"$ {e.command}" for e in download_cmds] + \
                         [f"{e.event_type}: {e.url} sha256={e.file_sha256}" for e in file_events]
        hit_events = sorted({e.event_id: e for e in download_cmds + file_events}.values(), key=lambda e: e.timestamp)
        alerts.append(make_alert(
            rule=_meta("HT-DL-001"), entity=f"session:{session_id}", key=session_id, events=hit_events,
            summary=f"{hit_events[0].src_ip} attempted to transfer {len(urls) or len(file_events)} file(s) to the decoy",
            severity=Severity.HIGH,
            techniques=[map_technique("T1105", confidence="high", evidence=evidence_lines)],
            evidence={"urls": urls[:20], "sha256": hashes[:20], "outcomes": dict(outcomes),
                      "commands": [e.command for e in download_cmds][:20]},
        ))
    return alerts


@rule("HT-DL-002", "Potential malware retrieval and execution", "malware-retrieval",
      "A download followed by execution in the same session (download-and-run chain).")
def malware_retrieval(ctx: RuleContext) -> list[Alert]:
    alerts = []
    for session_id, events in ctx.by_session.items():
        commands, hits, download_cmds, file_events = _download_activity(events)
        if not download_cmds and not file_events:
            continue
        exec_hits = [(b, e) for b, e in hits.get("execution", [])
                     if b.behaviour_id in ("pipe_to_shell", "exec_from_tmp", "chmod_exec")]
        names = {u.rstrip("/").rsplit("/", 1)[-1] for e in download_cmds for u in extract_urls(e.command)}
        names |= {(e.url or "").rstrip("/").rsplit("/", 1)[-1] for e in file_events if e.url}
        names.discard("")
        first_download = min(e.timestamp for e in download_cmds + file_events)
        chained = [(b, e) for b, e in exec_hits
                   if e.timestamp >= first_download and (
                       b.behaviour_id == "pipe_to_shell" and extract_urls(e.command)
                       or any(n in e.command for n in names))]
        if not chained:
            continue
        hit_events = sorted({e.event_id: e for e in download_cmds + file_events + [e for _, e in chained]}.values(),
                            key=lambda e: e.timestamp)
        alerts.append(make_alert(
            rule=_meta("HT-DL-002"), entity=f"session:{session_id}", key=session_id, events=hit_events,
            summary=f"{hit_events[0].src_ip} downloaded and tried to execute {', '.join(sorted(names)[:3]) or 'a payload'}",
            severity=Severity.CRITICAL,
            severity_reasons=["download followed by execution of the downloaded file in the same session"],
            techniques=[
                map_technique("T1105", confidence="high", evidence=[f"$ {e.command}" for e in download_cmds]
                              or [f"{e.event_type}: {e.url}" for e in file_events]),
                map_technique("T1059.004", confidence="high", evidence=[f"$ {e.command}" for _, e in chained]),
            ],
            evidence={"payload_names": sorted(names)[:20],
                      "chain": [e.command or f"{e.event_type}: {e.url}" for e in hit_events][:25]},
        ))
    return alerts


def rule_catalog() -> list[dict]:
    """Human-readable rule list for docs and the dashboard."""
    techniques_by_rule = {
        "HT-AUTH-001": ["T1110", "T1110.001"], "HT-AUTH-002": ["T1110.003"], "HT-AUTH-003": ["T1110"],
        "HT-AUTH-004": ["T1110.004"], "HT-AUTH-005": ["T1110"], "HT-AUTH-006": ["T1078", "T1078.001"],
        "HT-NET-001": ["T1595"], "HT-NET-002": [], "HT-NET-003": ["T1090", "T1572"],
        "HT-DL-001": ["T1105"], "HT-DL-002": ["T1105", "T1059.004"],
    }
    for group, (rid, _) in _COMMAND_RULES.items():
        techniques_by_rule[rid] = sorted({b.technique_id for b in BEHAVIOURS if b.group == group})
    return [{"rule_id": m.rule_id, "name": m.name, "classification": m.classification,
             "description": m.description, "techniques": techniques_by_rule.get(m.rule_id, [])}
            for m, _ in sorted(RULES.values(), key=lambda r: r[0].rule_id)]
