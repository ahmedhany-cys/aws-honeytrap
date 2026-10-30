"""Classify shell commands typed inside the honeypot into behaviours.

Each behaviour carries the ATT&CK technique it is evidence of. Patterns match
on individual shell statements (split on ; && || and |), so one compound
command line like ``cd /tmp; wget http://x/a.sh; chmod +x a.sh; ./a.sh`` yields
several behaviours.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Behaviour:
    behaviour_id: str
    group: str  # discovery | execution | persistence | evasion | ingress | impact | credential | lateral
    technique_id: str
    description: str
    pattern: re.Pattern
    confidence: str = "high"


def _b(bid, group, tid, desc, regex, confidence="high"):
    return Behaviour(bid, group, tid, desc, re.compile(regex, re.IGNORECASE), confidence)


BEHAVIOURS: tuple[Behaviour, ...] = (
    # Discovery
    _b("sysinfo", "discovery", "T1082", "System information discovery",
       r"^\s*(uname\b|lscpu\b|nproc\b|hostnamectl\b|cat\s+/proc/(cpuinfo|meminfo|version)\b|"
       r"cat\s+/etc/(os-release|issue|lsb-release|debian_version)\b|free\b|df\b|lsb_release\b|dmidecode\b|uptime\b)"),
    _b("user_discovery", "discovery", "T1033", "System owner/user discovery",
       r"^\s*(whoami|id|w|who|last|users)\b"),
    _b("account_discovery", "discovery", "T1087.001", "Local account discovery",
       r"^\s*(cat|head|tail|grep|awk|cut)\b.*\s/etc/(passwd|group)\b"),
    _b("network_config", "discovery", "T1016", "System network configuration discovery",
       r"^\s*(ifconfig|ip\s+(a|addr|address|r|route|link)|route|arp|cat\s+/etc/resolv\.conf|iwconfig)\b"),
    _b("network_connections", "discovery", "T1049", "System network connections discovery",
       r"^\s*(netstat|ss)\b"),
    _b("process_discovery", "discovery", "T1057", "Process discovery",
       r"^\s*(ps|top|htop|pgrep)\b"),
    _b("file_discovery", "discovery", "T1083", "File and directory discovery",
       r"^\s*(ls|find|locate|tree)\b"),
    _b("security_software", "discovery", "T1518.001", "Security software discovery",
       r"(ps|pgrep|systemctl|service)\b.*\b(aliyun|aegis|qcloud|bcm-agent|falcon|wazuh|ossec|auditd|crowdstrike|sentinel|clamav|fail2ban)",
       "medium"),
    _b("remote_system_discovery", "lateral", "T1018", "Remote system discovery",
       r"^\s*(ping\s+(-c\s*\d+\s+)?\d+\.\d+\.\d+\.\d+|arp\s+-a|nbtscan|cat\s+/etc/hosts|"
       r"cat\s+~?/?\S*\.ssh/known_hosts)"),
    _b("network_service_scan", "lateral", "T1046", "Network service discovery from the honeypot",
       r"^\s*(nmap|masscan|zmap|rustscan|nc\s+(-\w*z|-z)|ncat\s+-z|pnscan|zgrab)\b"),
    # Credential access
    _b("shadow_dump", "credential", "T1003.008", "Read /etc/shadow",
       r"\b(cat|head|tail|less|more|cp|grep)\b.*\s/etc/shadow\b"),
    _b("credential_files", "credential", "T1552.001", "Searched files for credentials",
       r"(grep|find)\b.*(password|passwd|secret|aws_access_key|\.env\b|id_rsa|credentials)", "medium"),
    # Execution / obfuscation
    _b("decode_payload", "execution", "T1140", "Decoded an encoded payload",
       r"(base64\s+(-d|--decode)|openssl\s+(enc|base64)\s+.*-d|xxd\s+-r|\becho\s+-e\s+['\"]?\\x)"),
    _b("pipe_to_shell", "execution", "T1059.004", "Piped content into a shell interpreter",
       r"\|\s*(ba|da|z|k)?sh\b|^\s*(nohup\s+)?(ba|da)?sh\s+(-c\s|\S+\.sh\b)"),
    _b("exec_from_tmp", "execution", "T1059.004", "Executed a file from a world-writable directory",
       r"^\s*(nohup\s+)?((ba|da)?sh\s+)?(\./|/tmp/|/dev/shm/|/var/tmp/|/run/)\S+"),
    _b("chmod_exec", "execution", "T1222.002", "Made a file executable",
       r"^\s*chmod\s+(\+x|[0-7]*7[0-7]{0,2})\b"),
    # Ingress tool transfer
    _b("download_tool", "ingress", "T1105", "Attempted to download a file",
       r"^\s*(wget|curl|tftp|ftpget|fetch|lwp-download|scp)\b|busybox\s+(wget|tftp|ftpget)\b"),
    # Persistence
    _b("ssh_key_persistence", "persistence", "T1098.004", "Modified SSH authorized_keys",
       r"authorized_keys"),
    _b("cron_persistence", "persistence", "T1053.003", "Created or modified a cron job",
       r"((^|[\s(|])crontab\s+(-e\b|-(\s|$)|[^-\s])|(>>?|\btee\b|\bcp\b|\bmv\b).*(/etc/cron|/var/spool/cron))"),
    _b("account_creation", "persistence", "T1136.001", "Created a local account",
       r"^\s*(useradd|adduser)\b"),
    _b("systemd_persistence", "persistence", "T1543.002", "Created or enabled a systemd service",
       r"(systemctl\s+enable|/etc/systemd/system/\S+\.service)"),
    _b("rc_persistence", "persistence", "T1037.004", "Modified an RC script",
       r"/etc/rc\.local|/etc/init\.d/"),
    _b("password_change", "persistence", "T1098", "Changed an account password",
       r"(^\s*passwd\b|chpasswd\b)"),
    # Stealth / defense impairment
    _b("history_clear", "evasion", "T1070.003", "Cleared shell history",
       r"(history\s+-c|>\s*~?/?\S*\.bash_history|rm\s+.*\.bash_history|cat\s+/dev/null\s*>\s*\S*history)"),
    _b("history_disable", "evasion", "T1690", "Prevented command history logging",
       r"(unset\s+HISTFILE|export\s+HISTFILE=/dev/null|HISTSIZE=0|set\s+\+o\s+history)"),
    _b("file_deletion", "evasion", "T1070.004", "Deleted files to remove traces",
       r"^\s*rm\s+-r?f\w*\s+(/tmp|/var/tmp|/dev/shm|\S*\.(sh|log))", "medium"),
    _b("firewall_tamper", "evasion", "T1686", "Disabled or modified the host firewall",
       r"(iptables\s+(-F|--flush|-X|-P\s+\w+\s+ACCEPT)|ufw\s+disable|systemctl\s+(stop|disable)\s+(firewalld|ufw))"),
    _b("security_tool_kill", "evasion", "T1685", "Stopped or killed security tooling",
       r"(pkill|killall|kill\s+-9|systemctl\s+stop|service\s+\S+\s+stop).*(aliyun|aegis|wazuh|ossec|auditd|falcon|crowdstrike|clamav|fail2ban)",
       "medium"),
    # Impact
    _b("cryptominer", "impact", "T1496.001", "Cryptocurrency miner indicators",
       r"(xmrig|minerd|cpuminer|stratum\+tcp|stratum\+ssl|nicehash|xmr-stak|--donate-level|c3pool|supportxmr)"),
)

_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")


def split_statements(command: str) -> list[str]:
    """Split a command line into statements. Pipes stay inside a statement."""
    return [s for s in _SPLIT.split(command or "") if s.strip()]


def classify(command: str) -> list[Behaviour]:
    """Return the distinct behaviours a command line exhibits, in catalogue order."""
    found: dict[str, Behaviour] = {}
    statements = split_statements(command)
    for behaviour in BEHAVIOURS:
        if any(behaviour.pattern.search(s) for s in statements):
            found[behaviour.behaviour_id] = behaviour
    return list(found.values())


URL_PATTERN = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"|;&<>]+", re.IGNORECASE)


def extract_urls(command: str) -> list[str]:
    return URL_PATTERN.findall(command or "")
