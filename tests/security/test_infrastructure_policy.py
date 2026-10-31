"""Policy-as-code checks on the Terraform source (no AWS account needed).

These encode the isolation and cost guarantees the documentation makes, so a
change that weakens them fails CI instead of silently shipping.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import hcl2
import pytest

TF = Path(__file__).resolve().parents[2] / "terraform"


def _clean(value):
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


@lru_cache(maxsize=1)
def parsed() -> dict[str, dict]:
    out = {}
    for path in TF.rglob("*.tf"):
        if ".terraform" in path.parts:
            continue
        with path.open() as fh:
            out[str(path.relative_to(TF))] = _clean(hcl2.load(fh))
    return out


def blocks(kind: str, rtype: str) -> list[tuple[str, str, dict]]:
    found = []
    for file, doc in parsed().items():
        for block in doc.get(kind, []):
            for t, named in block.items():
                if t == rtype:
                    for name, body in named.items():
                        found.append((file, name, body))
    return found


def text(path: str) -> str:
    return (TF / path).read_text()


ALL_TF = "\n".join(p.read_text() for p in TF.rglob("*.tf") if ".terraform" not in p.parts)


# ----------------------------------------------------------------- network isolation

def test_no_costly_or_bridging_network_resources():
    forbidden = ["aws_nat_gateway", "aws_lb", "aws_alb", "aws_elb", "aws_vpc_peering_connection",
                 "aws_ec2_transit_gateway", "aws_vpn_gateway", "aws_eip", "aws_vpc_endpoint_service",
                 "aws_globalaccelerator_accelerator", "aws_guardduty_detector"]
    for rtype in forbidden:
        assert not blocks("resource", rtype), f"{rtype} must not be deployed without approval"
    endpoints = blocks("resource", "aws_vpc_endpoint")
    assert len(endpoints) == 1 and endpoints[0][2]["vpc_endpoint_type"] == "Gateway"


def test_security_group_egress_is_s3_prefix_list_only():
    egress = blocks("resource", "aws_vpc_security_group_egress_rule")
    assert len(egress) == 1
    _, _, rule = egress[0]
    assert "prefix_list_id" in rule and "cidr_ipv4" not in rule and "cidr_ipv6" not in rule
    assert (rule["from_port"], rule["to_port"]) == (443, 443)
    assert not re.search(r'resource\s+"aws_security_group"[^}]*egress\s*{', ALL_TF), "no inline egress blocks"


def test_ingress_is_decoy_ports_plus_optional_admin():
    rules = {name: body for _, name, body in blocks("resource", "aws_vpc_security_group_ingress_rule")}
    assert set(rules) == {"ssh", "telnet", "admin"}
    assert rules["ssh"]["from_port"] == rules["ssh"]["to_port"] == 22
    assert rules["telnet"]["from_port"] == 23 and "enable_telnet" in str(rules["telnet"]["count"])
    assert rules["admin"]["cidr_ipv4"] == "${var.admin_cidr}"
    assert "/32$" in text("variables.tf"), "admin_cidr must be validated as a single host"


def test_default_security_group_is_locked():
    (_, _, sg), = blocks("resource", "aws_default_security_group")
    assert "ingress" not in sg and "egress" not in sg


def test_s3_endpoint_policy_is_scoped():
    doc = text("modules/network/main.tf")
    assert "var.allowed_bucket_arns" in doc and "al2023-repos-" in doc
    assert '"s3:*"' not in doc


# ----------------------------------------------------------------- instance hardening

def test_instance_metadata_and_disk_hardening():
    (_, _, inst), = blocks("resource", "aws_instance")
    md = inst["metadata_options"][0] if isinstance(inst["metadata_options"], list) else inst["metadata_options"]
    assert md["http_tokens"] == "required"
    assert md["http_put_response_hop_limit"] == 1, "hop limit 1 keeps containers away from instance credentials"
    disk = inst["root_block_device"][0] if isinstance(inst["root_block_device"], list) else inst["root_block_device"]
    assert disk["encrypted"] is True
    credit = inst["credit_specification"]
    credit = credit[0] if isinstance(credit, list) else credit
    assert credit["cpu_credits"] == "standard", "unlimited credits can bill"
    assert inst["monitoring"] is False
    assert "t3.micro" in str(inst["lifecycle"]), "instance type precondition must restrict to Free Tier types"


def test_user_data_container_lockdown():
    ud = text("modules/honeypot/user_data.sh.tftpl")
    for needle in ["--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit", "--memory",
                   "-i docker0 -d 169.254.169.254/32 -j DROP", "--ctstate NEW -j DROP",
                   "systemctl disable --now sshd", "PasswordAuthentication no"]:
        assert needle in ud, needle
    assert "--privileged" not in ud and "docker.sock" not in ud
    assert not re.search(r"(AKIA|ASIA)[0-9A-Z]{16}", ud)


def test_user_data_gives_cowrie_every_state_directory():
    # Regression: `install -d -o 10001 a/b/c` leaves the parents a/ and a/b/ owned
    # by root, so Cowrie could not write var/lib/cowrie/ssh_host_rsa_key and the
    # SSH listener never started on the first live deploy.
    ud = text("modules/honeypot/user_data.sh.tftpl")
    loop = re.search(r"for d in ([^;]+); do\n\s*install -d -o 10001 -g 10001", ud)
    assert loop, "state directories must be created one level at a time as uid 10001"
    created = set(loop.group(1).split())
    for leaf in ["var/log/cowrie", "var/lib/cowrie/tty", "var/lib/cowrie/downloads", "var/run"]:
        parts = leaf.split("/")
        for i in range(1, len(parts) + 1):
            assert "/".join(parts[:i]) in created, "/".join(parts[:i])
    assert "HONEYTRAP-SENSOR-HEALTH" in ud, "bootstrap must report the container health to the console"


# ----------------------------------------------------------------- IAM least privilege

def _statements(src: str) -> list[str]:
    return re.findall(r"statement\s*{(.*?)\n  }", src, re.S)


@pytest.mark.parametrize("path", ["modules/honeypot/main.tf", "modules/pipeline/main.tf"])
def test_iam_policies_have_no_wildcard_actions(path):
    src = text(path)
    assert not re.search(r'actions\s*=\s*\[[^\]]*"\*"', src)
    assert not re.search(r'actions\s*=\s*\[[^\]]*"(s3|iam|ec2|sns|ssm|logs):\*"', src)
    for stmt in _statements(src):
        if re.search(r'resources\s*=\s*\["\*"\]', stmt):
            assert "xray:" in stmt, "only X-Ray (no resource-level support) may use Resource *"


def test_sensor_role_is_write_only_to_its_prefix():
    src = text("modules/honeypot/main.tf")
    sensor = src[src.index('data "aws_iam_policy_document" "sensor"'):src.index('resource "aws_iam_role" "sensor"')]
    actions = set(re.findall(r'"(s3:[A-Za-z]+)"', sensor))
    assert actions == {"s3:PutObject", "s3:GetObject"}
    assert "raw/origin=live/sensor=${var.sensor_name}/*" in sensor
    assert "s3:x-amz-server-side-encryption" in sensor
    assert "ListBucket" not in sensor and "DeleteObject" not in sensor


def test_lambdas_cannot_delete_or_touch_raw_writes():
    src = text("modules/pipeline/main.tf")
    assert "DeleteObject" not in src
    write = re.search(r'sid\s*=\s*"WriteProcessed".*?resources\s*=\s*\[(.*?)\]', src, re.S).group(1)
    assert "processed/*" in write and "raw/" not in write


def test_ssm_parameters_are_secure_strings():
    for _, name, body in blocks("resource", "aws_ssm_parameter"):
        assert body["type"] == "SecureString", name


# ----------------------------------------------------------------- storage

def test_s3_public_access_blocked_and_encrypted():
    (_, _, pab), = blocks("resource", "aws_s3_bucket_public_access_block")
    for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert pab[flag] is True
    src = text("modules/storage/main.tf")
    assert 'sse_algorithm = "AES256"' in src
    assert "aws:SecureTransport" in src and "s3:TlsVersion" in src
    assert 'object_ownership = "BucketOwnerEnforced"' in src


def test_lifecycle_expires_sensitive_data():
    src = text("modules/storage/main.tf")
    for prefix in ("raw/", "evidence/", "processed/", "athena-results/", "flowlogs/"):
        assert f'"{prefix}"' in src
    assert "noncurrent_version_expiration" in src and "abort_incomplete_multipart_upload" in src


def test_log_retention_and_query_caps():
    assert "retention_in_days = var.log_retention_days" in text("modules/pipeline/main.tf")
    assert "bytes_scanned_cutoff_per_query" in text("modules/analytics/main.tf")
    assert "enforce_workgroup_configuration    = true" in text("modules/analytics/main.tf")


def test_budgets_exist():
    assert len(blocks("resource", "aws_budgets_budget")) == 2


# ----------------------------------------------------------------- provider / credentials

def test_no_hardcoded_credentials_in_terraform():
    assert not re.search(r"(access_key|secret_key|token)\s*=", ALL_TF)
    assert not re.search(r"(AKIA|ASIA)[0-9A-Z]{16}", ALL_TF)


def test_resources_are_tagged_by_default():
    src = text("providers.tf")
    for tag in ("Project", "Environment", "ManagedBy"):
        assert tag in src
