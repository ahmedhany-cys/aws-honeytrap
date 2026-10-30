# Security design and isolation strategy

A honeypot is an internet-facing system that we *want* to be attacked. The design goal is therefore not "prevent compromise" but **contain it**:

* nothing the attacker does can reach any other system;
* nothing the attacker does can reach AWS credentials or our data;
* nothing the attacker does can turn our sensor into an attack platform against third parties.

## Threat model

| Threat | Control | Verified by |
|---|---|---|
| Attacker escapes the emulated shell and runs code on the host | Cowrie is an *emulator*: commands are parsed by Python handlers, never passed to a real shell. It runs as uid 10001 in a container with a read-only root filesystem, `--cap-drop ALL`, `no-new-privileges`, and memory/CPU/PID limits. | `test_user_data_container_lockdown`; CI `docker inspect` output |
| Host or container used to attack or scan third parties | 1. The security group allows egress **only** to TCP/443 on the S3 managed prefix list. 2. Host iptables `DOCKER-USER` drops **every** new outbound connection from the Docker bridge, including DNS. 3. Cowrie refuses non-global download targets. | `test_security_group_egress_is_s3_prefix_list_only`, CI simulation (blocked download never yields a payload) |
| Theft of AWS credentials from the sensor | IMDSv2 required with **hop limit 1**, so a container one network hop away cannot obtain a token. iptables also drops container traffic to 169.254.169.254. No access keys exist anywhere on the host. | `test_instance_metadata_and_disk_hardening` |
| Credentials obtained anyway (defence in depth) | The instance role can only `s3:PutObject` under `raw/origin=live/sensor=<name>/` and `evidence/…/<name>/` (SSE required), and `s3:GetObject` on its two boot artifacts. It has no List, Delete, or read access to telemetry, and no IAM, EC2 or other service permissions. | `test_sensor_role_is_write_only_to_its_prefix` |
| Data exfiltration via S3 to an attacker-owned bucket | The S3 gateway endpoint policy allows only the HoneyTrap buckets and the Amazon Linux 2023 repo bucket, so the endpoint cannot be used to reach any other bucket. | `test_s3_endpoint_policy_is_scoped` |
| Lateral movement to other environments | Dedicated VPC (10.42.0.0/16) with no peering, transit gateway, VPN or NAT. The default security group is stripped of all rules. NACL restricts inbound traffic to the decoy ports. | `test_no_costly_or_bridging_network_resources`, `test_default_security_group_is_locked` |
| Management interface exposed | The real `sshd` is **disabled** by default. Optional operator access listens on port 22022, only from a single validated `/32`, key-only, with root login disabled. | `test_ingress_is_decoy_ports_plus_optional_admin` |
| Leak of captured sensitive data | Attacker-typed passwords exist in clear text only in `raw/`: SSE-S3, TLS ≥ 1.2 enforced, public access blocked, 14–30-day expiry. The processed layer stores only a masked form and a **keyed HMAC** fingerprint (key in SSM SecureString). Exports and the dashboard never see clear text. | `test_login_failure_is_redacted`, `test_process_batch_end_to_end` |
| Decoy credentials mistaken for real ones | Every "secret" in the fake filesystem is a documented decoy prefixed `decoy-` and is valid nowhere. | `test_decoy_credentials_are_obviously_fake` |
| Simulated or synthetic activity reported as real | Every record carries `data_origin`. Rules run per origin, and S3 keys, Athena partitions, alerts, SNS subjects, reports and dashboard banners all show it. | `test_origins_are_never_correlated` |
| Secrets committed to git | gitleaks in CI, pattern-based repository tests, `.gitignore` for data, state, `.env` and runtime files. | `tests/security/test_repository_hygiene.py` |
| Supply chain | Python dependencies pinned and audited with `pip-audit` in CI. Base image pinned by tag. The engine and Lambdas use only the standard library (and the runtime's boto3), so the Lambda package has no third-party code. | CI `dependencies` job |

## Network isolation in detail

```
Internet ──22/tcp (23 optional)──▶ [NACL] ──▶ [SG: in 22/23] ──▶ EC2 ──DNAT──▶ Cowrie container
                                                                  │
                         S3 prefix list:443 only ◀── [SG egress] ─┘   (host shipper + dnf only)
                                                                  │
                         Docker bridge ──X── DOCKER-USER DROP (NEW) ─ container can only *answer*
```

* **Routing.** The subnet has a default route to the internet gateway, because attackers' TCP sessions must be answered. Outbound *initiation* is blocked at three layers: the security group, host iptables, and Cowrie's own download guard.
* **The host itself** can reach only S3 (artifacts, telemetry, and the Amazon Linux package repo) through the gateway endpoint. It cannot reach the internet, so there is no NAT gateway and no data-transfer path to third parties.
* **DNS.** The Amazon-provided resolver is not filtered by security groups, which is a well-known DNS-tunnelling path. HoneyTrap closes it for the container by dropping *all* new container traffic, including UDP/53. The host's own DNS use is limited to resolving S3 and the package repo.
* **Flow logs.** All accepted and rejected traffic is written to `flowlogs/` in Parquet, giving a network-level record that the egress controls hold.

## Residual risks (accepted, documented)

* A Cowrie or Twisted **remote code execution vulnerability** would give an attacker code execution as uid 10001 inside the container. The container hardening and the egress controls above bound the impact: no credentials, no outbound connections, and a read-only filesystem. Mitigations: keep `cowrie` pinned and updated, run `pip-audit` in CI, and rebuild the image.
* **Kernel / container escape.** This is an unprivileged container with no capabilities, but it is not a VM. For stronger isolation, run the sensor under gVisor or Firecracker. That is listed as future work.
* **Public IPv4.** The sensor is fingerprintable as a honeypot by experienced actors. Its value lies in the volume of automated attacks, not in deceiving skilled operators.
* **The telemetry bucket holds attacker-supplied content**, including captured files and TTY logs. Treat `evidence/` as potentially malicious, and analyse samples only in a sandbox.

## Legal / ethical notes

* The sensor only *receives* connections. HoneyTrap never initiates traffic to attackers, and nothing "hacks back".
* Captured IPs and credentials are personal data in some jurisdictions. Retention is short by default (raw data for 14–30 days). Do not publish raw telemetry. The repository contains only synthetic data and our own simulation output.
* The simulation scripts refuse non-private targets unless they are explicitly authorised twice (CLI flag **and** environment variable). Use them only against infrastructure you own.
