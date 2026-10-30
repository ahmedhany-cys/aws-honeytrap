# Incident response playbook

HoneyTrap alerts describe activity against a **decoy**: no real asset is at risk from the activity itself. The response therefore focuses on two things:

1. making sure the **containment** held;
2. turning the observations into **intelligence** for real environments.

## Triage (every High / Critical SNS alert)

1. **Check the origin label.** The subject line reads `[HoneyTrap][LIVE|SIMULATION|SYNTHETIC][Severity]`. Only `LIVE` represents real external activity.
2. **Open the attacker in the dashboard:** Attacker Investigation → select the IP, or use `?ip=<ip>`. Review:
   * the sessions;
   * the masked credentials;
   * the command sequence;
   * the mapped ATT&CK techniques and the evidence behind each one.
3. **Export the incident report** (Markdown/JSON) from the Report tab, or run `honeytrap report --store s3://<bucket> --ip <ip> --out report.md`.
4. **Pull the session recording if needed.** It is at `evidence/tty/<sensor>/<file>`. Replay it with `playlog` (from Cowrie) on an analysis machine.

## Containment verification (Critical alerts, especially HT-DL-002 / HT-CMD-006)

The design says the attacker cannot leave the emulator or reach the network. Verify that it held:

* **VPC flow logs (Athena):** look for no `ACCEPT` records with `srcaddr` = the sensor's private IP and a public `dstaddr`, other than S3 on port 443.
* **Host egress drops:** `journalctl -k | grep HONEYTRAP-EGRESS-BLOCK` (needs admin access) shows the container egress attempts that iptables dropped.
* **Credentials not misused:** CloudTrail for the sensor role should show only `PutObject` and `GetObject` calls.

If any check fails, treat it as a **real incident**:

1. Isolate the instance: swap its security group for one with no rules.
2. Snapshot the EBS volume for forensics.
3. Revoke the role sessions: attach the `AWSDenyAll` inline policy to the sensor role.
4. Run `scripts/teardown.sh`.

## Intelligence actions

| Alert class | Action for production estates |
|---|---|
| Brute force / spraying / stuffing | Confirm production SSH disallows passwords (`PasswordAuthentication no`). Feed high-volume IPs into edge deny lists, with an expiry. |
| Shared credential pairs | Check the masked pairs against your own accounts' password policies. Enforce MFA or key-only access. |
| Download / malware retrieval | Add the URLs and SHA-256 hashes (Athena query `03_download_urls_and_hashes`) to the proxy/DNS blocklist and EDR IOC lists. Detonate samples only in a sandbox. |
| Persistence (authorized_keys, cron, useradd) | Hunt for the same SSH key fingerprints and cron lines across production. |
| Cryptominer | Block the pool domains at egress. Alert on `stratum+tcp` in proxy logs. |
| Tunnelling attempts | Ensure `AllowTcpForwarding no` on bastions and servers that don't need it. |

## Reporting

* Share only **masked** credentials and aggregated statistics outside the security team.
* Before submitting IPs to AbuseIPDB, follow its reporting guidelines. HoneyTrap does **not** auto-report.
* Keep the investigation report with the alert ID. Alert IDs are deterministic, so re-processing never creates conflicting duplicates.
