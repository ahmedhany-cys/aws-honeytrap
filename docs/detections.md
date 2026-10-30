# Detection engineering

The engine (`backend/honeytrap/detection/`) evaluates normalised Cowrie events with 18 rules. Thresholds live in [`thresholds.toml`](../backend/honeytrap/detection/thresholds.toml) and can be overridden per environment with `HONEYTRAP_DETECTION_CONFIG=<file.toml>` (only the keys you change).

## How evaluation works

* **Origin isolation.** Events are partitioned by `data_origin` (`live`, `simulation`, `synthetic`) before any rule runs. A simulated login can never push a live IP over a threshold, and the reverse is also true (`test_origins_are_never_correlated`).
* **Two passes.**
  * The *processor* Lambda runs every rule on each raw batch the shipper uploads (every 5 minutes).
  * The *correlator* Lambda re-runs them hourly over the last 24 h, so activity split across batches is still counted.
* **Deterministic alert IDs.** Each ID is `sha256(rule | entity | window start)`, using tumbling windows aligned to the epoch. Re-evaluating the same evidence updates the existing alert instead of creating a duplicate. A notification is sent only when an alert is new or its severity rises (`test_reprocessing_is_idempotent`).
* **Evidence-based ATT&CK mapping.** `map_technique()` refuses to map without at least one evidence string, and every mapping carries a `confidence` (high / medium / low). Command rules attach the exact command line as evidence.
* **Known limitation of tumbling windows.** A burst that straddles a window boundary is counted in two windows. The correlator's wider window catches most of these cases. A sliding window would need per-IP state (DynamoDB), which was deliberately left out to keep the design stateless and free.

## Severity model

| Level | Meaning | Examples |
|---|---|---|
| Informational | Campaign intelligence, no action | Credential pair seen from ≥ 5 IPs |
| Low | Expected internet noise | Repeated pair, repeat visits, connection floods, light discovery |
| Medium | Targeted activity, or the attacker got into the emulated shell | Brute force ≥ 10/10 min, password spraying, successful decoy login, suspicious execution |
| High | Hands-on-keyboard intent | Brute force ≥ 50/10 min, persistence, download attempts, scanning *from* the decoy, miners, firewall tampering |
| Critical | Download **and** execute chain in one session | `wget … ; chmod +x … ; ./…`, `curl … \| sh` |

**Escalation.** A severity is raised by one level when there is a real reputation signal: AbuseIPDB confidence ≥ 75, or ≥ 5 VirusTotal engines flagging the IP. Synthetic enrichment never escalates. Alerts at **High or above** are published to SNS (`severity.notify_min_severity`).

**Risk score per attacker (0–100).** The score adds up alert weights (Info 1, Low 5, Medium 12, High 25, Critical 40), plus 20 % of a real AbuseIPDB score. Bands: ≥ 80 Critical, ≥ 55 High, ≥ 30 Medium, ≥ 10 Low.

## Rule reference

| ID | Rule | Logic (default thresholds) | Severity | ATT&CK (confidence) |
|---|---|---|---|---|
| HT-AUTH-001 | SSH/Telnet brute force | ≥ 10 failed logins from one IP in a 10-min window | Medium; High at ≥ 50 | T1110 (high); T1110.001 (medium) only if ≥ 80 % of attempts hit ≤ 3 accounts |
| HT-AUTH-002 | Password spraying | One password (by HMAC fingerprint) against ≥ 5 usernames from one IP in 60 min | Medium | T1110.003 (high) |
| HT-AUTH-003 | Repeated credential combination | Same username:password pair ≥ 3 times from one IP in 60 min | Low | T1110 (medium) |
| HT-AUTH-004 | Credential stuffing pattern | ≥ 20 distinct pairs over ≥ 5 usernames, repeat ratio ≤ 0.2, in 60 min | Medium | T1110.004 (**low**: a honeypot cannot prove the pairs came from a breach) |
| HT-AUTH-005 | Credential pair shared across IPs | Same pair from ≥ 5 IPs in 24 h | Informational | T1110 (medium) |
| HT-AUTH-006 | Successful honeypot login | `cowrie.login.success` in a session | Medium | T1078 (medium); T1078.001 if the account name is a well-known default |
| HT-NET-001 | High-frequency connections | ≥ 20 TCP sessions from one IP in 1 min | Low | T1595 Active Scanning (medium) |
| HT-NET-002 | Multiple sessions from same IP | ≥ 5 sessions in 24 h | Low; Medium if any session logged in | none (behavioural) |
| HT-NET-003 | SSH tunnelling attempt | `cowrie.direct-tcpip.request` (Cowrie logs it and never forwards) | Medium | T1090 (high), T1572 (medium) |
| HT-CMD-001 | Reconnaissance / discovery | Discovery commands in a session | Low; Medium at ≥ 3 distinct techniques | T1082, T1033, T1087.001, T1016, T1049, T1057, T1083, T1518.001 |
| HT-CMD-002 | Suspicious shell execution | base64/xxd decoding, piping into `sh`, executing from `/tmp`, `/dev/shm`, `./x`, `chmod +x` | Medium | T1140, T1059.004, T1222.002 |
| HT-CMD-003 | Persistence attempt | `authorized_keys`, crontab install, `useradd`, `systemctl enable`, rc scripts, `passwd`/`chpasswd` | High | T1098.004, T1053.003, T1136.001, T1543.002, T1037.004, T1098 |
| HT-CMD-004 | Defense evasion / impairment | History clearing / disabling, trace deletion; firewall or security-tool tampering | Medium; High for firewall or tool tampering | T1070.003, T1690, T1070.004, T1686, T1685 |
| HT-CMD-005 | Credential access | Reading `/etc/shadow`, grepping files for secrets | Medium | T1003.008, T1552.001 |
| HT-CMD-006 | Network scanning from the honeypot | `nmap`/`masscan`/`zmap`/`nc -z`, ping sweeps, `known_hosts` reads | High | T1046, T1018 |
| HT-CMD-007 | Cryptominer / resource hijacking | `xmrig`, `stratum+tcp://`, `--donate-level`, known pools | High | T1496.001 |
| HT-DL-001 | Download / ingress tool transfer | `wget`/`curl`/`tftp`/`ftpget`/`scp`, or a Cowrie download/upload event | High | T1105 (high) |
| HT-DL-002 | Malware retrieval **and** execution | A download, then execution of the downloaded name (or `curl … \| sh`) later in the same session | **Critical** | T1105 + T1059.004 |

### Mapping decisions worth explaining in review

* **T1046 vs T1595.** Internet scanning *against* the sensor is pre-compromise **Reconnaissance** (T1595 Active Scanning). T1046 Network Service Discovery is a post-compromise technique, so it is mapped only when the attacker runs a scanner *inside* the emulated shell (HT-CMD-006).
* **ATT&CK v20 changes.** The catalogue is generated from MITRE's STIX bundle (`scripts/update_mitre_catalog.py`), not typed by hand. That showed:
  * T1562.004 (*Disable or Modify System Firewall*) was revoked in v20 and replaced by **T1686**;
  * T1562.003 was replaced by **T1690** *Prevent Command History Logging*;
  * *Defense Evasion* was split into **Stealth** and **Defense Impairment**.

  `test_revoked_techniques_are_not_used` prevents a regression to the old IDs.
* **Redirection writes are not downloads.** Cowrie logs `echo … > file` as `cowrie.session.file_download` with a `destfile` and no URL. The parser re-labels these as `cowrie.session.file_write`, so they do not inflate T1105.
* **Blocked downloads.** Cowrie refuses to fetch non-global addresses and does not emit a `file_download.failed` event for them. HT-DL-001 therefore keys on the command line as well as on download events.

## Verification

Every rule has a unit test that checks it fires at its threshold, stays quiet below it, and maps only the techniques it should (`tests/unit/test_rules.py`). The eight simulation scenarios then show that the rules fire on **real Cowrie output** (`tests/simulations/`):

| Scenario | Expected rules | Result (local run, 2026-10-30) |
|---|---|---|
| SSH brute force (30 failed logins) | HT-AUTH-001, HT-AUTH-003, HT-NET-002 | PASS |
| Password spray (8 users, 6 sessions) | HT-AUTH-002, HT-NET-002 | PASS |
| Post-login reconnaissance | HT-AUTH-006, HT-CMD-001, HT-CMD-005 | PASS |
| Suspicious commands (decode, persistence, evasion) | HT-AUTH-006, HT-CMD-002, HT-CMD-003, HT-CMD-004 | PASS |
| Download + execute | HT-AUTH-006, HT-DL-001, HT-DL-002 | PASS |
| Telnet default-credential brute force | HT-AUTH-001 | PASS |
| SSH tunnelling attempt | HT-NET-003 | PASS |
| Connection flood | HT-NET-001 | PASS |

The machine-readable results are in [`docs/evidence/simulation-results.json`](evidence/simulation-results.json). CI repeats the same run against the hardened Docker image on every push.
