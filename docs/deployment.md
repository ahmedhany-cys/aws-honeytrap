# Deployment

There are three ways to run HoneyTrap, from zero-risk to internet-exposed:

| Mode | What runs | Exposure | Cost |
|---|---|---|---|
| **Local (native)** | Cowrie in a venv on 127.0.0.1:2222/2223, simulations, dashboard | loopback only | none |
| **Local (Docker)** | Hardened Cowrie container + dashboard via `docker compose` | loopback only | none |
| **AWS** | Terraform stack (80 resources) with a public decoy | internet | see [cost-management.md](cost-management.md) |

## 1. Local, native (no Docker)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/pip install --no-deps -r requirements-cowrie.txt && .venv/bin/pip install -e .
scripts/honeypot_local.sh start                       # Cowrie on 127.0.0.1:2222 (ssh) / 2223 (telnet)
.venv/bin/python -m tests.simulations.runner          # 8 controlled attack scenarios -> data/simulation
.venv/bin/honeytrap synth --store data/demo           # labelled SYNTHETIC demo data (optional)
.venv/bin/streamlit run dashboard/app.py              # http://127.0.0.1:8501
scripts/honeypot_local.sh stop
```

## 2. Local, Docker

```bash
mkdir -p honeypot/runtime/docker-var && chmod 0777 honeypot/runtime/docker-var
docker compose up -d --build cowrie
python -m tests.simulations.runner --log honeypot/runtime/docker-var/log/cowrie/cowrie.json
docker compose --profile dashboard up -d dashboard   # optional
docker compose down
```

## 3. AWS

> ⚠️ Creates a **publicly reachable** EC2 instance and resources that consume credits or cost money. Read [security.md](security.md) and [cost-management.md](cost-management.md) first.

### Prerequisites

* Terraform ≥ 1.9, AWS CLI v2, credentials for the target account (an SSO profile is recommended). Nothing is hard-coded.
* A container image of the sensor, built for the instance architecture:
  * with Docker: `scripts/package_honeypot.sh` → `build/cowrie-image.tar.gz`
  * without Docker: download the `cowrie-image-linux-amd64` artifact from the latest successful CI run on `main` into `build/`.
* Edit `terraform/environments/dev.tfvars`. Set **`budget_email`** at least; `alert_email` is optional.

### Deploy

```bash
scripts/deploy.sh dev
```

The script:

1. shows the caller identity and the Free plan state;
2. builds `build/lambda.zip` reproducibly;
3. runs `terraform fmt`, `validate`, `tflint` and `checkov`;
4. plans, then lists the resources with usage-based cost;
5. applies **only after you type the environment name**.

After apply:

```bash
# Optional threat intel (free keys):
aws ssm put-parameter --overwrite --type SecureString --name /honeytrap-dev/abuseipdb-api-key --value <key>
aws ssm put-parameter --overwrite --type SecureString --name /honeytrap-dev/virustotal-api-key --value <key>
# Confirm the SNS email subscription(s) AWS sends you.
# Dashboard over the deployed bucket (read access via your own credentials):
HONEYTRAP_DATA=s3://$(terraform -chdir=terraform output -raw telemetry_bucket) streamlit run dashboard/app.py
```

### Verify the sensor without attacking anything

* `aws s3 ls s3://<telemetry>/raw/origin=live/` shows objects within ~10 minutes. Internet scanners find port 22 quickly.
* CloudWatch → `HoneyTrap` namespace → `EventsProcessed` increases.
* The `honeytrap-dev-no-telemetry` alarm stays OK.
* **Do not run the simulation scripts against the deployed sensor.** Its shipper labels everything it ships as `live`, which would mix your own test traffic into real telemetry. Validate detections with the local modes; CI does this on every push. The simulation runner also refuses non-private targets unless they are authorised twice.

### Teardown

```bash
scripts/teardown.sh dev     # type 'destroy'; verifies nothing tagged remains
```

Buckets are created with `force_destroy = true`, so the captured data is deleted with the stack. Copy anything you want to keep first.

## Remote state (optional)

`terraform/backend.tf.example` shows an S3 backend with native lock files (`use_lockfile`). State contains the generated HMAC key (as an SSM parameter value), so keep the state bucket private, encrypted and versioned.

## CI/CD

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
|---|---|
| python | ruff, unit + integration (moto) + security tests, coverage |
| terraform | fmt, validate, tflint (AWS ruleset), Checkov |
| secrets | gitleaks over full history |
| dependencies | pip-audit (strict) |
| honeypot | builds the hardened image, runs all 8 attack simulations against it, uploads results and (on `main`) the deployable image |

There is deliberately **no automatic deploy job**. Deployment creates internet-exposed resources and stays a manual, confirmed step. To automate it later, use GitHub OIDC (`aws-actions/configure-aws-credentials` with a role), not stored keys.
