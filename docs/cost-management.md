# Cost management

**Policy: Free-Tier-first, no intentional spend.** Nothing in this repository has been applied to AWS. `scripts/deploy.sh` makes you type the environment name before `terraform apply`.

## What was checked (2026-10-30)

| Check | Result |
|---|---|
| `aws freetier get-account-plan-state` | Account is on the post-July-2025 **Free plan**, `ACTIVE`. **$120.78 credits** remain, and the plan **expires 2026-11-30**. |
| `aws freetier get-free-tier-usage` | Lambda, EventBridge, Glue and CloudWatch usage are negligible against their always-free limits. |
| AWS Price List API (us-west-1) | t3.micro **$0.0124/h**. Public IPv4 **$0.005/h** (in use or idle). gp3 **$0.096/GB-month**. |

**What the Free plan means here.** Usage above the always-free allowances is deducted from credits, not charged to a card. When the credits run out or the plan expires, AWS closes the account unless you upgrade to a paid plan. A sensor deployed today can therefore run **at most until 2026-11-30** on this account. Tear it down before then, or upgrade knowingly.

## Monthly estimate (one sensor, us-west-1, list prices, 730 h)

| Item | Basis | Est. USD / month | Free plan |
|---|---|---|---|
| EC2 t3.micro | 730 h × $0.0124 | 9.05 | from credits |
| Public IPv4 address | 730 h × $0.005 | 3.65 | from credits |
| EBS gp3 8 GB | 8 × $0.096 | 0.77 | from credits |
| S3 storage + requests | < 1 GB, ~9k PUT/day (shipper + Lambda writes) | ~0.10–0.50 | from credits |
| VPC flow logs → S3 | vended log delivery, < 1 GB | < 0.25 | from credits |
| Lambda | ~9k invocations/day, 256 MB | 0.00 | always free (1M req, 400k GB-s) |
| EventBridge | S3 events + hourly schedule | 0.00 | AWS service events are free |
| SNS | High/Critical alerts only | 0.00 | 1k emails free |
| SQS DLQ | idle | 0.00 | 1M requests free |
| CloudWatch | 5 alarms, 3 EMF metrics, 14-day logs | 0.00 | 10 alarms / 10 metrics / 5 GB logs free |
| Athena | 10 MB minimum billed per query, capped at 100 MB | ~0.00 | no free tier ($5/TB) |
| Glue Data Catalog | 3 objects | 0.00 | 1M objects free |
| SSM Parameter Store | 3 standard SecureStrings | 0.00 | standard tier free |
| AWS Budgets | 2 budgets | 0.00 | budgets themselves are free |
| **Total** | | **≈ $13.6–14.5** | **≈ 9 months of credits, but the plan ends 2026-11-30** |

On a legacy (pre-July-2025) 12-month Free Tier account, 750 h of t3.micro and 750 h of public IPv4 are free, which brings the estimate close to $1/month.

## Cost risks and how they are contained

| Risk | Control |
|---|---|
| Forgetting to tear down | `scripts/teardown.sh <env>` destroys the stack and then verifies no tagged resources or instances remain. Budgets email at 25 %, 80 % and 100 % (forecast). |
| Budgets do **not** stop spend | Documented everywhere a budget is mentioned. Teardown is the only control that stops cost. |
| T3 unlimited CPU credits | `credit_specification { cpu_credits = "standard" }`, so CPU can't burst into surplus billing. |
| Instance type drift | Terraform precondition allows only t3/t4g micro/small (and t2.micro). |
| NAT gateway (~$32/month + data) | Not used. The S3 **gateway** endpoint is free, and a security test fails if a NAT, ALB, EIP or interface endpoint appears. |
| KMS CMKs ($1/key/month + requests) | SSE-S3 and AWS-managed keys instead (Checkov skips are justified in code). |
| Log growth | CloudWatch retention 14 days. S3 lifecycle expiry: raw/evidence 14–30 days, processed 90, Athena results 7, flow logs 14. Noncurrent versions are kept 7 days. |
| Athena runaway queries | The workgroup enforces a 100 MB scan cutoff per query, and partition projection avoids crawlers. |
| Telnet volume | Telnet is off by default. Enabling it multiplies events (Mirai-family scanners) and therefore S3 PUTs and Lambda invocations. |
| Paid threat-intel | None. AbuseIPDB and VirusTotal use free keys, per-run lookup caps (25) and a 24 h cache, and are optional. |
| Data transfer out | Replies to attackers are small. AWS includes 100 GB/month of free internet egress per account. |

## Activating the project budget filter

The project budget filters on the `Project` tag. Cost allocation tags must be **activated once** under Billing → Cost allocation tags (`Project`) before they filter. The account-wide guardrail budget works without activation.
