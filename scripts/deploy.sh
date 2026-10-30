#!/usr/bin/env bash
# Safe deployment workflow. Nothing is applied without an explicit typed confirmation.
#
#   scripts/deploy.sh dev            # build, validate, scan, plan, then ask before apply
#
# Steps: preflight (identity, region, Free plan status) -> build artifacts ->
# fmt/validate/tflint/checkov -> terraform plan -> show billable resources -> confirm -> apply.
set -euo pipefail
ENV="${1:?usage: scripts/deploy.sh <environment>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF="$ROOT/terraform"
VARS="$TF/environments/$ENV.tfvars"
[ -f "$VARS" ] || { echo "no such environment file: $VARS"; exit 1; }

echo "== Preflight"
aws sts get-caller-identity --query '{Account:Account,Arn:Arn}' --output table
aws freetier get-account-plan-state --output table 2>/dev/null || echo "(free tier plan API unavailable for this account)"

echo "== Build artifacts"
"$ROOT/scripts/build_lambda.sh"
[ -f "$ROOT/build/cowrie-image.tar.gz" ] || { echo "missing build/cowrie-image.tar.gz - run scripts/package_honeypot.sh or download the CI artifact"; exit 1; }

echo "== Static checks"
terraform -chdir="$TF" fmt -check -recursive
terraform -chdir="$TF" init -input=false >/dev/null
terraform -chdir="$TF" validate
command -v tflint >/dev/null && (cd "$TF" && tflint --init >/dev/null && tflint --recursive) || echo "(tflint not installed - skipped)"
command -v checkov >/dev/null && checkov -d "$TF" --quiet --compact || echo "(checkov not installed - skipped)"

echo "== Plan"
terraform -chdir="$TF" plan -input=false -var-file="environments/$ENV.tfvars" -out=tfplan
terraform -chdir="$TF" show -json tfplan > "$ROOT/build/tfplan.json"
python3 - "$ROOT/build/tfplan.json" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
billable = {"aws_instance": "EC2 t3/t4g micro (Free Tier hours; public IPv4 is billed)",
            "aws_flow_log": "VPC flow logs (vended log delivery per GB)",
            "aws_athena_workgroup": "Athena (per TB scanned, no free tier; capped per query)",
            "aws_lambda_function": "Lambda (always-free 1M requests / 400k GB-s)",
            "aws_s3_bucket": "S3 storage and requests"}
changes = [r for r in plan.get("resource_changes", []) if "create" in r["change"]["actions"]]
print(f"\n{len(changes)} resources to create. Resources with usage-based cost:")
for r in changes:
    if r["type"] in billable:
        print(f"  - {r['address']}: {billable[r['type']]}")
PY

echo
echo "This creates PUBLICLY EXPOSED, potentially billable resources in your AWS account."
read -r -p "Type the environment name ('$ENV') to apply: " answer
[ "$answer" = "$ENV" ] || { echo "aborted"; exit 1; }
terraform -chdir="$TF" apply -input=false tfplan
terraform -chdir="$TF" output
