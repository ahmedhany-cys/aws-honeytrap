#!/usr/bin/env bash
# Destroy everything HoneyTrap created and verify nothing billable is left.
#
#   scripts/teardown.sh dev
set -euo pipefail
ENV="${1:?usage: scripts/teardown.sh <environment>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF="$ROOT/terraform"
REGION="$(awk -F'"' '/^region/ {print $2}' "$TF/environments/$ENV.tfvars")"

read -r -p "Destroy ALL HoneyTrap resources for '$ENV' in $REGION, including captured data? Type 'destroy': " answer
[ "$answer" = "destroy" ] || { echo "aborted"; exit 1; }

# Lambda zip and image paths must exist for the plan to evaluate; placeholders are fine for destroy.
mkdir -p "$ROOT/build"
[ -f "$ROOT/build/lambda.zip" ] || "$ROOT/scripts/build_lambda.sh"
[ -f "$ROOT/build/cowrie-image.tar.gz" ] || : > "$ROOT/build/cowrie-image.tar.gz"

terraform -chdir="$TF" destroy -input=false -auto-approve -var-file="environments/$ENV.tfvars"

echo "== Verifying nothing billable remains (tag Project=honeytrap, Environment=$ENV)"
left=$(aws resourcegroupstaggingapi get-resources --region "$REGION" \
  --tag-filters Key=Project,Values=honeytrap Key=Environment,Values="$ENV" \
  --query 'ResourceTagMappingList[].ResourceARN' --output text)
if [ -n "$left" ]; then
  echo "WARNING: tagged resources still present (may be eventual consistency, re-run in a minute):"
  echo "$left" | tr '\t' '\n'
  exit 2
fi
running=$(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values=honeytrap Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
[ -z "$running" ] || { echo "WARNING: instances still present: $running"; exit 2; }
addresses=$(aws ec2 describe-addresses --region "$REGION" --query 'Addresses[].PublicIp' --output text)
[ -z "$addresses" ] || echo "NOTE: Elastic IPs exist in $REGION (not created by HoneyTrap): $addresses"
echo "Teardown complete. CloudWatch log groups are deleted by Terraform; budgets are removed too."
