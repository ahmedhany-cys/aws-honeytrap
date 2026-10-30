#!/usr/bin/env bash
# Run every check and save the raw results to docs/evidence/ so the dashboard's
# "Architecture & Validation" page and the README show real, reproducible output.
#
#   scripts/collect_evidence.sh            # tests, terraform, tflint, checkov, gitleaks
#   PLAN=1 scripts/collect_evidence.sh     # also a read-only `terraform plan` (needs AWS credentials; creates nothing)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/evidence"
PY="${PY:-$ROOT/.venv/bin/python}"
TFLINT="${TFLINT:-tflint}"
CHECKOV="${CHECKOV:-checkov}"
mkdir -p "$OUT"
cd "$ROOT"

echo "== pytest"
"$PY" -m pytest tests/unit tests/integration tests/security -q -p no:cacheprovider \
  --junitxml="$OUT/pytest-junit.xml" --cov --cov-report=json:"$OUT/coverage.json" --cov-report=term | tail -n 25 \
  | tee "$OUT/pytest-summary.txt"

echo "== terraform"
{
  echo "$ terraform version"; terraform version | head -1
  echo "$ terraform fmt -check -recursive"; terraform -chdir=terraform fmt -check -recursive && echo "(no formatting changes needed)"
} > "$OUT/terraform-fmt.txt" 2>&1
terraform -chdir=terraform init -backend=false -input=false >/dev/null
{ echo "$ terraform validate"; terraform -chdir=terraform validate -no-color; } > "$OUT/terraform-validate.txt" 2>&1
cat "$OUT/terraform-validate.txt"

echo "== tflint"
(cd terraform && "$TFLINT" --init >/dev/null 2>&1; { echo "$ tflint --recursive"; "$TFLINT" --version | head -1; "$TFLINT" --recursive --format compact && echo "0 issues"; }) \
  > "$OUT/tflint.txt" 2>&1
cat "$OUT/tflint.txt"

echo "== checkov"
"$CHECKOV" -d terraform --framework terraform --compact --download-external-modules false -o json \
  > "$OUT/.checkov-raw.json" 2>/dev/null
"$PY" - "$OUT/.checkov-raw.json" "$OUT/checkov-summary.json" <<'PY'
import json, sys
raw = json.load(open(sys.argv[1])); raw = raw[0] if isinstance(raw, list) else raw
res, summ = raw["results"], raw["summary"]
out = {"checkov_version": summ["checkov_version"], "resources": summ["resource_count"],
       "passed": summ["passed"], "failed": summ["failed"], "skipped": summ["skipped"],
       "failed_checks": [{"check": c["check_id"], "resource": c["resource"], "file": c["file_path"],
                          "name": c["check_name"]} for c in res["failed_checks"]],
       "skipped_checks": [{"check": c["check_id"], "resource": c["resource"],
                           "justification": c.get("check_result", {}).get("suppress_comment", "")}
                          for c in res["skipped_checks"]]}
json.dump(out, open(sys.argv[2], "w"), indent=2)
print(f"checkov {out['checkov_version']}: passed={out['passed']} failed={out['failed']} skipped={out['skipped']}")
PY
rm -f "$OUT/.checkov-raw.json"

echo "== gitleaks"
if command -v gitleaks >/dev/null; then
  if git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then mode=(git); scope="git history"; else mode=(dir); scope="working tree"; fi
  gitleaks "${mode[@]}" "$ROOT" --config "$ROOT/.gitleaks.toml" --no-banner --redact -f json -r "$OUT/.gitleaks.json" >/dev/null 2>&1
  "$PY" - "$OUT/.gitleaks.json" "$OUT/gitleaks-summary.json" "$(gitleaks version)" "$scope" <<'PY'
import json, sys
findings = json.load(open(sys.argv[1])) if open(sys.argv[1]).read().strip() else []
json.dump({"findings": len(findings), "version": sys.argv[3], "scope": sys.argv[4],
           "rules": sorted({f["RuleID"] for f in findings})}, open(sys.argv[2], "w"), indent=2)
print(f"gitleaks: {len(findings)} findings")
PY
  rm -f "$OUT/.gitleaks.json"
fi

if [ "${PLAN:-0}" = "1" ]; then
  echo "== terraform plan (read-only)"
  "$ROOT/scripts/build_lambda.sh"
  img="$ROOT/build/cowrie-image.tar.gz"
  [ -f "$img" ] || { echo "(no image built - using an empty placeholder for plan only)"; : > "$img"; }
  terraform -chdir=terraform plan -input=false -no-color -var-file=environments/dev.tfvars -out=tfplan > "$ROOT/build/plan.txt" 2>&1
  status=$?
  if [ $status -ne 0 ]; then echo "terraform plan FAILED:"; grep -A8 "^Error" "$ROOT/build/plan.txt"; exit $status; fi
  terraform -chdir=terraform show -json tfplan > "$ROOT/build/tfplan.json" 2>/dev/null
  "$PY" - "$ROOT/build/tfplan.json" "$OUT/terraform-plan-summary.json" "$ROOT/build/plan.txt" <<'PY'
import collections, json, re, sys
plan = json.load(open(sys.argv[1]))
creates = [r for r in plan["resource_changes"] if r["change"]["actions"] == ["create"]]
by_type = collections.Counter(r["type"] for r in creates)
summary_line = next((l for l in open(sys.argv[3]) if l.startswith("Plan:")), "").strip()
json.dump({"plan": summary_line, "terraform_version": plan["terraform_version"],
           "resources_to_create": len(creates), "by_type": dict(sorted(by_type.items())),
           "applied": False}, open(sys.argv[2], "w"), indent=2)
print(summary_line)
PY
  rm -f terraform/tfplan
  exit $status
fi
echo "evidence written to docs/evidence/"
