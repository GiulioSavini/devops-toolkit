#!/usr/bin/env bash
# Validates everything under baselines/iam/. Run from the repository root.
# Host requirements: docker, bash, curl.
set -euo pipefail

ROOT="$(pwd)"
BASE="baselines/iam"
[[ -d "$BASE" ]] || { echo "run from the repository root" >&2; exit 2; }

PYTHON_IMAGE="python:3.13.15-slim-trixie"
TERRAFORM_IMAGE="hashicorp/terraform:1.16.4"
SHELLCHECK_IMAGE="koalaman/shellcheck:v0.11.0"
PARLIAMENT_VERSION="1.6.4"
# parliament 1.6.4 imports pkg_resources, which setuptools removed in 81.
SETUPTOOLS_VERSION="75.8.0"
CHECK_JSONSCHEMA_VERSION="0.38.2"
PYYAML_VERSION="6.0.3"
AZURE_POLICY_SCHEMA="https://schema.management.azure.com/schemas/2020-10-01/policyDefinition.json"
GCP_CONSTRAINTS_DOC="https://docs.cloud.google.com/organization-policy/reference/org-policy-constraints"
SCP_MAX_CHARS=10240

step() { printf '\n==> %s\n' "$*"; }

# Every check below runs in a pinned container, so a missing or unreachable
# Docker daemon has to fail loudly here instead of surfacing as "invalid JSON"
# from a container that never started.
require_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker is required to run this suite" >&2; exit 2; }
  docker version >/dev/null 2>&1 || { echo "the docker daemon is not reachable (DOCKER_HOST=${DOCKER_HOST:-unset})" >&2; exit 2; }
}

pull_images() {
  local image
  for image in "$@"; do
    docker pull -q "$image" >/dev/null || { echo "cannot pull $image" >&2; exit 2; }
    echo "ok  $image"
  done
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

step "docker preflight: pinned images are pullable"
require_docker
pull_images "$PYTHON_IMAGE" "$TERRAFORM_IMAGE" "$SHELLCHECK_IMAGE"

step "JSON syntax (every .json under $BASE)"
while IFS= read -r -d '' f; do
  docker run --rm -i "$PYTHON_IMAGE" python -m json.tool >/dev/null <"$f" \
    || { echo "invalid JSON: $f" >&2; exit 1; }
  echo "ok  $f"
done < <(find "$BASE" -name '*.json' -print0 | sort -z)

step "SCP size (minified) <= $SCP_MAX_CHARS characters"
for f in "$BASE"/aws/scp/*.json; do
  size=$(docker run --rm -i "$PYTHON_IMAGE" python -c \
    'import json,sys; print(len(json.dumps(json.load(sys.stdin), separators=(",", ":"))))' <"$f")
  if (( size > SCP_MAX_CHARS )); then
    echo "FAIL $f is $size characters" >&2; exit 1
  fi
  echo "ok  $f ($size chars)"
done

step "AWS policy grammar and known actions (parliament $PARLIAMENT_VERSION)"
# A permissions boundary is a ceiling and legitimately uses Resource "*";
# mute only that finding, only for that file (parliament's ignore_locations
# is broken for plain strings in 1.6.4, so run it separately).
cat >"$work/boundary.yaml" <<'EOF'
RESOURCE_STAR:
  severity: MUTE
EOF
docker run --rm \
  -v "$ROOT/$BASE/aws:/policies:ro" -v "$work:/cfg:ro" \
  "$PYTHON_IMAGE" sh -euc "
    pip install -q --root-user-action=ignore --disable-pip-version-check \
      parliament==$PARLIAMENT_VERSION setuptools==$SETUPTOOLS_VERSION
    rc=0
    for f in /policies/scp/*.json /policies/iam/*.json; do
      case \"\$f\" in
        */workload-permissions-boundary.json) cfg='--config /cfg/boundary.yaml' ;;
        *) cfg='' ;;
      esac
      # parliament refuses --file when stdin is not a TTY; feed via stdin.
      if out=\$(parliament \$cfg <\"\$f\"); then
        echo \"ok  \$f\"
      else
        echo \"FAIL \$f\"; echo \"\$out\"; rc=1
      fi
    done
    exit \$rc
  "

step "EventBridge patterns: top-level keys are valid event fields"
for f in "$BASE"/aws/eventbridge/*.json; do
  docker run --rm -i "$PYTHON_IMAGE" python -c '
import json, sys
p = json.load(sys.stdin)
allowed = {"version","id","detail-type","source","account","time","region","resources","detail"}
bad = set(p) - allowed
assert not bad, f"unknown top-level keys: {bad}"
assert "detail" in p, "pattern must filter on detail"
' <"$f" || { echo "FAIL $f" >&2; exit 1; }
  echo "ok  $f"
done

step "Azure Policy rule against $AZURE_POLICY_SCHEMA"
for f in "$BASE"/azure/policy/*.json; do
  docker run --rm -i "$PYTHON_IMAGE" sh -euc "
    pip install -q --root-user-action=ignore --disable-pip-version-check check-jsonschema==$CHECK_JSONSCHEMA_VERSION
    python -c 'import json,sys; json.dump(json.load(sys.stdin)[\"properties\"][\"policyRule\"], open(\"/tmp/rule.json\",\"w\"))'
    check-jsonschema --schemafile $AZURE_POLICY_SCHEMA /tmp/rule.json
  " <"$f" || { echo "FAIL $f" >&2; exit 1; }
  echo "ok  $f"
done

step "GCP org policies: structure, and constraint exists in Google's reference"
curl -fsSL "$GCP_CONSTRAINTS_DOC" -o "$work/constraints.html"
for f in "$BASE"/gcp/org-policies/*.yaml; do
  constraint="$(basename "$f" .yaml)"
  grep -q "constraints/${constraint}\b" "$work/constraints.html" \
    || { echo "FAIL $f: constraints/$constraint not found in $GCP_CONSTRAINTS_DOC" >&2; exit 1; }
  docker run --rm -i -e CONSTRAINT="$constraint" "$PYTHON_IMAGE" sh -euc "
    pip install -q --root-user-action=ignore --disable-pip-version-check PyYAML==$PYYAML_VERSION
    python -c '
import os, re, sys, yaml
p = yaml.safe_load(sys.stdin)
c = os.environ[\"CONSTRAINT\"]
assert re.fullmatch(r\"organizations/[A-Z_0-9]+/policies/\" + re.escape(c), p[\"name\"]), \"name does not match file name: \" + p[\"name\"]
assert set(p) <= {\"name\", \"spec\", \"dryRunSpec\"}, \"unexpected top-level keys: \" + str(set(p))
for key in (\"spec\", \"dryRunSpec\"):
    if key not in p:
        continue
    rules = p[key][\"rules\"]
    assert isinstance(rules, list) and rules, key + \".rules must be a non-empty list\"
    for r in rules:
        kinds = {\"enforce\", \"values\", \"allowAll\", \"denyAll\"} & set(r)
        assert len(kinds) == 1, \"each rule needs exactly one of enforce/values/allowAll/denyAll: \" + str(r)
        assert set(r) <= {\"enforce\", \"values\", \"allowAll\", \"denyAll\", \"condition\", \"parameters\"}, \"unknown rule key: \" + str(r)
        if \"parameters\" in r:
            assert \".managed.\" in c, \"parameters are only valid on managed constraints\"
'
  " <"$f" || { echo "FAIL $f" >&2; exit 1; }
  echo "ok  $f"
done

step "region-allowlist SCP still exempts the global (us-east-1-only) services"
# A region-deny SCP that forgets one of these locks the account out of its own
# control plane: IAM and STS are global, CloudFront/Route 53/WAF/Shield/Support
# and everything billing-related only have endpoints in us-east-1.
docker run --rm -i "$PYTHON_IMAGE" python -c '
import json, sys
p = json.load(sys.stdin)
st = [s for s in p["Statement"] if "NotAction" in s]
assert len(st) == 1, "expected exactly one NotAction statement"
st = st[0]
assert st["Effect"] == "Deny", "a region allowlist is expressed as a Deny"
na = set(st["NotAction"])
required = {
    "iam:*", "sts:*", "organizations:*", "account:*", "support:*",
    "cloudfront:*", "route53:*", "route53domains:*", "waf:*", "wafv2:*",
    "shield:*", "globalaccelerator:*", "budgets:*", "ce:*", "cur:*",
    "billing:*", "tax:*", "artifact:*", "kms:*", "sso:*",
    "access-analyzer:*", "config:*", "health:*", "trustedadvisor:*",
}
missing = sorted(required - na)
assert not missing, "NotAction is missing global services: " + ", ".join(missing)
cond = st["Condition"]
assert "StringNotEquals" in cond and "aws:RequestedRegion" in cond["StringNotEquals"], \
    "the deny must be conditional on aws:RequestedRegion"
regions = cond["StringNotEquals"]["aws:RequestedRegion"]
assert isinstance(regions, list) and regions, "allowed regions must be a non-empty list"
assert all("*" not in r for r in regions), "region values must be exact"
' <"$BASE/aws/scp/region-allowlist.json" || { echo "FAIL $BASE/aws/scp/region-allowlist.json" >&2; exit 1; }
echo "ok  $BASE/aws/scp/region-allowlist.json"

step "GitHub OIDC sub claim templates use documented claim keys only"
for f in "$BASE"/github/oidc-sub-template-*.json; do
  docker run --rm -i "$PYTHON_IMAGE" python -c '
import json, sys
p = json.load(sys.stdin)
assert set(p) <= {"use_default", "include_claim_keys"}, "unknown keys: " + str(set(p))
# The claim keys GitHub documents for the customized sub claim.
allowed = {
    "actor", "actor_id", "base_ref", "environment", "event_name", "head_ref",
    "job_workflow_ref", "job_workflow_sha", "ref", "ref_type", "repo",
    "repository_id", "repository_owner", "repository_owner_id",
    "repository_visibility", "runner_environment", "workflow", "workflow_ref",
    "workflow_sha", "context",
}
keys = p.get("include_claim_keys", [])
assert keys, "include_claim_keys must be set; an empty template is the default sub"
bad = [k for k in keys if k not in allowed]
assert not bad, "claim keys GitHub does not expose in sub: " + str(bad)
assert "repo" in keys or "repository_id" in keys, \
    "without repo or repository_id the sub no longer identifies the repository"
assert len(keys) >= 2, "a single claim key is almost always too broad for a trust policy"
if "use_default" in p:
    assert p["use_default"] is False, "use_default must be false when overriding the template"
' <"$f" || { echo "FAIL $f" >&2; exit 1; }
  echo "ok  $f"
done

step "Terraform: fmt, init -backend=false, validate, test (mocked providers)"
for dir in "$BASE"/terraform/*/; do
  dir="${dir%/}"
  docker run --rm --entrypoint sh -v "$ROOT/$dir:/src:ro" "$TERRAFORM_IMAGE" -euc '
    cp -r /src /m && cd /m
    terraform fmt -check -recursive -diff
    terraform init -backend=false -input=false -no-color >/dev/null
    terraform validate -no-color
    terraform test -no-color
  ' || { echo "FAIL $dir" >&2; exit 1; }
  echo "ok  $dir"
done

step "shellcheck"
docker run --rm -v "$ROOT/$BASE/bin:/mnt:ro" "$SHELLCHECK_IMAGE" -x /mnt/aws-stale-credentials.sh
echo "ok  $BASE/bin/aws-stale-credentials.sh"

step "aws-stale-credentials.sh against a synthetic credential report"
now="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
old="2020-02-01T00:00:00+00:00"
created="2019-01-01T00:00:00+00:00"
header="user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
cat >"$work/report.csv" <<EOF
$header
<root_account>,arn:aws:iam::111122223333:root,$created,not_supported,$now,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
alice,arn:aws:iam::111122223333:user/alice,$created,true,$now,$created,N/A,true,true,$created,$now,eu-west-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
bob,arn:aws:iam::111122223333:user/bob,$created,true,$old,$created,N/A,false,true,$created,N/A,N/A,N/A,true,$now,N/A,N/A,N/A,false,N/A,false,N/A
carol,arn:aws:iam::111122223333:user/carol,$created,false,N/A,N/A,N/A,false,false,N/A,N/A,N/A,N/A,true,$created,$old,eu-west-1,ec2,false,N/A,false,N/A
EOF
cat >"$work/expected.tsv" <<EOF
bob	password	$old	not used since
bob	access_key_1	$created	never used
carol	access_key_2	$old	not used since
EOF
rc=0
bash "$BASE/bin/aws-stale-credentials.sh" -d 90 -f "$work/report.csv" >"$work/actual.tsv" || rc=$?
[[ $rc -eq 1 ]] || { echo "FAIL expected exit 1 (stale found), got $rc" >&2; exit 1; }
diff -u "$work/expected.tsv" "$work/actual.tsv"
{ echo "$header"; grep '^alice,' "$work/report.csv"; } >"$work/clean.csv"
bash "$BASE/bin/aws-stale-credentials.sh" -f "$work/clean.csv" >/dev/null \
  || { echo "FAIL clean report should exit 0" >&2; exit 1; }
cut -d, -f1-3 "$work/report.csv" >"$work/truncated.csv"
rc=0
bash "$BASE/bin/aws-stale-credentials.sh" -f "$work/truncated.csv" 2>/dev/null || rc=$?
[[ $rc -eq 2 ]] || { echo "FAIL truncated report should exit 2, got $rc" >&2; exit 1; }
echo "ok  stale detection, clean report, malformed report"

printf '\nAll IAM checks passed.\n'
