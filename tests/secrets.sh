#!/usr/bin/env bash
# Validates baselines/secrets/*. Run from the repository root:
#
#   bash tests/secrets.sh
#
# What is checked for real:
#   a) gitleaks + baselines/secrets/.gitleaks.toml finds the planted secret in
#      fixtures/dirty/ (rule "internal-service-token") and finds NOTHING in
#      fixtures/clean/ -- the pair that proves both the rule and the
#      allowlist entry work. A config that matches nothing anywhere would
#      pass the second half and this test would not catch it without the
#      first half, which is why dirty is scanned first.
#   b) a SOPS + age round trip, keys generated fresh inside this test:
#      encrypt a plaintext YAML, assert the VALUES are ciphertext while the
#      KEYS stay readable, decrypt and assert the plaintext comes back
#      byte-identical. A different age key must fail to decrypt.
#   c) every path_regex in baselines/secrets/.sops.yaml actually matches the
#      path it claims and gets the recipient(s)/encrypted_regex it claims:
#      one file per rule (ansible group_vars, kubernetes bootstrap secret,
#      and the catch-all) is created at the exact matching path and
#      encrypted for real, then the resulting recipient list and which keys
#      got encrypted are asserted from the SOPS metadata -- not silently
#      unencrypted, not matched by the wrong rule.
#   d) baselines/secrets/vault/policy-app-readonly.hcl is accepted by the
#      real `vault policy fmt` parser, which is proven to also reject a
#      syntax error and an invalid capability name. The policy is then
#      loaded into a real dev-mode Vault server and a token scoped to it can
#      read its own path but is DENIED (403) reading a sibling app's path --
#      the least-privilege claim, proven live, not asserted in a comment.
#      The same server also demonstrates the KV v2 path trap the policy's
#      own comments warn about: `vault kv get` (CLI, translates the path)
#      returns the secret; a raw `vault read` at the same CLI-shaped path
#      returns nothing, only the real `secret/data/...` path does.
#   e) both baselines/secrets/eso/*.yaml manifests validate against the real
#      External Secrets Operator CRD JSON schemas (kubeconform -strict).
#      An unknown field under spec.data[] and a missing required field
#      (provider.vault.server) are each rejected. The schemas are vendored
#      under baselines/secrets/eso/schemas/ (fetched once from
#      https://github.com/datreeio/CRDs-catalog) so this check needs no
#      network at test time, unlike a `-schema-location` pointed at a live
#      URL would.
#
# What this does NOT do:
#   - It does not validate baselines/secrets/vault/k8s-auth-role.sh against a
#     real Kubernetes API. `vault write auth/kubernetes/config` and
#     `auth/kubernetes/role/...` accept any string for kubernetes_host /
#     kubernetes_ca_cert without checking reachability, so a container-only
#     run would prove nothing beyond "the CLI parsed its flags" -- worse
#     than not testing it, because a green check would look like a
#     guarantee it is not. See guides/secrets-management.md.
#   - It does not exercise PGP, AWS KMS, GCP KMS or Azure Key Vault as SOPS
#     key backends -- only age, which is what .sops.yaml actually uses.
#   - It does not run `vault kv put`/`get` through the Kubernetes-auth login
#     path end to end; that needs a real Kubernetes API server issuing
#     ServiceAccount tokens, which a container alone does not have.
#
# Host requirements: docker and bash. Every tool runs in a container pinned
# by digest. alpine's `age`/`sops` apk packages are additionally pinned to an
# exact version string below: age and sops have no combined official image,
# and Alpine's package index is not immutable the way an image digest is, so
# the version pin is what keeps this reproducible rather than the base image
# alone.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$ROOT_DIR/baselines/secrets"
[[ -d "$SECRETS_DIR" ]] || { echo "run from the repository root" >&2; exit 2; }

# Image digests were current on 2026-09-29 (`docker pull <tag>` then
# `docker image inspect --format '{{index .RepoDigests 0}}' <tag>`).
GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"          # v8.30.1
ALPINE_IMAGE="alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"                         # 3.22
VAULT_IMAGE="hashicorp/vault@sha256:750bb37c1638fa194ab37053a81618c61bb0491ddec6fccac87c07a8e6cd8166"                 # 1.18 (server v1.18.5)
KUBECONFORM_IMAGE="ghcr.io/yannh/kubeconform@sha256:6b90a5f23d846140ce0194fe050b1995e546eba938f3a6bf10c039dd5e24588f"  # v0.8.0-alpine

# Exact apk package versions pinned at authoring time (`apk add --no-cache
# age sops` on the digest above resolved to these). Pinning the version
# string makes `apk add` fail loudly if Alpine's v3.22 repo ever stops
# serving this exact build, instead of silently installing something newer.
AGE_SOPS_PIN="age=1.2.1-r10 sops=3.9.4-r11"

WORK="$(mktemp -d)"
VAULT_CID=""

cleanup() {
  [[ -n "$VAULT_CID" ]] && docker rm -f "$VAULT_CID" >/dev/null 2>&1
  # The alpine and vault containers write root-owned files into the bind
  # mount; fix ownership before rm so cleanup cannot mask the script's real
  # exit status.
  docker run --rm -v "$WORK:/w" "$ALPINE_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker is required"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

step "docker preflight: pinned images are pullable"
for image in "$GITLEAKS_IMAGE" "$ALPINE_IMAGE" "$VAULT_IMAGE" "$KUBECONFORM_IMAGE"; do
  docker pull -q "$image" >/dev/null || fail "cannot pull $image"
done

# ---------------------------------------------------------------------------
# a) gitleaks: the planted-secret / clean-fixture pair
# ---------------------------------------------------------------------------
step "a) gitleaks: fixtures/dirty must be caught, fixtures/clean must not"
mkdir -p "$WORK/gitleaks"

set +e
docker run --rm -v "$SECRETS_DIR:/repo:ro" -v "$WORK/gitleaks:/out" "$GITLEAKS_IMAGE" \
  dir /repo/fixtures/dirty -c /repo/.gitleaks.toml --no-banner --no-color \
  --report-format json --report-path /out/dirty.json >"$WORK/gitleaks/dirty.log" 2>&1
DIRTY_RC=$?
set -e
# gitleaks exits 1 when it finds leaks -- 0 here would mean the rule matched
# nothing, which is the failure this whole check exists to catch.
[[ "$DIRTY_RC" -eq 1 ]] || fail "gitleaks exited $DIRTY_RC scanning fixtures/dirty, expected 1 (leak found):\n$(cat "$WORK/gitleaks/dirty.log")"
grep -q '"RuleID": "internal-service-token"' "$WORK/gitleaks/dirty.json" \
  || fail "gitleaks did not report rule internal-service-token against fixtures/dirty"
grep -q '"Secret": "svc_deadbeefdeadbeefdeadbeefdeadbeef"' "$WORK/gitleaks/dirty.json" \
  || fail "gitleaks did not report the planted secret value"
pass "gitleaks caught the planted secret in fixtures/dirty (rule internal-service-token)"

set +e
docker run --rm -v "$SECRETS_DIR:/repo:ro" -v "$WORK/gitleaks:/out" "$GITLEAKS_IMAGE" \
  dir /repo/fixtures/clean -c /repo/.gitleaks.toml --no-banner --no-color \
  --report-format json --report-path /out/clean.json >"$WORK/gitleaks/clean.log" 2>&1
CLEAN_RC=$?
set -e
[[ "$CLEAN_RC" -eq 0 ]] || fail "gitleaks exited $CLEAN_RC scanning fixtures/clean, expected 0 (no leaks):\n$(cat "$WORK/gitleaks/clean.log")"
[[ "$(cat "$WORK/gitleaks/clean.json")" == "[]" ]] \
  || fail "gitleaks reported findings against fixtures/clean, the allowlist entry is not working:\n$(cat "$WORK/gitleaks/clean.json")"
pass "gitleaks reports zero leaks in fixtures/clean (allowlist entry works)"

# ---------------------------------------------------------------------------
# b) SOPS + age round trip
# ---------------------------------------------------------------------------
step "b) SOPS + age round trip with a throwaway keypair"
mkdir -p "$WORK/rt" "$WORK/keys"

cat > "$WORK/rt/plain.yaml" <<'EOF'
username: alice
password: hunter2
EOF

docker run --rm -v "$WORK:/w" -w /w "$ALPINE_IMAGE" sh -c "
  set -e
  apk add --no-cache -q $AGE_SOPS_PIN
  age-keygen -o /w/keys/correct.txt 2>/w/keys/correct.raw
  age-keygen -o /w/keys/wrong.txt   2>/w/keys/wrong.raw
  grep -i 'public key' /w/keys/correct.raw | sed 's/.*: //' > /w/keys/correct.pub
  grep -i 'public key' /w/keys/wrong.raw   | sed 's/.*: //' > /w/keys/wrong.pub
" >"$WORK/rt/keygen.log" 2>&1 || fail "age-keygen failed:\n$(cat "$WORK/rt/keygen.log")"

CORRECT_PUB="$(cat "$WORK/keys/correct.pub")"
[[ -n "$CORRECT_PUB" ]] || fail "could not extract the throwaway age public key"

docker run --rm -v "$WORK:/w" -w /w/rt "$ALPINE_IMAGE" sh -c "
  apk add --no-cache -q $AGE_SOPS_PIN
  sops --encrypt --age '$CORRECT_PUB' plain.yaml > enc.yaml
" >"$WORK/rt/encrypt.log" 2>&1 || fail "sops encrypt failed:\n$(cat "$WORK/rt/encrypt.log")"

grep -q '^username: ENC\[' "$WORK/rt/enc.yaml" || fail "username key is not readable / value is not ciphertext"
grep -q '^password: ENC\[' "$WORK/rt/enc.yaml" || fail "password key is not readable / value is not ciphertext"
grep -q '^username: alice$' "$WORK/rt/enc.yaml" && fail "username value is still plaintext -- encryption did not happen"
pass "sops encrypt: keys readable, values are ciphertext"

docker run --rm -v "$WORK:/w" -w /w/rt -e SOPS_AGE_KEY_FILE=/w/keys/correct.txt "$ALPINE_IMAGE" sh -c "
  apk add --no-cache -q $AGE_SOPS_PIN
  sops --decrypt enc.yaml
" >"$WORK/rt/decrypted.yaml" 2>"$WORK/rt/decrypt.log" || fail "sops decrypt with the correct key failed:\n$(cat "$WORK/rt/decrypt.log")"
diff -u "$WORK/rt/plain.yaml" "$WORK/rt/decrypted.yaml" >"$WORK/rt/diff.log" 2>&1 \
  || fail "decrypted plaintext is not byte-identical to the original:\n$(cat "$WORK/rt/diff.log")"
pass "sops decrypt with the correct key reproduces the plaintext byte-identically"

set +e
docker run --rm -v "$WORK:/w" -w /w/rt -e SOPS_AGE_KEY_FILE=/w/keys/wrong.txt "$ALPINE_IMAGE" sh -c "
  apk add --no-cache -q $AGE_SOPS_PIN
  sops --decrypt enc.yaml
" >"$WORK/rt/wrong.log" 2>&1
WRONG_RC=$?
set -e
[[ "$WRONG_RC" -ne 0 ]] || fail "sops decrypt with the WRONG age key succeeded -- it must not"
grep -qi "no identity matched any of the recipients\|failed to get the data key" "$WORK/rt/wrong.log" \
  || fail "sops rejected the wrong key but without the expected diagnostic:\n$(cat "$WORK/rt/wrong.log")"
pass "sops decrypt with a different age key is rejected with the expected diagnostic"

# ---------------------------------------------------------------------------
# c) .sops.yaml creation_rules match the paths they claim
# ---------------------------------------------------------------------------
step "c) .sops.yaml creation_rules match their target paths and recipients"
REPO="$WORK/match/repo"
mkdir -p "$REPO/baselines/ansible/inventory/group_vars" \
         "$REPO/baselines/kubernetes/bootstrap-secrets" \
         "$REPO/misc"
cp "$SECRETS_DIR/.sops.yaml" "$REPO/.sops.yaml"

# age PUBLIC keys, matching baselines/secrets/.sops.yaml -- safe to commit
# (see that file's header). gitleaks' default ruleset's generic-api-key rule
# still flags them by shape (high-entropy string assigned to a var); the
# inline `gitleaks:allow` comment suppresses just these two known-safe lines
# without touching the shared allowlist in .gitleaks.toml.
OPS_ANSIBLE_KEY="age1u35gqqustgezt2wq27v0tvy8sxdp4hxxjljggpg2zw2l7s904uns4tfcdj"    # gitleaks:allow
PLATFORM_K8S_KEY="age1x98hlj0ve08pn8nj8anacgkhd60340j5823czxmessq9jah2q4ts2w4rpn"  # gitleaks:allow

cat > "$REPO/baselines/ansible/inventory/group_vars/prod.sops.yml" <<'EOF'
db_password: correct-horse-battery-staple
EOF
cat > "$REPO/baselines/kubernetes/bootstrap-secrets/vault-token.sops.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: vault-token
type: Opaque
stringData:
  token: s.abcdef
EOF
cat > "$REPO/misc/other.sops.yaml" <<'EOF'
some_key: some_value
EOF

docker run --rm -v "$REPO:/w" -w /w "$ALPINE_IMAGE" sh -c "
  set -e
  apk add --no-cache -q $AGE_SOPS_PIN
  sops -e -i baselines/ansible/inventory/group_vars/prod.sops.yml
  sops -e -i baselines/kubernetes/bootstrap-secrets/vault-token.sops.yaml
  sops -e -i misc/other.sops.yaml
" >"$WORK/match/encrypt.log" 2>&1 || fail "sops -e against the creation_rules paths failed:\n$(cat "$WORK/match/encrypt.log")"

ANSIBLE_FILE="$REPO/baselines/ansible/inventory/group_vars/prod.sops.yml"
grep -q "recipient: $OPS_ANSIBLE_KEY" "$ANSIBLE_FILE" \
  || fail "ansible group_vars file was not encrypted for the ops_ansible recipient"
grep -q "recipient: $PLATFORM_K8S_KEY" "$ANSIBLE_FILE" \
  && fail "ansible group_vars file was ALSO encrypted for platform_k8s -- the wrong rule matched"
pass "ansible group_vars path_regex matches and grants only the ops_ansible recipient"

K8S_FILE="$REPO/baselines/kubernetes/bootstrap-secrets/vault-token.sops.yaml"
grep -q "recipient: $PLATFORM_K8S_KEY" "$K8S_FILE" \
  || fail "kubernetes bootstrap-secrets file was not encrypted for the platform_k8s recipient"
grep -q "recipient: $OPS_ANSIBLE_KEY" "$K8S_FILE" \
  && fail "kubernetes bootstrap-secrets file was ALSO encrypted for ops_ansible -- the wrong rule matched"
grep -q '^kind: Secret$' "$K8S_FILE" || fail "encrypted_regex over-encrypted: 'kind' should stay plaintext"
grep -q '^type: Opaque$' "$K8S_FILE" || fail "encrypted_regex over-encrypted: 'type' should stay plaintext"
grep -q '^    token: ENC\[' "$K8S_FILE" || fail "encrypted_regex under-encrypted: 'stringData.token' should be ciphertext"
pass "kubernetes bootstrap-secrets path_regex matches, grants only platform_k8s, encrypted_regex scopes to stringData"

MISC_FILE="$REPO/misc/other.sops.yaml"
grep -q "recipient: $OPS_ANSIBLE_KEY" "$MISC_FILE" || fail "catch-all rule did not grant ops_ansible"
grep -q "recipient: $PLATFORM_K8S_KEY" "$MISC_FILE" || fail "catch-all rule did not grant platform_k8s"
pass "catch-all path_regex (last rule) grants both recipients to an otherwise-unmatched *.sops.yaml file"

# ---------------------------------------------------------------------------
# d) Vault policy: real parser, plus a live least-privilege + KV v2 proof
# ---------------------------------------------------------------------------
step "d) vault policy fmt rejects broken policies, accepts the real one"
mkdir -p "$WORK/vault"
cat > "$WORK/vault/bad-syntax.hcl" <<'EOF'
path "secret/data/app-readonly/*" {
  capabilities = ["read"
}
EOF
cat > "$WORK/vault/bad-cap.hcl" <<'EOF'
path "secret/data/app-readonly/*" {
  capabilities = ["fly"]
}
EOF
cp "$SECRETS_DIR/vault/policy-app-readonly.hcl" "$WORK/vault/good.hcl"
chmod 666 "$WORK/vault/bad-syntax.hcl" "$WORK/vault/bad-cap.hcl" "$WORK/vault/good.hcl"

for bad in bad-syntax bad-cap; do
  set +e
  docker run --rm -v "$WORK/vault:/w" -w /w "$VAULT_IMAGE" policy fmt "$bad.hcl" >"$WORK/vault/$bad.log" 2>&1
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || fail "vault policy fmt accepted $bad.hcl -- it must reject it"
  grep -qi "failed to parse policy" "$WORK/vault/$bad.log" \
    || fail "$bad.hcl was rejected but without the expected diagnostic:\n$(cat "$WORK/vault/$bad.log")"
done
pass "vault policy fmt rejects a syntax error and an invalid capability, each with the expected diagnostic"

docker run --rm -v "$WORK/vault:/w" -w /w "$VAULT_IMAGE" policy fmt good.hcl >"$WORK/vault/good.log" 2>&1 \
  || fail "vault policy fmt rejected the real shipped policy:\n$(cat "$WORK/vault/good.log")"
pass "vault policy fmt accepts baselines/secrets/vault/policy-app-readonly.hcl"

step "d) live dev-mode Vault: policy round trip, least-privilege denial, KV v2 path trap"
VAULT_CID="$(docker run -d --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_ADDR=http://127.0.0.1:8200 \
  -v "$SECRETS_DIR/vault:/policies:ro" \
  "$VAULT_IMAGE" server -dev -dev-listen-address=0.0.0.0:8200)"

vault_exec() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="${1:-root}" "$VAULT_CID" "${@:2}"; }

ready=0
for _ in $(seq 1 30); do
  if vault_exec root vault status >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" -eq 1 ]] || fail "dev-mode vault server did not become ready in time"

vault_exec root vault policy write app-readonly /policies/policy-app-readonly.hcl >"$WORK/vault/write.log" 2>&1 \
  || fail "vault policy write failed:\n$(cat "$WORK/vault/write.log")"
vault_exec root vault policy read app-readonly >"$WORK/vault/readback.hcl" 2>"$WORK/vault/readback.log" \
  || fail "vault policy read failed:\n$(cat "$WORK/vault/readback.log")"
grep -q 'path "secret/data/app-readonly/\*"' "$WORK/vault/readback.hcl" \
  || fail "policy read back from vault does not contain the expected path block"
pass "vault policy write/read round trip through a real server matches what was shipped"

vault_exec root vault kv put secret/app-readonly/db password=hunter2 >/dev/null 2>&1 \
  || fail "setup: could not write the test secret as root"
vault_exec root vault kv put secret/other-app/db password=not-yours >/dev/null 2>&1 \
  || fail "setup: could not write the sibling app's test secret as root"

SCOPED_TOKEN="$(vault_exec root vault token create -policy=app-readonly -field=token)"
[[ -n "$SCOPED_TOKEN" ]] || fail "could not create a token scoped to app-readonly"

OWN_READ="$(vault_exec "$SCOPED_TOKEN" vault kv get -field=password secret/app-readonly/db 2>"$WORK/vault/own-read.log")" \
  || fail "the app-readonly token could not read its OWN path:\n$(cat "$WORK/vault/own-read.log")"
[[ "$OWN_READ" == "hunter2" ]] || fail "the app-readonly token read back the wrong value: $OWN_READ"
pass "a token scoped to policy-app-readonly.hcl can read its own path"

set +e
vault_exec "$SCOPED_TOKEN" vault kv get secret/other-app/db >"$WORK/vault/sibling-read.log" 2>&1
SIBLING_RC=$?
set -e
[[ "$SIBLING_RC" -ne 0 ]] || fail "the app-readonly token was able to read a SIBLING app's secret -- least privilege is broken"
grep -q "403\|permission denied" "$WORK/vault/sibling-read.log" \
  || fail "the sibling read was rejected but without the expected 403/permission-denied diagnostic:\n$(cat "$WORK/vault/sibling-read.log")"
pass "the same token is DENIED (403) reading a sibling app's secret -- least privilege proven live, not asserted"

# The trap the policy file's own comments describe: the CLI hides the KV v2
# data/ segment, a raw API call (or a naively-written policy path) does not.
CLI_SHAPED="$(vault_exec root vault read secret/app-readonly/db 2>&1)"
echo "$CLI_SHAPED" | grep -q "hunter2" \
  && fail "raw 'vault read' at the CLI-shaped (v1-looking) path unexpectedly returned data -- the mount may not be KV v2"
echo "$CLI_SHAPED" | grep -qi "Invalid path for a versioned K/V" \
  || fail "raw 'vault read' at the CLI-shaped path did not warn as expected:\n$CLI_SHAPED"
V2_SHAPED="$(vault_exec root vault read secret/data/app-readonly/db 2>&1)"
echo "$V2_SHAPED" | grep -q "hunter2" \
  || fail "raw 'vault read' at the real secret/data/... path did not return the secret:\n$V2_SHAPED"
pass "KV v2 path trap demonstrated live: secret/app-readonly/db returns nothing raw, secret/data/app-readonly/db does"

docker rm -f "$VAULT_CID" >/dev/null 2>&1
VAULT_CID=""

# ---------------------------------------------------------------------------
# e) ESO manifests against the real CRD schemas
# ---------------------------------------------------------------------------
step "e) kubeconform -strict: ESO manifests against the real CRD JSON schemas"
SCHEMA_TEMPLATE='/w/eso/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

if ! docker run --rm --network none -v "$SECRETS_DIR:/w:ro" -w /w "$KUBECONFORM_IMAGE" \
  -strict -summary -output json \
  -schema-location "$SCHEMA_TEMPLATE" \
  eso/cluster-secret-store.yaml eso/external-secret.yaml >"$WORK/eso-good.json" 2>&1; then
  fail "kubeconform rejected the shipped ESO manifests:\n$(cat "$WORK/eso-good.json")"
fi
grep -q '"valid": 2' "$WORK/eso-good.json" || fail "kubeconform did not report both ESO manifests as valid:\n$(cat "$WORK/eso-good.json")"
pass "ClusterSecretStore and ExternalSecret both validate against the real ESO CRD schemas, fully offline"

mkdir -p "$WORK/eso-neg"
sed 's/secretKey: password/secretKey: password\n      totallyBogusField: yes/' \
  "$SECRETS_DIR/eso/external-secret.yaml" > "$WORK/eso-neg/es-unknown-field.yaml"
grep -q totallyBogusField "$WORK/eso-neg/es-unknown-field.yaml" \
  || fail "the control could not inject the unknown field -- update this test"
sed '/server: "https/d' "$SECRETS_DIR/eso/cluster-secret-store.yaml" > "$WORK/eso-neg/css-missing-field.yaml"
grep -q 'server:' "$WORK/eso-neg/css-missing-field.yaml" \
  && fail "the control could not remove the required field -- update this test"

set +e
docker run --rm --network none -v "$SECRETS_DIR:/schemas:ro" -v "$WORK/eso-neg:/w:ro" -w /w "$KUBECONFORM_IMAGE" \
  -strict -summary \
  -schema-location "/schemas/eso/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  es-unknown-field.yaml >"$WORK/eso-neg/unknown.log" 2>&1
UNKNOWN_RC=$?
set -e
[[ "$UNKNOWN_RC" -ne 0 ]] || fail "kubeconform -strict accepted an ExternalSecret with an unknown field -- -strict is not really on"
grep -q "totallyBogusField" "$WORK/eso-neg/unknown.log" \
  || fail "kubeconform rejected the manifest but without naming the unknown field:\n$(cat "$WORK/eso-neg/unknown.log")"
pass "kubeconform -strict rejects an ExternalSecret with an unknown field, naming it"

set +e
docker run --rm --network none -v "$SECRETS_DIR:/schemas:ro" -v "$WORK/eso-neg:/w:ro" -w /w "$KUBECONFORM_IMAGE" \
  -strict -summary \
  -schema-location "/schemas/eso/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  css-missing-field.yaml >"$WORK/eso-neg/missing.log" 2>&1
MISSING_RC=$?
set -e
[[ "$MISSING_RC" -ne 0 ]] || fail "kubeconform accepted a ClusterSecretStore missing the required vault.server field"
grep -q "missing property 'server'" "$WORK/eso-neg/missing.log" \
  || fail "kubeconform rejected the manifest but without naming the missing field:\n$(cat "$WORK/eso-neg/missing.log")"
pass "kubeconform rejects a ClusterSecretStore missing the required provider.vault.server field, naming it"

echo
echo "All baselines/secrets/ checks passed."
