#!/usr/bin/env bash
# Static validation of baselines/kubernetes/*: every file that is a real API
# resource is checked against the actual Kubernetes 1.37 OpenAPI schema
# (kubeconform -strict). The three files that are NOT API resources
# (kubelet, audit, encryption config — nothing the API server exposes a
# schema for) get their own real check instead of being silently skipped:
#   - kubelet-config.yaml is fed to the real kubelet binary shipped in the
#     pinned kind node image, and the run must not trigger kubelet's own
#     "lenient decoding" fallback, which is what happens when a key does not
#     exist in the KubeletConfiguration type kubelet was compiled with.
#   - audit-policy.yaml and encryption-config.yaml are checked structurally
#     against the documented API (audit levels are a closed enum; the
#     "identity" provider, if present, must not be the encryption provider
#     that is actually used first).
# Full runtime validation of the control-plane-only files (does the API
# server actually start with them) is out of scope here — it would require
# booting a full kubeadm control plane, which is heavier than a NetworkPolicy
# or PSS check and part of what tests/kubernetes-e2e.sh already exists for on
# the workload side. See guides/kubernetes-hardening.md's Verification
# section for how to confirm these two on a real cluster.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$ROOT_DIR/baselines/kubernetes"

KUBECONFORM_IMAGE="ghcr.io/yannh/kubeconform@sha256:6b90a5f23d846140ce0194fe050b1995e546eba938f3a6bf10c039dd5e24588f"
YQ_IMAGE="mikefarah/yq@sha256:cfc4eee658595834ef304eadb0c3ea721f3b7cb6404ad8b7cb909cc5b5145b23"
PYTHON_IMAGE="python@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b"
KIND_NODE_IMAGE="kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
K8S_VERSION="1.37.0"

yq() { docker run --rm -v "$K8S_DIR:/w:ro" "$YQ_IMAGE" e "$@"; }

API_RESOURCE_FILES=(
  namespace-pss-restricted.yaml
  networkpolicy-default-deny.yaml
  networkpolicy-allow-dns.yaml
  rbac-least-privilege.yaml
  hardened-deployment.yaml
  vap-disallow-latest-tag.yaml
  vap-require-nonroot.yaml
)

echo "==> kubeconform -strict (Kubernetes $K8S_VERSION): API-resource baselines"
docker run --rm -v "$K8S_DIR:/w:ro" -w /w "$KUBECONFORM_IMAGE" \
  -strict -kubernetes-version "$K8S_VERSION" -summary \
  "${API_RESOURCE_FILES[@]}"

echo "==> yamllint --strict: every baseline YAML file"
docker run --rm -v "$K8S_DIR:/w:ro" "$PYTHON_IMAGE" \
  sh -c "pip install --quiet --root-user-action=ignore yamllint==1.38.0 && \
    yamllint --strict -d '{extends: default, rules: {line-length: disable, document-start: disable}}' /w"

echo "==> real kubelet binary: kubelet-config.yaml must decode without unknown fields"
KUBELET_OUT="$(mktemp)"
trap 'rm -f "$KUBELET_OUT"' EXIT
timeout 8 docker run --rm -v "$K8S_DIR:/cfg:ro" --entrypoint /usr/bin/kubelet "$KIND_NODE_IMAGE" \
  --config=/cfg/kubelet-config.yaml > "$KUBELET_OUT" 2>&1 || true
cat "$KUBELET_OUT"
if grep -q "lenient decoding" "$KUBELET_OUT"; then
  echo "FAIL: kubelet-config.yaml has a field kubelet does not recognize:" >&2
  grep "lenient decoding" "$KUBELET_OUT" >&2
  exit 1
fi
if grep -qE "failed to decode|could not find expected|yaml:" "$KUBELET_OUT"; then
  echo "FAIL: kubelet-config.yaml is not valid YAML/KubeletConfiguration:" >&2
  exit 1
fi
# Positive marker that the file was accepted: the kubelet must get far enough
# to start initialising. On a node image where it proceeds further it prints
# "kubelet dependencies"; from 1.37 it stops earlier, at the first missing
# runtime prerequisite ("failed to run Kubelet: open
# /etc/kubernetes/pki/ca.crt"), which it can only reach with a decoded config.
# Requiring one of the two keeps a silent run (no output at all) a failure.
if ! grep -qE "kubelet dependencies|failed to run Kubelet" "$KUBELET_OUT"; then
  echo "FAIL: kubelet did not get past config loading (unexpected output above)" >&2
  exit 1
fi

echo "==> structural check: audit-policy.yaml"
RULE_COUNT="$(yq '.rules | length' /w/audit-policy.yaml)"
if [[ "$RULE_COUNT" -lt 1 ]]; then
  echo "FAIL: audit-policy.yaml must have at least one rule (the API server rejects an empty policy)" >&2
  exit 1
fi
BAD_LEVELS="$(yq '.rules[].level' /w/audit-policy.yaml | grep -vE '^(None|Metadata|Request|RequestResponse)$' || true)"
if [[ -n "$BAD_LEVELS" ]]; then
  echo "FAIL: audit-policy.yaml has rule(s) with an invalid level: $BAD_LEVELS" >&2
  exit 1
fi

echo "==> structural check: encryption-config.yaml"
FIRST_PROVIDER="$(yq '.resources[0].providers[0] | keys | .[0]' /w/encryption-config.yaml)"
if [[ "$FIRST_PROVIDER" == "identity" ]]; then
  echo "FAIL: encryption-config.yaml has 'identity' (plaintext) as the FIRST provider — data would be stored unencrypted" >&2
  exit 1
fi
KMS_VERSIONS="$(yq '.resources[0].providers[] | select(has("kms")) | .kms.apiVersion' /w/encryption-config.yaml || true)"
if echo "$KMS_VERSIONS" | grep -qx "v1"; then
  echo "FAIL: encryption-config.yaml configures a KMS v1 provider — v1 is deprecated and disabled by default since Kubernetes v1.29, use apiVersion: v2" >&2
  exit 1
fi

echo "All kubernetes static baseline checks passed."
