#!/usr/bin/env bash
# End-to-end validation of baselines/kubernetes/* on a throwaway kind cluster.
#
# tests/kubernetes.sh checks that these files are valid against the API schema.
# That is not the same as checking that they DO anything, which is the failure
# this file exists for: a NetworkPolicy that selects no pods, a Pod Security
# label that admits what it should reject, or an admission policy with no
# binding are all schema-valid and all useless.
#
# Every assertion is paired with the same assertion made BEFORE the baseline is
# applied, so a check that cannot fail is visible as a failure here rather than
# as a green run.
#
# Host requirements: docker, curl, bash. kubectl and kind are downloaded at a
# pinned version into a temporary directory; nothing is installed on the host,
# and the cluster is deleted on exit including on failure.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$ROOT_DIR/baselines/kubernetes"
DOCKER_DIR="$ROOT_DIR/baselines/docker"

# kind v0.33.0's own default node image, so the pair is a combination upstream
# tests. Kubernetes 1.37 is also what namespace-pss-restricted.yaml pins
# enforce-version to: a namespace may not pin a version NEWER than the API
# server, so these two move together.
KIND_VERSION="v0.33.0"
KIND_SHA256="aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
NODE_IMAGE="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
K8S_MINOR="v1.37"

CLUSTER="devops-toolkit-e2e-$$"
APP_IMAGE="devops-toolkit/example-app:v1"
NS=production

TMP_DIR="$(mktemp -d)"
BIN="$TMP_DIR/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "    ok: $*"; }

cleanup() {
  local rc=$?
  if [ -x "$BIN/kind" ]; then
    echo "==> deleting cluster $CLUSTER"
    "$BIN/kind" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap cleanup EXIT

command -v docker >/dev/null || fail "docker is required"
command -v curl >/dev/null || fail "curl is required"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

# ---------------------------------------------------------------------------
# tooling, pinned and checksummed
# ---------------------------------------------------------------------------
echo "==> fetching kind $KIND_VERSION and kubectl $K8S_MINOR"
curl -fsSLo "$BIN/kind" \
  "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64"
echo "$KIND_SHA256  $BIN/kind" | sha256sum -c - >/dev/null \
  || fail "kind binary checksum mismatch — refusing to run it"
chmod +x "$BIN/kind"

# kubectl's own published checksum, fetched alongside the binary from the same
# release channel; the point is integrity of the download, not of the channel.
KUBECTL_PATCH="$(curl -fsSL "https://dl.k8s.io/release/stable-${K8S_MINOR#v}.txt")"
curl -fsSLo "$BIN/kubectl" "https://dl.k8s.io/release/$KUBECTL_PATCH/bin/linux/amd64/kubectl"
KUBECTL_SHA="$(curl -fsSL "https://dl.k8s.io/release/$KUBECTL_PATCH/bin/linux/amd64/kubectl.sha256")"
echo "$KUBECTL_SHA  $BIN/kubectl" | sha256sum -c - >/dev/null \
  || fail "kubectl binary checksum mismatch — refusing to run it"
chmod +x "$BIN/kubectl"
ok "kind $KIND_VERSION, kubectl $KUBECTL_PATCH (checksums verified)"

# ---------------------------------------------------------------------------
# cluster
# ---------------------------------------------------------------------------
# One control-plane node is enough for admission and NetworkPolicy behaviour.
# The API server flags are the ones baselines/kubernetes/audit-policy.yaml and
# encryption-config.yaml exist for, mounted from the baseline files themselves
# so this also proves the API server starts with them — which is the part
# tests/kubernetes.sh explicitly leaves out of scope.
cat > "$TMP_DIR/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: $NODE_IMAGE
    extraMounts:
      - hostPath: $K8S_DIR/audit-policy.yaml
        containerPath: /etc/kubernetes/audit-policy.yaml
        readOnly: true
      - hostPath: $TMP_DIR/encryption-config.yaml
        containerPath: /etc/kubernetes/encryption-config.yaml
        readOnly: true
      - hostPath: $TMP_DIR/audit
        containerPath: /var/log/kubernetes
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-policy-file: /etc/kubernetes/audit-policy.yaml
        audit-log-path: /var/log/kubernetes/audit.log
        audit-log-maxage: "7"
        encryption-provider-config: /etc/kubernetes/encryption-config.yaml
      extraVolumes:
        - name: audit-policy
          hostPath: /etc/kubernetes/audit-policy.yaml
          mountPath: /etc/kubernetes/audit-policy.yaml
          readOnly: true
          pathType: File
        - name: encryption-config
          hostPath: /etc/kubernetes/encryption-config.yaml
          mountPath: /etc/kubernetes/encryption-config.yaml
          readOnly: true
          pathType: File
        - name: audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
EOF
mkdir -p "$TMP_DIR/audit"

# The no-KMS variant is the one that can be booted here: a kms provider whose
# socket does not exist makes kubeadm fail with "got unexpected nil
# transformer", so encryption-config.yaml (KMS v2 first) cannot be validated
# without the plugin it names. The shipped key is a public placeholder, so a
# real random key is substituted for this run — which also proves the
# documented `head -c 32 /dev/urandom | base64` produces an accepted key.
E2E_KEY="$(head -c 32 /dev/urandom | base64 -w0)"
sed "s|UExBQ0VIT0xERVItUkVQTEFDRS1NRS0zMkJZVEVTISE=|$E2E_KEY|" \
  "$K8S_DIR/encryption-config-secretbox.yaml" > "$TMP_DIR/encryption-config.yaml"
grep -q "$E2E_KEY" "$TMP_DIR/encryption-config.yaml" \
  || fail "failed to substitute a real key into the encryption config"

echo "==> creating kind cluster $CLUSTER (Kubernetes $K8S_MINOR)"
"$BIN/kind" create cluster --name "$CLUSTER" --config "$TMP_DIR/kind.yaml" --wait 180s \
  || fail "kind cluster did not come up — the API server may have rejected audit-policy.yaml or encryption-config-secretbox.yaml"
export KUBECONFIG="$TMP_DIR/kubeconfig"
"$BIN/kind" get kubeconfig --name "$CLUSTER" > "$KUBECONFIG"
ok "API server started with the baseline audit policy and secretbox encryption config"

kubectl() { "$BIN/kubectl" "$@"; }

SERVER_MINOR="v$(kubectl version -o json | python3 -c "import json,sys;v=json.load(sys.stdin)['serverVersion'];print(v['major']+'.'+v['minor'])")"
[ "$SERVER_MINOR" = "$K8S_MINOR" ] \
  || fail "expected a $K8S_MINOR API server, got $SERVER_MINOR — namespace-pss-restricted.yaml pins enforce-version to $K8S_MINOR"
ok "API server is $SERVER_MINOR, matching the pinned enforce-version"

# ---------------------------------------------------------------------------
# the workload image the hardened Deployment refers to
# ---------------------------------------------------------------------------
echo "==> building and loading $APP_IMAGE"
docker build -q -t "$APP_IMAGE" -f "$DOCKER_DIR/Dockerfile" "$DOCKER_DIR" >/dev/null
"$BIN/kind" load docker-image "$APP_IMAGE" --name "$CLUSTER" >/dev/null
ok "image available in the node's containerd store"

# ---------------------------------------------------------------------------
# 1. Pod Security Standards
# ---------------------------------------------------------------------------
PRIV_POD='
apiVersion: v1
kind: Pod
metadata:
  name: privileged-probe
spec:
  containers:
    - name: c
      image: registry.k8s.io/pause:3.10
      securityContext:
        privileged: true
'

echo "==> control: WITHOUT the restricted labels, a privileged pod is admitted"
kubectl create namespace pss-control >/dev/null
printf '%s' "$PRIV_POD" | kubectl apply -n pss-control -f - >/dev/null 2>&1 \
  || fail "a privileged pod was rejected in an unlabelled namespace — this cluster rejects it for some other reason, so the next assertion would prove nothing"
ok "privileged pod admitted in an unlabelled namespace"
kubectl delete namespace pss-control --wait=false >/dev/null

echo "==> Pod Security Standards: restricted namespace rejects a privileged pod"
kubectl apply -f "$K8S_DIR/namespace-pss-restricted.yaml" >/dev/null
PSS_OUT="$(printf '%s' "$PRIV_POD" | kubectl apply -n "$NS" -f - 2>&1 || true)"
printf '%s' "$PSS_OUT" | grep -q 'violates PodSecurity "restricted' \
  || fail "expected a PodSecurity rejection in $NS, got: $PSS_OUT"
ok "rejected by Pod Security Admission: $(printf '%s' "$PSS_OUT" | head -1 | cut -c1-110)"

# ---------------------------------------------------------------------------
# 2. the hardened Deployment is admitted by that same namespace and runs
# ---------------------------------------------------------------------------
# A "hardened" manifest that the restricted profile rejects, or that never
# becomes Ready, is the more common failure than a missing control.
# hardened-deployment.yaml sets serviceAccountName: app-reader, which lives in
# rbac-least-privilege.yaml. Without it the ReplicaSet controller cannot create
# pods at all ("error looking up service account production/app-reader"), and
# the Deployment sits at 0 available with nothing wrong in the manifest — so
# these two files are one change, in this order.
echo "==> RBAC baseline (the Deployment's ServiceAccount lives here)"
kubectl apply -f "$K8S_DIR/rbac-least-privilege.yaml" >/dev/null
kubectl -n "$NS" get serviceaccount app-reader >/dev/null \
  || fail "rbac-least-privilege.yaml did not create the app-reader ServiceAccount"
ok "app-reader ServiceAccount and its Role exist"

echo "==> the hardened Deployment is admitted by restricted and becomes Ready"
kubectl apply -f "$K8S_DIR/hardened-deployment.yaml" >/dev/null
kubectl -n "$NS" rollout status deploy/hardened-app --timeout=120s >/dev/null \
  || { kubectl -n "$NS" get rs -o name | while read -r rs; do
         kubectl -n "$NS" describe "$rs" | sed -n "/Events:/,\$p"; done
       kubectl -n "$NS" get pods
       fail "the hardened Deployment never became Ready"; }
ok "Deployment Ready under the restricted profile"

POD="$(kubectl -n "$NS" get pod -l app=hardened-app -o jsonpath='{.items[0].metadata.name}')"
[ -n "$POD" ] || fail "no pod found for the hardened Deployment"

# The image is distroless: no shell, no coreutils, so `kubectl exec ... id -u`
# returns nothing. That is a property worth keeping, not working around, so the
# assertions below read the container runtime's own view on the node instead —
# which is stronger evidence than the manifest anyway, because it is what
# containerd actually applied.
NODE="$("$BIN/kind" get nodes --name "$CLUSTER" | head -1)"
CTR_ID="$(docker exec "$NODE" crictl ps --name '^app$' -q | head -1)"
[ -n "$CTR_ID" ] || fail "could not find the running container for $POD via crictl"
CTR_SPEC="$(docker exec "$NODE" crictl inspect "$CTR_ID")"

spec_get() { printf '%s' "$CTR_SPEC" | python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1" 2>/dev/null || true; }

RUN_UID="$(spec_get "['info']['runtimeSpec']['process']['user']['uid']")"
[ "$RUN_UID" = "65532" ] || fail "the runtime is running the container as uid '$RUN_UID', not 65532"
ok "containerd runs the container as uid 65532"

RUN_GID="$(spec_get "['info']['runtimeSpec']['process']['user']['gid']")"
[ "$RUN_GID" = "65532" ] || fail "the runtime is running the container as gid '$RUN_GID', not 65532"
ok "containerd runs the container as gid 65532"

RUN_RO="$(spec_get "['info']['runtimeSpec']['root']['readonly']")"
[ "$RUN_RO" = "True" ] || fail "the runtime did not apply a read-only root filesystem (got '$RUN_RO')"
ok "root filesystem is read-only in the runtime spec"

RUN_NNP="$(spec_get "['info']['runtimeSpec']['process']['noNewPrivileges']")"
[ "$RUN_NNP" = "True" ] || fail "no_new_privs is not set on the running container (got '$RUN_NNP')"
ok "no_new_privs is set"

# With every capability dropped, containerd omits the key rather than writing an
# empty list, so "missing" and "[]" are the same answer here.
RUN_CAPS="$(printf '%s' "$CTR_SPEC" | python3 -c "import json,sys;c=json.load(sys.stdin)['info']['runtimeSpec']['process'].get('capabilities',{});print(len(c.get('bounding') or []))")"
[ "$RUN_CAPS" = "0" ] || fail "the capability bounding set is not empty ($RUN_CAPS capabilities)"
ok "capability bounding set is empty (all capabilities dropped)"

RUN_SECCOMP="$(spec_get "['info']['runtimeSpec']['linux']['seccomp']['defaultAction']")"
[ -n "$RUN_SECCOMP" ] || fail "no seccomp profile is applied to the running container"
ok "a seccomp profile is applied (defaultAction: $RUN_SECCOMP)"

# Control: the same readings on a pod created WITHOUT the hardened settings must
# differ, otherwise these values are the runtime's defaults and prove nothing.
echo "==> control: an unhardened pod shows the opposite runtime settings"
kubectl create namespace runtime-control >/dev/null
cat <<'YAML' | kubectl apply -n runtime-control -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: plain
  labels:
    app: plain
spec:
  containers:
    - name: plain
      image: registry.k8s.io/e2e-test-images/agnhost:2.53
      command: ["sleep", "3600"]
YAML
kubectl -n runtime-control wait --for=condition=Ready pod/plain --timeout=120s >/dev/null \
  || fail "the control pod never became Ready"
PLAIN_ID="$(docker exec "$NODE" crictl ps --name '^plain$' -q | head -1)"
PLAIN_SPEC="$(docker exec "$NODE" crictl inspect "$PLAIN_ID")"
# containerd omits root.readonly entirely when it is false, so a missing key is
# the answer "writable".
PLAIN_RO="$(printf '%s' "$PLAIN_SPEC" | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['runtimeSpec']['root'].get('readonly', False))" 2>/dev/null || echo unknown)"
PLAIN_CAPS="$(printf '%s' "$PLAIN_SPEC" | python3 -c "import json,sys;c=json.load(sys.stdin)['info']['runtimeSpec']['process'].get('capabilities',{});print(len(c.get('bounding') or []))" 2>/dev/null || echo unknown)"
[ "$PLAIN_RO" = "False" ] || fail "expected an unhardened pod to have a writable rootfs, got '$PLAIN_RO' — the read-only check above may be reading a runtime default"
[ "$PLAIN_CAPS" != "0" ] || fail "an unhardened pod ALSO has an empty capability set — the check above is reading a runtime default"
ok "unhardened pod: root readonly=$PLAIN_RO, $PLAIN_CAPS capabilities retained"
kubectl delete namespace runtime-control --wait=false >/dev/null

# ---------------------------------------------------------------------------
# 3. NetworkPolicy: default-deny must block, and DNS must still work
# ---------------------------------------------------------------------------
# This is where the CNI matters: a NetworkPolicy the CNI does not enforce is
# accepted by the API server and does nothing. The control below establishes
# that the traffic flows BEFORE the policy, so "blocked" cannot be confused
# with "never worked".
CLIENT_POD='
apiVersion: v1
kind: Pod
metadata:
  name: netcheck
  labels:
    app: netcheck
spec:
  containers:
    - name: c
      image: registry.k8s.io/e2e-test-images/agnhost:2.53
      command: ["sleep", "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 65532
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
'
echo "==> netcheck client pod"
printf '%s' "$CLIENT_POD" | kubectl apply -n "$NS" -f - >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod/netcheck --timeout=120s >/dev/null \
  || fail "the netcheck pod never became Ready"

SVC_IP="$(kubectl -n "$NS" get svc hardened-app -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
if [ -z "$SVC_IP" ]; then
  TARGET_IP="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}')"
else
  TARGET_IP="$SVC_IP"
fi
[ -n "$TARGET_IP" ] || fail "could not determine a target IP for the connectivity check"

# agnhost's connect has an explicit timeout, so "blocked" is a timeout rather
# than the test hanging. A refused connection would mean the packet reached the
# host and nothing filtered it.
# Both helpers return a single token, so an assertion can never be satisfied by
# an empty string — which is exactly how a blocked check first looked like a
# passing one here.
#
# agnhost connect exits non-zero and names the reason; the reason matters, so it
# is carried in the token. A refused connection would mean the packet reached
# the host and nothing filtered it, which is a different outcome from blocked.
conn_check() {
  local out rc
  out="$(kubectl -n "$NS" exec netcheck -- \
    /agnhost connect --timeout=5s "$TARGET_IP:8080" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo CONNECTED
  elif printf '%s' "$out" | grep -qiE 'timed out|timeout|i/o timeout|deadline'; then
    echo BLOCKED_TIMEOUT
  elif printf '%s' "$out" | grep -qiE 'refused'; then
    echo REFUSED
  else
    echo "OTHER:$out"
  fi
}

dns_check() {
  kubectl -n "$NS" exec netcheck -- sh -c \
    'if timeout 5 nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
       echo RESOLVED
     else
       echo DNS_BLOCKED
     fi' 2>/dev/null || echo DNS_BLOCKED
}

echo "==> control: before any NetworkPolicy, pod-to-pod and DNS both work"
OUT="$(conn_check)"
[ "$OUT" = CONNECTED ] || fail "pod-to-pod traffic did not work even before a NetworkPolicy: $OUT"
ok "pod-to-pod to $TARGET_IP:8080 succeeds"
OUT="$(dns_check)"
[ "$OUT" = RESOLVED ] || fail "DNS did not resolve before any NetworkPolicy: $OUT"
ok "DNS resolves kubernetes.default"

echo "==> default-deny alone must block pod-to-pod AND DNS"
kubectl apply -f "$K8S_DIR/networkpolicy-default-deny.yaml" >/dev/null
sleep 5
OUT="$(conn_check)"
[ "$OUT" = BLOCKED_TIMEOUT ] \
  || fail "expected pod-to-pod to be blocked by timeout, got: $OUT. REFUSED would mean the packet reached the host; CONNECTED means this cluster's CNI does not enforce NetworkPolicy, and then the whole section proves nothing."
ok "pod-to-pod blocked, and blocked by timeout rather than refusal"
OUT="$(dns_check)"
[ "$OUT" = DNS_BLOCKED ] \
  || fail "DNS still resolved under default-deny, so egress is not actually denied: $OUT"
ok "DNS also blocked — which is why the DNS policy must ship in the same change"

echo "==> allow-dns restores DNS without restoring pod-to-pod"
kubectl apply -f "$K8S_DIR/networkpolicy-allow-dns.yaml" >/dev/null
sleep 5
OUT="$(dns_check)"
[ "$OUT" = RESOLVED ] || fail "DNS still does not resolve after applying the DNS allow policy: $OUT"
ok "DNS resolves again"
OUT="$(conn_check)"
[ "$OUT" = BLOCKED_TIMEOUT ] \
  || fail "the DNS allow policy also re-opened pod-to-pod traffic, which it must not: $OUT"
ok "pod-to-pod still blocked: the DNS policy widened egress only to port 53"

# ---------------------------------------------------------------------------
# 4. ValidatingAdmissionPolicy
# ---------------------------------------------------------------------------
LATEST_POD='
apiVersion: v1
kind: Pod
metadata:
  name: latest-tag
spec:
  containers:
    - name: c
      image: registry.k8s.io/pause:latest
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 65532
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
'
echo "==> control: before the policy, a :latest image is admitted"
printf '%s' "$LATEST_POD" | kubectl apply -n "$NS" -f - >/dev/null 2>&1 \
  || fail "a :latest pod was rejected before the policy existed — something else rejects it and the next check would prove nothing"
ok ":latest admitted without the policy"
kubectl -n "$NS" delete pod latest-tag --wait=false >/dev/null

echo "==> ValidatingAdmissionPolicy rejects :latest and admits a pinned tag"
kubectl apply -f "$K8S_DIR/vap-disallow-latest-tag.yaml" >/dev/null
# The binding is evaluated by the API server; give it a moment to be picked up.
for _ in $(seq 1 20); do
  VAP_OUT="$(printf '%s' "$LATEST_POD" | kubectl apply -n "$NS" -f - 2>&1 || true)"
  printf '%s' "$VAP_OUT" | grep -q "explicit non-'latest' tag" && break
  sleep 2
done
printf '%s' "$VAP_OUT" | grep -q "explicit non-'latest' tag" \
  || fail "expected the admission policy to reject a :latest image, got: $VAP_OUT"
ok "rejected: $(printf '%s' "$VAP_OUT" | head -1 | cut -c1-110)"

# And the policy must not be a blanket deny: a pinned tag still goes through.
PINNED_POD="$(printf '%s' "$LATEST_POD" | sed 's#pause:latest#pause:3.10#; s#name: latest-tag#name: pinned-tag#')"
printf '%s' "$PINNED_POD" | kubectl apply -n "$NS" -f - >/dev/null 2>&1 \
  || fail "the admission policy also rejected a correctly pinned tag"
ok "a pinned tag (pause:3.10) is still admitted"

# The registry-port case the naive expression gets wrong.
PORT_POD="$(printf '%s' "$LATEST_POD" | sed 's#registry.k8s.io/pause:latest#myregistry:5000/app#; s#name: latest-tag#name: registry-port#')"
PORT_OUT="$(printf '%s' "$PORT_POD" | kubectl apply -n "$NS" -f - 2>&1 || true)"
printf '%s' "$PORT_OUT" | grep -q "explicit non-'latest' tag" \
  || fail "an image with a registry port and NO tag (myregistry:5000/app) was admitted: $PORT_OUT"
ok "myregistry:5000/app rejected — the port colon is not mistaken for a tag"

# ---------------------------------------------------------------------------
# 5. the audit log the API server was started with actually receives events
# ---------------------------------------------------------------------------
echo "==> audit policy: the API server wrote audit events for the requests above"
# The log is written by the API server inside the node as root, mode 0600, so it
# is read through the node rather than from the bind mount on the host.
docker exec "$NODE" cat /var/log/kubernetes/audit.log > "$TMP_DIR/audit.log" 2>/dev/null || true
[ -s "$TMP_DIR/audit.log" ] \
  || fail "no audit log was produced, so audit-policy.yaml is not doing anything"
python3 - "$TMP_DIR/audit.log" <<'PY' || fail "the audit log does not contain the expected events"
import json, sys
kinds = set()
secrets_at_metadata_or_above = False
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    res = (e.get("objectRef") or {}).get("resource")
    if res:
        kinds.add(res)
    if res == "secrets" and e.get("level") in ("Metadata", "Request", "RequestResponse"):
        secrets_at_metadata_or_above = True
missing = {"pods", "networkpolicies"} - kinds
if missing:
    print(f"expected audit events for {missing}, saw: {sorted(kinds)[:15]}")
    sys.exit(1)
print(f"    resources seen in the audit log: {len(kinds)}")
PY
ok "audit events present for pods and networkpolicies"

# Secrets must never be logged at a level that includes their body.
python3 - "$TMP_DIR/audit.log" <<'PY' || fail "a Secret body was written to the audit log"
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if (e.get("objectRef") or {}).get("resource") == "secrets":
        if e.get("level") in ("Request", "RequestResponse"):
            print(f"secret logged at level {e['level']}: {e.get('requestURI')}")
            sys.exit(1)
PY
ok "no Secret was logged at Request or RequestResponse level"

# ---------------------------------------------------------------------------
# 6. etcd encryption at rest is really in effect
# ---------------------------------------------------------------------------
# The only honest check: write a Secret through the API and read the raw bytes
# out of etcd. Unencrypted, the value is visible in plain text.
echo "==> encryption at rest: a Secret is not readable in plain text in etcd"
kubectl -n "$NS" create secret generic e2e-canary \
  --from-literal=token=SUPERSECRETCANARYVALUE >/dev/null
# The kind node image has no etcdctl and the etcd image has no shell, so the
# read is an exec of etcdctl itself (etcdctl v3 needs no ETCDCTL_API any more)
# inside the etcd container, via crictl on the node.
NODE="$("$BIN/kind" get nodes --name "$CLUSTER" | head -1)"
ETCD_CTR="$(docker exec "$NODE" crictl ps --name '^etcd$' -q | head -1)"
[ -n "$ETCD_CTR" ] || fail "no running etcd container found on the node"
RAW="$(docker exec "$NODE" crictl exec "$ETCD_CTR" etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/production/e2e-canary 2>&1 | tr -d '\0' || true)"
[ -n "$RAW" ] || fail "could not read the Secret back out of etcd, so this check proves nothing"
printf '%s' "$RAW" | grep -q 'SUPERSECRETCANARYVALUE' \
  && fail "the Secret value is stored in PLAIN TEXT in etcd — encryption-config.yaml is not in effect"
printf '%s' "$RAW" | grep -qE 'k8s:enc:|aescbc|aesgcm|secretbox' \
  || fail "the stored Secret is neither plain text nor recognisably encrypted; inspect it by hand: $(printf '%s' "$RAW" | head -c 120)"
ok "stored ciphertext carries the k8s:enc: prefix, and the plain value is absent"

echo
echo "All Kubernetes end-to-end checks passed."
