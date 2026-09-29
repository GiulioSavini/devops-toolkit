# Kubernetes Hardening

A baseline for a production cluster: Pod Security Admission, workload security
context, NetworkPolicy, RBAC, admission policies in CEL, API server audit, and
encryption at rest. Every setting ships as a file under
[`baselines/kubernetes/`](../baselines/kubernetes/), is schema-validated by
[`tests/kubernetes.sh`](../tests/kubernetes.sh), and — for everything that has
observable behaviour — is proven on a real cluster by
[`tests/kubernetes-e2e.sh`](../tests/kubernetes-e2e.sh).

| | |
|---|---|
| Applies to | Kubernetes 1.30+ for ValidatingAdmissionPolicy (GA in 1.30), 1.25+ for Pod Security Admission. Validated on 1.37 with containerd 2.x |
| Baseline files | [`baselines/kubernetes/`](../baselines/kubernetes/) |
| Validated by | [`tests/kubernetes.sh`](../tests/kubernetes.sh) (schema and config decoding), [`tests/kubernetes-e2e.sh`](../tests/kubernetes-e2e.sh) (live kind cluster, 28 assertions) |
| Lockout risk | **High on the control plane, medium on workloads.** A bad `EncryptionConfiguration` stops the API server from starting; `default-deny` NetworkPolicy breaks DNS for every pod in the namespace; a `failurePolicy: Fail` admission policy blocks all creates if its CEL is wrong |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **A compromised container becoming a compromised cluster.** A pod that can
  run as root, mount the host filesystem, or escalate privileges reaches the
  node, and from the node reaches the kubelet credentials and every other pod
  on it.
- **Lateral movement between workloads.** Without NetworkPolicy, every pod can
  reach every other pod and every cluster service, so one vulnerable frontend
  reaches the database directly.
- **A stolen ServiceAccount token.** Tokens are mounted into pods by default.
  A token bound to a role with `secrets: list` across the cluster is a
  cluster-wide credential dump.
- **A stolen etcd backup.** Without encryption at rest, an etcd snapshot is
  every Secret in the cluster in plain text.
- **Privilege escalation through the API.** `escalate`, `bind`, `impersonate`,
  and the ability to create admission webhooks are all paths to cluster-admin
  that do not look like cluster-admin in an RBAC review.
- **Producing the evidence afterwards.** Who exec'd into which pod, who read
  which Secret, who changed which RBAC binding.

What it is not for:

- **Untrusted multi-tenant workloads on a shared kernel.** PSS `restricted`
  plus seccomp raises the cost of an escape; it does not create a boundary. Use
  separate node pools, or a sandboxed runtime (gVisor, Kata), or separate
  clusters.
- **Node-level hardening.** The kubelet section here is the Kubernetes half;
  the host itself is [Linux hardening](linux-hardening.md).
- **Image provenance.** The admission policy here rejects `:latest`; it does
  not verify signatures. That needs a verifying admission controller — see
  [Docker security](docker-security.md) for the signing side.
- **Anything about the cloud provider's IAM.** A node with an over-permissive
  instance profile is a cluster compromise that no pod spec prevents. See
  [cloud IAM](cloud-iam.md).
- **Secrets management.** Kubernetes Secrets are base64, not encrypted, until
  you configure encryption at rest — and even then they are readable by anyone
  with `get` on them. See [secrets management](secrets-management.md).

## Pod Security Admission

[`baselines/kubernetes/namespace-pss-restricted.yaml`](../baselines/kubernetes/namespace-pss-restricted.yaml)
is the cheapest control in this guide: four labels on a namespace, enforced by
the API server with no controller to install.

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: v1.37
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`restricted` rejects privileged containers, host namespaces, host path mounts,
privilege escalation, running as root, and anything with added capabilities
beyond `NET_BIND_SERVICE`.

**Pin `enforce-version`. Never use `latest`.** With `latest`, a cluster upgrade
that tightens the `restricted` profile starts rejecting pods that were
previously admitted — during the upgrade, with no change to your manifests.
Pinning makes that an explicit, reviewable bump: raise the version, deploy to
staging, see what breaks. The version pinned here is `v1.37`, which is also why
`tests/kubernetes.sh` validates against the 1.37 schema; the two must move
together.

Set `warn` and `audit` to `restricted` on **every** namespace, including the
ones you only enforce `baseline` on. They cost nothing and tell you what would
break before you enforce it.

`tests/kubernetes-e2e.sh` proves this works by first creating a privileged pod
in a namespace **without** the labels — it is admitted — and then attempting
the same pod in the labelled namespace, where it must be rejected. Without that
control, an assertion that "the privileged pod failed" would also pass if the
pod failed for an unrelated reason.

### What PSS does not cover

`restricted` says nothing about resource limits, image tags, automounted
tokens, or `hostPort`. Those need admission policies, which is the next
section.

## Workload security context

[`baselines/kubernetes/hardened-deployment.yaml`](../baselines/kubernetes/hardened-deployment.yaml)
is the pod spec that `restricted` admits. Pod level:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```

Container level:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

| Field | Why |
|---|---|
| `runAsNonRoot: true` | The assertion. Without it, an image whose `USER` is root runs as root — `USER` in a Dockerfile is a default, not a control |
| `runAsUser`/`runAsGroup` | Explicit uid, so the pod does not depend on the image's metadata. 65532 is the distroless `nonroot` uid |
| `seccompProfile: RuntimeDefault` | Applies the container runtime's default syscall filter. `restricted` requires it; without it the container gets the unconfined syscall surface |
| `allowPrivilegeEscalation: false` | Sets `no_new_privs`. A setuid binary in the image cannot raise privileges |
| `readOnlyRootFilesystem: true` | No dropped payloads, no persistence across a restart. Anything the app must write gets an explicit `emptyDir` |
| `capabilities.drop: ["ALL"]` | Empties the bounding set. Add back only `NET_BIND_SERVICE`, and only if the process truly cannot listen above 1024 |
| `automountServiceAccountToken: false` | Set on both the pod and the ServiceAccount. A pod that never calls the API has no reason to carry a cluster credential on its filesystem |
| `resources.requests`/`limits` | Not only scheduling. A pod with no memory limit can evict its neighbours off the node |
| `readinessProbe`/`livenessProbe` | On a distroless image the orchestrator is the only thing that can health-check the container, because there is no shell for a `HEALTHCHECK` |

### Two ordering facts that cost real debugging time

**Apply RBAC before the Deployment.** `hardened-deployment.yaml` references
`serviceAccountName: app-reader`, which is defined in
[`rbac-least-privilege.yaml`](../baselines/kubernetes/rbac-least-privilege.yaml).
Apply the Deployment first and it is accepted, the ReplicaSet is created, and
then nothing happens: the ReplicaSet controller cannot create pods and reports
`error looking up service account production/app-reader`. The Deployment sits at
0 available with a manifest that is completely correct. `kubectl describe
replicaset` is where the answer is; `kubectl describe deployment` does not say
it.

**The manifest is a request, not the state.** `kubectl get pod -o yaml` shows
what you asked for. To see what the runtime applied, read the container's OCI
spec on the node:

```bash
CTR=$(crictl ps --name '^app$' -q | head -1)
crictl inspect "$CTR" | jq '.info.runtimeSpec.process | {uid: .user.uid, noNewPrivileges, caps: (.capabilities.bounding // [] | length)}'
crictl inspect "$CTR" | jq '.info.runtimeSpec.root.readonly, .info.runtimeSpec.linux.seccomp.defaultAction'
```

This is what `tests/kubernetes-e2e.sh` asserts on: uid 65532, `readonly: true`,
`noNewPrivileges: true`, a bounding capability set of length 0, and
`SCMP_ACT_ERRNO` as the seccomp default action. An unhardened pod in the same
cluster is used as the control, and reports 14 bounding capabilities and a
writable root — which is what proves the hardened readings mean something.

One containerd detail worth knowing: when the bounding set is empty, containerd
**omits the key** rather than emitting an empty list. Read it as
`(.capabilities.bounding // [] | length)`; a naive string comparison against
`""` passes for both the empty and the missing case.

## NetworkPolicy

Default-deny, then allow. Two files, and **they must be applied together**.

[`networkpolicy-default-deny.yaml`](../baselines/kubernetes/networkpolicy-default-deny.yaml)
selects every pod in the namespace with `podSelector: {}` and lists both
`Ingress` and `Egress` under `policyTypes` with no rules, which denies both
directions.

[`networkpolicy-allow-dns.yaml`](../baselines/kubernetes/networkpolicy-allow-dns.yaml)
then allows egress to port 53 on UDP and TCP.

The second file exists because of what default-deny actually breaks:
**DNS**. Every pod resolves through CoreDNS, and egress deny includes egress to
CoreDNS. The symptom is not "network blocked" — it is every hostname in the
application failing to resolve, which looks like a CoreDNS outage, a bad
`resolv.conf`, or an upstream DNS problem. `tests/kubernetes-e2e.sh` asserts
this sequence explicitly: before any policy, pod-to-pod and DNS both work;
with default-deny alone, both fail; with the DNS policy added, DNS resolves
again **and pod-to-pod is still blocked**.

The DNS policy here allows port 53 to any destination, which is the portable
form. Tighten it to CoreDNS only once you know your cluster's label:

```yaml
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
        podSelector:
          matchLabels:
            k8s-app: kube-dns
    ports:
      - {protocol: UDP, port: 53}
      - {protocol: TCP, port: 53}
```

Two things to check before relying on any of this:

- **Your CNI must enforce NetworkPolicy.** The API accepts NetworkPolicy
  objects whether or not anything implements them, so a cluster with a
  non-enforcing CNI looks fully policied and denies nothing. Calico, Cilium and
  kind's kindnetd all enforce; flannel alone does not. Test it, do not assume
  it: create a default-deny and confirm a connection actually times out.
- **A blocked connection times out; it is not refused.** `connection refused`
  means the packet reached the destination and something declined it — the
  policy allowed it through. Only a timeout proves the drop. Assertions on
  network behaviour must distinguish the two, and must not treat *empty output*
  as success: a check that greps for a string in the output of a command that
  produced nothing at all passes for the wrong reason.

Egress policy also needs a decision about the cluster's own API server: pods
that use the Kubernetes API need egress to the API server endpoint, which is
usually outside the pod CIDR and therefore not matched by any
`podSelector`. Use an explicit `ipBlock` for the control plane address.

## RBAC

[`rbac-least-privilege.yaml`](../baselines/kubernetes/rbac-least-privilege.yaml)
is small on purpose. A dedicated ServiceAccount with
`automountServiceAccountToken: false`, a Role that can `get`/`list`/`watch`
ConfigMaps, and a Role scoped to **one named Secret**:

```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["app-db-credentials"]
    verbs: ["get"]
```

`resourceNames` is the difference between "this pod can read its own database
password" and "this pod can read every credential in the namespace". Note that
`resourceNames` cannot restrict `list` or `watch` — those verbs operate on the
collection, so granting either grants access to every object of that type in
the scope. If a workload needs `list` on Secrets, that is the finding.

Rules worth applying to every cluster:

- **No wildcards.** `verbs: ["*"]`, `resources: ["*"]` or `apiGroups: ["*"]` in
  anything except a deliberately-scoped cluster-admin role is a
  finding. Wildcards also silently grow: a new API group in the next release is
  immediately included.
- **Prefer Role over ClusterRole.** A ClusterRoleBinding to a namespaced
  workload's ServiceAccount is the most common accidental cluster-wide grant.
- **Treat `escalate`, `bind`, `impersonate` as cluster-admin.** `escalate`
  lets a subject create roles more powerful than their own; `bind` lets them
  bind an existing powerful role; `impersonate` lets them act as anyone. None
  of them looks dangerous in a rule list.
- **`create` on `pods` in a namespace with a privileged ServiceAccount is a
  privilege escalation**, because the new pod can mount that token. So is
  `create` on `pods/exec` against an existing privileged pod.
- **Audit what actually exists.** `kubectl auth can-i --list
  --as=system:serviceaccount:production:app-reader` answers for one subject;
  `kubectl get clusterrolebindings -o wide` shows who is bound to
  `cluster-admin`, which is usually more people than anyone expects.

## Admission policies in CEL

Two policies, using ValidatingAdmissionPolicy — in-tree CEL evaluated by the
API server, so there is no webhook to run, no certificate to rotate, and no
webhook outage that takes admission with it.

[`vap-disallow-latest-tag.yaml`](../baselines/kubernetes/vap-disallow-latest-tag.yaml)
requires an explicit non-`latest` tag or an `@sha256:` digest on every
container, init container **and** ephemeral container. Ephemeral containers
matter: `kubectl debug` injects one, and it is a real code-execution path that
a policy covering only `spec.containers` ignores entirely.

The CEL is more careful than it first looks:

```cel
c.image.contains('@sha256:') ||
(c.image.substring(c.image.lastIndexOf('/') + 1).contains(':') &&
 !c.image.endsWith(':latest'))
```

The naive version of this check is `c.image.contains(':')`, and it is wrong for
`myregistry:5000/app` — the colon belongs to the registry **port**, there is no
tag at all, and the image resolves to `:latest`. Taking the substring after the
last `/` looks at the final path component only, where a colon can only be a
tag separator. `tests/kubernetes-e2e.sh` asserts exactly this case, along with
the accepted (`:v1`) and rejected (`:latest`) forms.

[`vap-require-nonroot.yaml`](../baselines/kubernetes/vap-require-nonroot.yaml)
requires `runAsNonRoot: true` at pod level, or on every container. It is bound
to namespaces labelled `enforce: baseline`, because `restricted` already
requires it — this closes the gap in namespaces that cannot yet run
`restricted`.

Both bindings target namespaces by label rather than by name:

```yaml
matchResources:
  namespaceSelector:
    matchLabels:
      pod-security.kubernetes.io/enforce: restricted
```

A new namespace is covered the moment it gets its PSS label, with no policy
change. A policy bound to a name list is a policy that silently misses the next
namespace someone creates.

`failurePolicy: Fail` on both: if the CEL cannot be evaluated, the request is
rejected. `Ignore` means a broken policy admits everything, which is worse than
an outage because it is invisible. Test the CEL against real manifests before
binding with `Deny` — the binding's `validationActions` can be set to `[Warn,
Audit]` first, which reports without blocking.

## API server audit

[`audit-policy.yaml`](../baselines/kubernetes/audit-policy.yaml), referenced
from the API server as:

```text
--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
```

Rules are evaluated **in order, first match wins**, which is the whole design:
the specific rules come first, the catch-all comes last.

| Rule | Level | Reason |
|---|---|---|
| `secrets` | `Metadata` | Who read which Secret, when — **never** `Request` or `RequestResponse`, which writes the Secret's contents into the audit log in plain text and turns your log pipeline into a secret store |
| `serviceaccounts/token` | `Request` | Token requests, including the audience, which is how you spot a token minted for the wrong service |
| `impersonate`, `escalate`, `bind` | `RequestResponse` | The three verbs that are privilege escalation. Full bodies |
| `pods/exec`, `pods/attach`, `pods/portforward`, `nodes/proxy` | `RequestResponse` | Interactive access to a running workload. This is the record that answers "who ran what in production" |
| admission configurations | `RequestResponse` | A mutating webhook is arbitrary code in the admission path; its creation must be fully logged |
| `certificatesigningrequests` (+`/approval`) | `RequestResponse` | A CSR approved for the wrong CN is a new cluster identity |
| RBAC objects | `RequestResponse` | Every permission change, with the before and after |
| `events` | `None` | Enormous volume, no forensic value |
| `system:kube-proxy` watches | `None` | Constant, expected, high volume |
| health and discovery endpoints | `None` | Same |
| catch-all | `Metadata` | Everything else is still recorded at metadata level. A policy whose last rule is `None` silently drops whatever nobody thought of |

`omitStages: ["RequestReceived"]` halves the log volume without losing
anything: the `ResponseComplete` event for the same request carries the outcome.

The audit log is on the control-plane node's local filesystem, which means an
attacker with node access can edit it. Ship it off the host in real time —
that is the only version that is evidence.

`tests/kubernetes-e2e.sh` reads the actual audit log from the running API
server and asserts both directions: the expected resources appear, **and** no
Secret was logged at `Request` level or above.

## Encryption at rest

Two variants ship, because the right one depends on whether you have a KMS.

[`encryption-config.yaml`](../baselines/kubernetes/encryption-config.yaml) uses
a KMS v2 provider: the key material lives in an external KMS and the API server
talks to a plugin over a Unix socket. This is the correct answer for a
production cluster — the key is never on the control-plane filesystem.

[`encryption-config-secretbox.yaml`](../baselines/kubernetes/encryption-config-secretbox.yaml)
uses a local secretbox key, for self-managed control planes, air-gapped
environments, and anywhere keeping a KMS plugin socket healthy on every API
server is not worth the operational cost.

**A KMS provider whose socket does not exist stops the cluster from
starting.** kubeadm fails with `got unexpected nil transformer` — which names
neither KMS nor the socket. This is why the end-to-end test runs the secretbox
variant: the KMS variant cannot be validated without the plugin it names, and
shipping it as the only option would mean shipping a file nobody had ever
booted.

Provider order is the whole mechanism: the **first** provider encrypts new
writes, and every provider is tried in order when decrypting.

```yaml
providers:
  - secretbox:
      keys:
        - name: key1
          secret: <32 bytes, base64>
  - identity: {}          # MUST be last
```

`identity` means "store in plain text". As the **first** provider it writes
every new object unencrypted while still decrypting the old ones — so nothing
looks broken, and the cluster is not encrypted. It belongs last, and only until
every pre-existing object has been rewritten.

Rotation, in that order and never in one change:

```bash
# 1. Prepend the new key, keep the old one. Reload (or restart the API server).
# 2. Rewrite every object so it is re-encrypted with the new key:
kubectl get secrets -A -o json | kubectl replace -f -
# 3. In a LATER change, remove the old key.
```

Generate real keys — the one in the repository is a placeholder in a public
file:

```bash
head -c 32 /dev/urandom | base64
```

Treat the file as a secret: root-owned, mode 0600, outside the static manifests
directory, excluded from any backup that is not itself encrypted, never in
version control.

Verify by reading etcd directly, because the API server decrypts transparently
and `kubectl get secret` looks identical either way:

```bash
kubectl -n production create secret generic canary --from-literal=k=CANARYVALUE
ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/production/canary | hexdump -C | head
# expect the k8s:enc:secretbox: prefix, and NOT the string CANARYVALUE
```

`tests/kubernetes-e2e.sh` does this on the live cluster, asserting both that
the plaintext is absent and that an encryption prefix is present — either
assertion alone can pass for the wrong reason.

## Kubelet

[`kubelet-config.yaml`](../baselines/kubernetes/kubelet-config.yaml) is the
node-side half. `tests/kubernetes.sh` feeds this file to the **real kubelet
binary** from the pinned node image and requires that it decode without falling
back to lenient decoding, which is what happens when a key does not exist in
the `KubeletConfiguration` type that kubelet was compiled with — the failure
mode a schema check cannot catch.

| Setting | Why |
|---|---|
| `authentication.anonymous.enabled: false` | The kubelet API unauthenticated is node compromise. This is the single most important line in the file |
| `authorization.mode: Webhook` | Every kubelet API request is authorized by the API server, instead of `AlwaysAllow` |
| `readOnlyPort: 0` | Closes port 10255, which serves pod specs and environment variables with no authentication at all |
| `protectKernelDefaults: true` | The kubelet refuses to start rather than silently overwriting host sysctls. Expect this to surface a real conflict with the sysctl baseline in [Linux hardening](linux-hardening.md) the first time |
| `seccompDefault: true` | `RuntimeDefault` seccomp for every pod that does not specify a profile, which is the pods you did not write |
| `rotateCertificates` + `serverTLSBootstrap` | Client and serving certificates rotate automatically. `serverTLSBootstrap` needs a CSR approver, or the CSRs sit pending and the kubelet serves a self-signed certificate |
| `podPidsLimit: 4096` | A fork bomb in one pod stops being a node-wide outage |
| `streamingConnectionIdleTimeout: 5m` | Abandoned `exec`/`port-forward` sessions do not stay open indefinitely |
| `tlsMinVersion: VersionTLS12` | Floor. Raise to TLS 1.3 if every client supports it |

## Rollout

1. **Label namespaces `warn`/`audit` first, enforce nothing.** Deploy, and read
   the warnings. This tells you what `restricted` would reject with no risk at
   all.
2. **Fix the workloads**: security context, resource limits, explicit
   `emptyDir` for every path the app writes, `automountServiceAccountToken:
   false` where the API is not used.
3. **Set `enforce: restricted`** on the namespace, with `enforce-version`
   pinned. Existing pods keep running — PSS is admission-time only, so nothing
   breaks until the next rollout, which also means the change is not actually
   proven until you redeploy.
4. **RBAC before workloads**, always — see the ordering note above.
5. **NetworkPolicy: apply default-deny and allow-dns in the same change.**
   Then add the specific allows. Verify a blocked connection *times out*.
6. **Admission policies with `validationActions: [Warn, Audit]` first.** Read
   the warnings, then switch to `[Deny]`.
7. **Control plane last, one node at a time.** Audit policy and the encryption
   config are API server flags: a mistake in either is an API server that does
   not start. Keep a copy of the working static pod manifest outside
   `/etc/kubernetes/manifests`, and with encryption, keep `identity` last until
   every object has been rewritten.

## Verification

```bash
# PSS: the labels that are actually on the namespaces
kubectl get ns -L pod-security.kubernetes.io/enforce,pod-security.kubernetes.io/enforce-version
# any namespace with an empty enforce column is unprotected

# The runtime's view of a running container, not the manifest's
crictl inspect "$(crictl ps --name '^app$' -q | head -1)" \
  | jq '.info.runtimeSpec.process.user.uid, .info.runtimeSpec.root.readonly'

# NetworkPolicy really enforces: this must TIME OUT, not be refused
kubectl -n production run probe --rm -it --restart=Never \
  --image=registry.k8s.io/e2e-test-images/agnhost:2.47 -- \
  /bin/sh -c 'timeout 5 nc -zv hardened-app 8080; echo rc=$?'

# RBAC: what one ServiceAccount can actually do
kubectl auth can-i --list --as=system:serviceaccount:production:app-reader -n production
# and who holds cluster-admin
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name, (.subjects//[])[].name'

# Admission policies are bound and active
kubectl get validatingadmissionpolicy,validatingadmissionpolicybinding

# Audit log is being written, and no Secret body is in it
sudo grep -c '"kind":"Event"' /var/log/kubernetes/audit.log
sudo jq -r 'select(.objectRef.resource=="secrets") | .level' /var/log/kubernetes/audit.log | sort -u
# expect: Metadata, and nothing else

# Encryption at rest: read etcd, not the API
# (see the Encryption at rest section for the full etcdctl command)

# kubelet: the unauthenticated read-only port must be closed
curl -sS --max-time 3 http://<node>:10255/pods; echo "rc=$?"
# expect a connection failure, not a pod list
```

## Rollback

| Change | Undo |
|---|---|
| PSS `enforce` label | `kubectl label ns production pod-security.kubernetes.io/enforce-` — takes effect immediately, existing pods were never affected |
| Security context | Revert the manifest and redeploy. No cluster state to clean up |
| NetworkPolicy | `kubectl -n production delete networkpolicy default-deny-all`. Delete default-deny **before** allow-dns, never the other way round |
| Admission policy | Delete the **binding**, not the policy: an unbound policy evaluates nothing, and keeping it makes re-enabling one command |
| RBAC | Delete the RoleBinding. Deleting the Role leaves a dangling `roleRef` that fails at bind time |
| Audit policy | Restore the previous file and restart the API server. A syntactically invalid policy means the API server will not start |
| Encryption config | Keep `identity` in the provider list and it can be removed safely; remove the key that encrypted existing objects and those objects are **permanently unreadable** |
| Kubelet config | Restore the file, `systemctl restart kubelet`. `protectKernelDefaults: true` is the one that most often refuses to start |

## Common failure modes

- **`default-deny` applied without the DNS policy.** Every hostname stops
  resolving; it looks like a CoreDNS outage.
- **A CNI that does not enforce NetworkPolicy.** Every policy is accepted, none
  applies, and the cluster looks fully segmented.
- **`enforce-version: latest`**, and a cluster upgrade starts rejecting pods
  that were admitted the day before.
- **The Deployment applied before its ServiceAccount.** 0 available replicas,
  and the reason is only in `kubectl describe replicaset`.
- **A KMS `EncryptionConfiguration` with no plugin socket**: the API server
  does not start, and the error is `got unexpected nil transformer`.
- **`identity` first in the provider list.** New Secrets are written in plain
  text and nothing appears broken.
- **A key removed before every object was rewritten.** Those objects are
  unreadable, permanently.
- **`level: RequestResponse` on `secrets`**, putting every Secret's contents
  into the audit log and into whatever ships it.
- **A last audit rule of `level: None`**, silently dropping everything nobody
  enumerated.
- **`resourceNames` used with `list`**, which does nothing: the verb operates
  on the collection.
- **A `ClusterRoleBinding` where a `RoleBinding` was meant** — namespace-scoped
  intent, cluster-scoped grant.
- **`failurePolicy: Ignore`** on an admission policy, so a CEL error admits
  everything.
- **`readOnlyRootFilesystem: true` with no `emptyDir`** for the app's cache or
  temp directory, failing on a code path that only runs under load.
- **Distroless plus `kubectl exec`**: there is no shell, so the usual debugging
  reflex fails. Use `kubectl debug` with an ephemeral container — which the
  image policy above deliberately covers.
- **Memory limit below real peak usage**, so the container is OOM-killed and
  reported as a crash loop.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Pod Security Admission | CIS Kubernetes Benchmark | AC-3, CM-7, SC-2 | A.8.2, A.8.19 | (i) |
| Workload security context | same | AC-6, CM-7, SC-2 | A.8.2, A.8.19 | (i) |
| NetworkPolicy | same | AC-4, SC-7 | A.8.20, A.8.22 | (e) |
| RBAC | same | AC-2, AC-3, AC-6 | A.5.15, A.5.18, A.8.2 | (i) |
| Admission policies | same | CM-2, CM-6, SI-7 | A.8.9, A.8.30 | (d), (e) |
| API server audit | same | AU-2, AU-3, AU-9, AU-12 | A.8.15, A.8.16 | (b) |
| Encryption at rest | same | SC-12, SC-13, SC-28 | A.8.24, A.5.33 | (h) |
| Kubelet configuration | same | AC-17, CM-6, IA-2, SC-8 | A.8.5, A.8.9, A.8.24 | (e), (h) |
| Resource limits | same | SC-5, SC-6 | A.8.6 | (c) |

## References

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
  and
  [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
  and the [CEL language reference](https://kubernetes.io/docs/reference/using-api/cel/)
- [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
  — including the list of CNIs that implement it
- [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
  especially the privilege escalation prevention section
- [Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Encrypting Secret data at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
  and [KMS v2](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
- [Kubelet configuration reference](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) —
  the authoritative section numbers for your audited version
- [Docker security](docker-security.md) for the image these manifests run, and
  [Linux hardening](linux-hardening.md) for the nodes underneath
