# Kubernetes Cluster Hardening (CIS Benchmark)

Hardening guide for Kubernetes control plane, worker nodes, and tenant workloads.

---

## 1. Pod Security Standards (PSS)

Enforce the **Restricted** profile on production namespaces:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

---

## 2. Default Deny NetworkPolicy

Prevent cross-namespace lateral movement by default:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

---

## 3. Control Plane Checklist

- [ ] Enable **etcd encryption at rest** using KMS or Secretbox.
- [ ] Enable Kubernetes **Audit Logging** with alert routing for privilege escalations.
- [ ] Restrict `system:masters` and disable anonymous auth (`--anonymous-auth=false`).
- [ ] RBAC: Audit ServiceAccounts and eliminate wildcard (`*`) permissions.
