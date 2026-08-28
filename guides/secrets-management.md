# Secrets Management & Zero-Trust Secrets

Architectures and practical patterns for managing credentials, API tokens, and certificates securely.

---

## 1. Secret Storage Hierarchy

```text
[Enterprise KMS (AWS KMS / Azure KV / GCP KMS)]
                     ↓
[Secret Engine (HashiCorp Vault / Cloud Secret Manager)]
                     ↓
[App Ingestion (Envoy / K8s External Secrets / SOPS)]
                     ↓
[Runtime Memory (Never committed to disk / logs)]
```

---

## 2. Encrypting Repositories with Mozilla SOPS & Age

1. Generate Age keypair:
   ```bash
   age-keygen -o key.txt
   ```
2. Configure `.sops.yaml`:
   ```yaml
   creation_rules:
     - path_regex: .*\.enc\.ya?ml$
       age: age1ql3...
   ```
3. Encrypt and Decrypt:
   ```bash
   sops -e secrets.yaml > secrets.enc.yaml
   sops -d secrets.enc.yaml > secrets.yaml
   ```

---

## 3. Secret Rotation Lifecycle

- **Automated Rotation**: Implement rotating credentials using tools like `secret-rotator` or Vault Dynamic Secrets.
- **Immediate Invalidation**: When a credential leak is detected, revoke first, investigate second.
