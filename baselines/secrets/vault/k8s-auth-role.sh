#!/usr/bin/env bash
# Reference commands for binding the "app-readonly" policy above to a
# Kubernetes ServiceAccount via Vault's Kubernetes auth method. This is a
# REFERENCE, run by hand (or from a bootstrap pipeline) against a real Vault
# cluster with a real Kubernetes API to validate against -- tests/secrets.sh
# does NOT execute this file. See the "gap" note in
# guides/secrets-management.md: `vault write auth/kubernetes/role/...` accepts
# any string for `kubernetes_host`/`kubernetes_ca_cert` without checking
# reachability, so a container-only test would prove nothing beyond "the CLI
# parsed its flags" -- worse than not testing it, because a green check would
# look like a real guarantee.
set -euo pipefail

# 1. Enable the auth method once per cluster (idempotent: errors harmlessly
#    with "path is already in use" if already enabled -- don't `|| true` this
#    in a script that also handles OTHER errors, check the message).
vault auth enable kubernetes

# 2. Point it at the Kubernetes API this Vault should trust tokens from.
#    Vault validates the ServiceAccount token it receives at LOGIN time by
#    calling this API's TokenReview endpoint -- it does not just decode the
#    JWT locally. kubernetes_ca_cert is the cluster's CA, not Vault's own TLS
#    cert; mixing those up is the second most common mistake here.
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 3. The role: which ServiceAccount(s), in which namespace(s), get which
#    policy, for how long. Scope both dimensions -- a role with
#    bound_service_account_names="*" hands the policy to every pod in the
#    namespace, including ones nobody reviewed for it.
vault write auth/kubernetes/role/eso-reader \
  bound_service_account_names="external-secrets" \
  bound_service_account_namespaces="external-secrets" \
  policies="app-readonly" \
  ttl="15m"

# 4. What actually happens at login (this is what ESO's SecretStore does for
#    you -- see baselines/secrets/eso/cluster-secret-store.yaml):
#      vault write auth/kubernetes/login role=eso-reader \
#        jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
#    returns a Vault token scoped to the "app-readonly" policy, good for the
#    ttl above. A short ttl is the point: a leaked token this pod's sidecar
#    logged by accident is worthless in 15 minutes, versus a static Vault
#    token pasted into a Secret that is valid until someone remembers to
#    revoke it.
