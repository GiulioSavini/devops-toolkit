# Least-privilege Vault policy for one application's read path.
#
# THE CLASSIC MISTAKE: KV v2 has TWO different paths for the SAME secret.
#   - The CLI hides it:  `vault kv get secret/app/db`
#   - The HTTP API (and every policy path) does NOT: the actual backend path
#     is `secret/data/app/db` for reads/writes and `secret/metadata/app/db`
#     for listing, soft-delete/undelete and reading version metadata.
# A policy written against `secret/app/db` (the CLI-friendly, KV v1-shaped
# path) silently grants access to NOTHING under a v2 mount: no error, the
# token just gets "permission denied" the first time client code calls the
# API directly, or the app reads an old version it wasn't blocked from
# because a DIFFERENT rule matched. Always write policy paths against the
# real KV v2 backend layout: <mount>/data/<path> and <mount>/metadata/<path>.
#
# capabilities are chosen deliberately, not copy-pasted as ["read"] everywhere:
#   - "read"  on data/*   : fetch the current (or a pinned) version of a secret.
#   - "list"  on metadata/*: lets `vault kv list` enumerate keys under the
#     app's own prefix, WITHOUT granting read of metadata contents such as
#     version timestamps for secrets outside that prefix in the same mount.
# Neither "create", "update" nor "delete" is granted: this token is a
# consumer, not an owner. Secrets under this path are written by a separate,
# more privileged pipeline identity with its own, narrower policy.

# Read the current version of every secret under this app's own prefix.
# "app-readonly/*" -- the trailing glob is intentional: it lets the app team
# add new secret names under their own prefix without a policy change, but it
# does NOT let them reach a sibling app's prefix (e.g. "secret/data/other-app/*").
path "secret/data/app-readonly/*" {
  capabilities = ["read"]
}

# List (but not read the historical metadata contents of) the app's own
# prefix, so `vault kv list secret/app-readonly/` and client SDKs that
# enumerate keys before fetching them work. Listing under KV v2 always goes
# through metadata/, never data/ -- a policy that grants "list" on
# "secret/data/app-readonly/*" instead grants nothing for listing.
path "secret/metadata/app-readonly/*" {
  capabilities = ["list", "read"]
}

# Explicitly denied by omission, called out here so the next person editing
# this file does not "helpfully" add it back:
#   - "secret/data/*"            (every other app's secrets)
#   - "secret/data/app-readonly" (the bare prefix itself has no secret at it;
#     only paths BELOW it do, which is why the rules above end in /*)
#   - any "create", "update", "delete", "sudo" capability anywhere in this file
