# Fixture: deliberately contains a fake secret so tests/secrets.sh can prove
# gitleaks + .gitleaks.toml actually detect a leak. Not a real credential.
#
# Note: a canonical "AKIA...EXAMPLE" AWS key is NOT used here — gitleaks'
# built-in ruleset allowlists any match ending in "EXAMPLE" precisely
# because AWS's own docs use that string, so it would not prove detection.
INTERNAL_SERVICE_TOKEN = "svc_deadbeefdeadbeefdeadbeefdeadbeef"
