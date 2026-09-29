# Fixture: no secrets. tests/secrets.sh asserts gitleaks reports zero leaks
# for this file, so the "clean scan passes" path is exercised too, not just
# the "dirty scan fails" path.
AWS_REGION = "eu-south-1"
SERVICE_NAME = "devops-toolkit-example"
# Placeholder allowlisted in .gitleaks.toml — proves the allowlist entry works.
INTERNAL_SERVICE_TOKEN = "svc_00000000000000000000000000000000"
