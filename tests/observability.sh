#!/usr/bin/env bash
# Validates baselines/observability/. Run from the repository root:
#
#   bash tests/observability.sh
#
# Host requirements: bash and docker. Every tool runs from a digest-pinned
# image, so a local run and a CI run resolve the same versions.
#
# What this proves:
#   1. `promtool check rules` on slo-rules.yml and slo-alerts.yml — the
#      PromQL parses and the rule graph has no dangling references.
#   2. `promtool test rules` on slo-alerts_test.yml — synthetic series fed
#      into the real recording + alerting rules, asserting each burn-rate
#      alert FIRES when it should and stays quiet when it should not,
#      including a case that isolates the fast alert's 1h/5m branch from its
#      6h/30m branch by diluting a real incident's long window rather than
#      raising a single constant ratio (which both branches would clear
#      identically and would prove nothing about which threshold is which).
#      This is the check that proves the burn-rate arithmetic itself, not
#      just its syntax.
#   3. `amtool check-config` on alertmanager.yml, THEN a live Alertmanager
#      container is started against it and two real alerts are posted
#      through `amtool alert add`: a page-severity alert and a
#      ticket-severity alert for the same job. The v2 API response is read
#      back to prove the ticket alert is actually reported `suppressed` with
#      `inhibitedBy` pointing at the page alert's fingerprint — not just that
#      the inhibit_rules block parses. A second pair (different job, no
#      matching page alert) proves the `equal: [job, slo]` scoping: it must
#      stay `active`.
#   4. `otelcol validate --config` on otel-collector/config.yaml, plus one
#      documented, EMPIRICALLY VERIFIED gap: this collector build (0.116.1)
#      rejects an unknown processor key (case 4b below), but ACCEPTS a
#      config where a processor is defined and never referenced from
#      `service.pipelines` — the "silently dead config" trap the file's own
#      comments warn about. That second case is asserted the way it actually
#      behaves (exit 0), not the way a tidier test would prefer, and the
#      same gap is written up in guides/observability-logging.md rather than
#      silently dropped.
#
# What this does NOT do:
#   - It does not run the OpenTelemetry Collector, only validates its config.
#     Proving memory_limiter actually sheds load under a real trace/metric
#     flood needs a running collector and a load generator, which is out of
#     scope for a config-validation test.
#   - It does not exercise Alertmanager's Slack/webhook delivery — the
#     receivers reference `_file` secrets that do not exist on this host by
#     design (see the comment in alertmanager.yml), so no notification is
#     ever actually sent. What IS proven is routing and inhibition, which
#     depend only on labels and the config, not on the receiver's transport.
#   - It does not stand up a Prometheus server to scrape real
#     `http_requests_total` metrics; check 2 above is what stands in for
#     that, using promtool's own unit-test evaluator.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -d baselines/observability ]] || { echo "run from the repository root" >&2; exit 2; }

# Image digests were current on 2026-09-29.
PROMETHEUS_IMG="prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"                       # v3.5.0 (ships promtool)
ALERTMANAGER_IMG="prom/alertmanager@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba"                    # v0.28.1 (ships amtool, and is the server itself)
OTELCOL_IMG="otel/opentelemetry-collector-contrib@sha256:d0ebf65280da2e1b1491d1b93648281afd353d4b9ea19160090303cec9a233bd"       # 0.116.1
CURL_IMG="curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"                              # 8.11.1
JQ_IMG="ghcr.io/jqlang/jq@sha256:4f34c6d23f4b1372ac789752cc955dc67c2ae177eb1b5860b75cdc5091ce6f91" # ghcr.io/jqlang/jq:1.8.1
ALPINE_IMG="alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"                                     # 3.22

WORK="$(mktemp -d)"
NET_NAME="obs-test-$$"
AM_CONTAINER="obs-am-test-$$"
cleanup() {
  # amtool/promtool/otelcol-contrib all run as a non-root user in their
  # images (verified: prom/prometheus and prom/alertmanager run as `nobody`,
  # otelcol-contrib as uid 10001), so this bind mount is never actually
  # written to as root. The chown runs anyway: it is what makes this script
  # safe to copy into a baseline whose tools DO write as root, and it costs
  # one extra container.
  docker rm -f "$AM_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NET_NAME" >/dev/null 2>&1 || true
  docker run --rm -v "$WORK:/w" "$ALPINE_IMG" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

# Writable copy of the tree: every check runs against this, so a broken-copy
# control can never modify the repository.
OBS="$WORK/obs"
mkdir -p "$OBS"
cp -a baselines/observability/. "$OBS/"
# otelcol-contrib's image runs as uid 10001, not the host user that owns this
# mktemp -d (mode 700 by default). Without this, the very first otelcol
# validate call fails on "permission denied" before it ever looks at the
# config's contents.
chmod -R o+rX "$WORK"
PROM_DIR="$OBS/prometheus"
AM_DIR="$OBS/alertmanager"
OTEL_DIR="$OBS/otel-collector"

promtool() {
  docker run --rm -v "$WORK:/w" -w "$1" --entrypoint promtool "$PROMETHEUS_IMG" "${@:2}"
}
amtool() {
  docker run --rm -v "$WORK:/w" -w "$1" --entrypoint amtool "$ALERTMANAGER_IMG" "${@:2}"
}
otelcol_validate() {
  docker run --rm -v "$WORK:/w:ro" --entrypoint /otelcol-contrib "$OTELCOL_IMG" validate --config "file:/w/$1"
}

### 1. promtool check rules -------------------------------------------------
# --lint-fatal is not optional: by default `check rules` prints "duplicate
# rule(s) found" as a lint warning and still exits 0. Without this flag every
# control in this section would pass its `grep` on the printed text and then
# fail the "must be rejected" assertion, because the command never actually
# failed.
step "promtool check rules: slo-rules.yml, slo-alerts.yml"
promtool "/w/obs/prometheus" check rules --lint-fatal slo-rules.yml slo-alerts.yml \
  >"$WORK/check-rules.log" 2>&1 || fail "check rules failed on the checked-in files:\n$(cat "$WORK/check-rules.log")"
pass "both rule files parse and have no dangling references"

step "control: check rules must reject a duplicate rule name"
# Same record name AND same (empty) label set as job:slo_errors_per_request:
# ratio_rate5m in slo_error_ratios, appended into a different group. A
# different label set is not a duplicate to promtool (it is a legitimately
# different series identity) — it has to be the exact same identity to
# trigger the lint error, which is what actually happened the first time
# this test was written: a control that added a `job:` label passed
# silently and proved nothing.
cp "$PROM_DIR/slo-rules.yml" "$WORK/slo-rules.yml.good"
cat >> "$PROM_DIR/slo-rules.yml" <<'EOF'
      - record: job:slo_errors_per_request:ratio_rate5m
        expr: vector(1)
EOF
if promtool "/w/obs/prometheus" check rules --lint-fatal slo-rules.yml slo-alerts.yml >"$WORK/check-dup.log" 2>&1; then
  fail "promtool accepted a duplicate recording-rule identity — the check above proves nothing"
fi
grep -qi "duplicate rule" "$WORK/check-dup.log" \
  || fail "check rules failed for an unexpected reason:\n$(cat "$WORK/check-dup.log")"
cp "$WORK/slo-rules.yml.good" "$PROM_DIR/slo-rules.yml"
pass "check rules rejects a duplicate rule identity"

step "control: check rules must reject a broken PromQL expression"
cp "$PROM_DIR/slo-alerts.yml" "$WORK/slo-alerts.yml.good"
sed -i 's/expr: up == 0/expr: up === 0/' "$PROM_DIR/slo-alerts.yml"
if promtool "/w/obs/prometheus" check rules --lint-fatal slo-rules.yml slo-alerts.yml >"$WORK/check-badexpr.log" 2>&1; then
  fail "promtool accepted a malformed PromQL expression — the check above proves nothing"
fi
grep -qi "parse error" "$WORK/check-badexpr.log" \
  || fail "check rules failed for an unexpected reason:\n$(cat "$WORK/check-badexpr.log")"
cp "$WORK/slo-alerts.yml.good" "$PROM_DIR/slo-alerts.yml"
pass "check rules rejects a broken PromQL expression"

### 2. promtool test rules — the important one ------------------------------
step "promtool test rules: slo-alerts_test.yml"
promtool "/w/obs/prometheus" test rules slo-alerts_test.yml >"$WORK/test-rules.log" 2>&1 \
  || fail "the burn-rate alert unit tests failed:\n$(cat "$WORK/test-rules.log")"
grep -q "SUCCESS" "$WORK/test-rules.log" \
  || fail "promtool test rules exited 0 but did not print SUCCESS — investigate:\n$(cat "$WORK/test-rules.log")"
pass "every burn-rate fire/no-fire case in slo-alerts_test.yml holds, including the branch-isolation case"

step "control: test rules must reject a corrupted burn-rate multiplier"
# Raising 14.4 to 144 breaks exactly the branch the dilution test case
# isolates (see the header comment in slo-alerts_test.yml): with the fast
# branch's own threshold made unreachable and the slow branch's long window
# diluted below its bar by design, the alert stops firing for an incident
# that must page. If this control ever passes, the unit test file has
# stopped actually pinning that constant.
cp "$PROM_DIR/slo-alerts.yml" "$WORK/slo-alerts.yml.good2"
sed -i 's/14\.4 \* slo:error_budget_ratio:target/144 * slo:error_budget_ratio:target/g' "$PROM_DIR/slo-alerts.yml"
if promtool "/w/obs/prometheus" test rules slo-alerts_test.yml >"$WORK/test-rules-broken.log" 2>&1; then
  fail "promtool test rules passed with the 14.4 burn-rate constant corrupted to 144 — the unit tests prove nothing about that threshold"
fi
grep -q "FAILED" "$WORK/test-rules-broken.log" \
  || fail "test rules failed for an unexpected reason:\n$(cat "$WORK/test-rules-broken.log")"
cp "$WORK/slo-alerts.yml.good2" "$PROM_DIR/slo-alerts.yml"
pass "test rules rejects a corrupted burn-rate constant (the dilution case catches it)"

### 3. amtool check-config, then a live routing + inhibition proof ----------
step "amtool check-config: alertmanager.yml"
amtool "/w/obs/alertmanager" check-config alertmanager.yml >"$WORK/am-check.log" 2>&1 \
  || fail "amtool rejected the checked-in alertmanager.yml:\n$(cat "$WORK/am-check.log")"
grep -q "SUCCESS" "$WORK/am-check.log" \
  || fail "amtool check-config did not report SUCCESS:\n$(cat "$WORK/am-check.log")"
pass "alertmanager.yml parses, with its route tree, inhibit rule and 3 receivers"

step "control: check-config must reject a route to an unknown receiver"
cp "$AM_DIR/alertmanager.yml" "$WORK/alertmanager.yml.good"
sed -i 's/receiver: ticket-queue/receiver: does-not-exist/' "$AM_DIR/alertmanager.yml"
if amtool "/w/obs/alertmanager" check-config alertmanager.yml >"$WORK/am-badreceiver.log" 2>&1; then
  fail "amtool accepted a route pointing at an undefined receiver — the check above proves nothing"
fi
grep -qi "undefined receiver" "$WORK/am-badreceiver.log" \
  || fail "check-config failed for an unexpected reason:\n$(cat "$WORK/am-badreceiver.log")"
cp "$WORK/alertmanager.yml.good" "$AM_DIR/alertmanager.yml"
pass "check-config rejects a route to an unknown receiver"

step "control: check-config must reject a malformed matcher"
# `severity = ` (trailing space, no value) is NOT a good control: Alertmanager
# falls back to a legacy matcher parser that silently accepts it as
# severity="" and check-config still succeeds — the first version of this
# test used exactly that and passed while proving nothing. `~~` is not a
# matcher operator in either parser, and it fails with "bad matcher format"
# rather than being reinterpreted into something valid.
sed -i '0,/severity = "page"/{s/severity = "page"/severity ~~ "page"/}' "$AM_DIR/alertmanager.yml"
grep -q 'severity ~~ "page"' "$AM_DIR/alertmanager.yml" \
  || fail "the malformed-matcher control did not modify alertmanager.yml — update this test"
if amtool "/w/obs/alertmanager" check-config alertmanager.yml >"$WORK/am-badmatcher.log" 2>&1; then
  fail "amtool accepted a malformed matcher — the check above proves nothing"
fi
grep -qi "bad matcher format" "$WORK/am-badmatcher.log" \
  || fail "check-config failed for an unexpected reason:\n$(cat "$WORK/am-badmatcher.log")"
cp "$WORK/alertmanager.yml.good" "$AM_DIR/alertmanager.yml"
pass "check-config rejects a malformed matcher"

step "amtool config routes test: label sets resolve to the right receiver"
resolved="$(amtool "/w/obs/alertmanager" config routes test --config.file=alertmanager.yml \
  severity=page job=checkout slo=availability)"
[[ "$resolved" == "page-slack-critical" ]] \
  || fail "a page-severity checkout alert resolved to '$resolved', not page-slack-critical"
resolved="$(amtool "/w/obs/alertmanager" config routes test --config.file=alertmanager.yml \
  severity=ticket job=search slo=availability)"
[[ "$resolved" == "ticket-queue" ]] \
  || fail "a ticket-severity search alert resolved to '$resolved', not ticket-queue"
resolved="$(amtool "/w/obs/alertmanager" config routes test --config.file=alertmanager.yml \
  alertname=SomethingWithNoSeverityLabel)"
[[ "$resolved" == "default-fallback" ]] \
  || fail "an alert matching neither child route resolved to '$resolved', not default-fallback"
pass "the routing tree sends page to page-slack-critical, ticket to ticket-queue, and everything else to the fallback"

step "live proof: a firing critical actually inhibits the matching warning"
# amtool config routes test only resolves the route tree against a config
# file; it cannot evaluate inhibit_rules, which are stateful (they compare
# two ALERTS, not a config against a label set). Proving inhibition needs a
# running Alertmanager and two real alerts posted to it.
docker network create "$NET_NAME" >/dev/null
docker run -d --name "$AM_CONTAINER" --network "$NET_NAME" \
  -v "$AM_DIR:/etc/alertmanager:ro" \
  "$ALERTMANAGER_IMG" --config.file=/etc/alertmanager/alertmanager.yml >/dev/null

# Wait for the API to answer rather than sleeping a fixed guess.
for _ in $(seq 1 30); do
  if docker run --rm --network "$NET_NAME" "$CURL_IMG" -sf "http://$AM_CONTAINER:9093/-/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker run --rm --network "$NET_NAME" "$CURL_IMG" -sf "http://$AM_CONTAINER:9093/-/ready" >/dev/null 2>&1 \
  || fail "Alertmanager did not become ready"

docker run --rm --network "$NET_NAME" --entrypoint amtool "$ALERTMANAGER_IMG" \
  --alertmanager.url="http://$AM_CONTAINER:9093" alert add \
  alertname=ErrorBudgetBurnFast severity=page job=checkout slo=availability >/dev/null 2>&1
docker run --rm --network "$NET_NAME" --entrypoint amtool "$ALERTMANAGER_IMG" \
  --alertmanager.url="http://$AM_CONTAINER:9093" alert add \
  alertname=ErrorBudgetBurnSlow severity=ticket job=checkout slo=availability >/dev/null 2>&1
# Same-severity ticket alert for a DIFFERENT job, with no matching page alert
# posted for it: the negative control for the `equal: [job, slo]` scoping.
docker run --rm --network "$NET_NAME" --entrypoint amtool "$ALERTMANAGER_IMG" \
  --alertmanager.url="http://$AM_CONTAINER:9093" alert add \
  alertname=ErrorBudgetBurnSlow severity=ticket job=billing slo=availability >/dev/null 2>&1
sleep 1

alerts_json="$WORK/am-alerts.json"
docker run --rm --network "$NET_NAME" "$CURL_IMG" -sf "http://$AM_CONTAINER:9093/api/v2/alerts" >"$alerts_json"

# jq, not host python, so the only host requirements stay bash and docker.
jq() {
  docker run --rm -i "$JQ_IMG" "$@"
}

checkout_ticket_state="$(jq -r \
  '.[] | select(.labels.alertname=="ErrorBudgetBurnSlow" and .labels.job=="checkout") | .status.state' \
  <"$alerts_json")"
[[ "$checkout_ticket_state" == "suppressed" ]] \
  || fail "checkout's ticket alert is '$checkout_ticket_state', expected suppressed (inhibited by the page alert for the same job)"

checkout_inhibited_by_page="$(jq -r '
  (map(select(.labels.alertname=="ErrorBudgetBurnFast" and .labels.job=="checkout")) | .[0].fingerprint) as $page_fp
  | (map(select(.labels.alertname=="ErrorBudgetBurnSlow" and .labels.job=="checkout")) | .[0].status.inhibitedBy) as $inhibited_by
  | if ($inhibited_by | index($page_fp)) != null then "yes" else "no" end
' <"$alerts_json")"
[[ "$checkout_inhibited_by_page" == "yes" ]] \
  || fail "checkout's ticket alert is suppressed but not by the checkout page alert's fingerprint"
pass "a firing page alert for checkout suppresses the matching ticket alert, via inhibitedBy"

billing_ticket_state="$(jq -r \
  '.[] | select(.labels.alertname=="ErrorBudgetBurnSlow" and .labels.job=="billing") | .status.state' \
  <"$alerts_json")"
[[ "$billing_ticket_state" == "active" ]] \
  || fail "billing's ticket alert (no matching page alert for that job) is '$billing_ticket_state', expected active — the equal:[job,slo] scoping is leaking across jobs"
pass "a ticket alert for a job with no matching page alert is NOT inhibited (equal:[job,slo] is scoped correctly)"

docker rm -f "$AM_CONTAINER" >/dev/null 2>&1
docker network rm "$NET_NAME" >/dev/null 2>&1

### 4. otelcol validate, and the documented dead-config gap -----------------
step "otelcol validate --config: otel-collector/config.yaml"
otelcol_validate "obs/otel-collector/config.yaml" >"$WORK/otel-validate.log" 2>&1 \
  || fail "otelcol validate rejected the checked-in config:\n$(cat "$WORK/otel-validate.log")"
pass "the collector config is accepted"

step "control: otelcol validate must reject an unknown processor key"
cp "$OTEL_DIR/config.yaml" "$WORK/config.yaml.good"
sed -i 's/limit_mib: 512/limit_mib: 512\n    bogus_unknown_key: true/' "$OTEL_DIR/config.yaml"
if otelcol_validate "obs/otel-collector/config.yaml" >"$WORK/otel-badkey.log" 2>&1; then
  cp "$WORK/config.yaml.good" "$OTEL_DIR/config.yaml"
  fail "otelcol validate accepted an unknown processor key — the check above proves nothing"
fi
grep -q "invalid keys" "$WORK/otel-badkey.log" \
  || { cp "$WORK/config.yaml.good" "$OTEL_DIR/config.yaml"; fail "validate failed for an unexpected reason:\n$(cat "$WORK/otel-badkey.log")"; }
cp "$WORK/config.yaml.good" "$OTEL_DIR/config.yaml"
pass "otelcol validate rejects an unknown processor key ('has invalid keys: bogus_unknown_key')"

step "documented gap: otelcol validate does NOT catch a processor missing from service.pipelines"
# This is not a control that is expected to fail — it is an empirical
# finding, asserted so a future otelcol upgrade that starts catching this
# is noticed (the test breaks, forcing this comment and the guide to be
# corrected), rather than the gap being silently assumed forever.
# Insert a processor block before "extensions:" and never reference it from
# any pipeline. Plain awk, so the only host requirements stay bash and docker.
awk '
  /^extensions:$/ && !done {
    print "  resource/unused:"
    print "    attributes:"
    print "      - key: deployment.environment"
    print "        action: upsert"
    print "        value: production"
    print ""
    done = 1
  }
  { print }
' "$OTEL_DIR/config.yaml" > "$WORK/config-dead.yaml"
grep -q "resource/unused" "$WORK/config-dead.yaml" \
  || fail "the dead-config fixture could not be built — config.yaml no longer has a top-level 'extensions:' line, update this test"
if otelcol_validate "config-dead.yaml" >"$WORK/otel-dead.log" 2>&1; then
  pass "confirmed: a 'resource/unused' processor defined but absent from every pipeline is accepted with exit 0 — this is the silently-dead-config trap; see guides/observability-logging.md"
else
  fail "otelcol validate REJECTED a component missing from service.pipelines — this contradicts the documented gap; update this test and guides/observability-logging.md to match the new behaviour:\n$(cat "$WORK/otel-dead.log")"
fi

echo
echo "All observability baseline checks passed."
