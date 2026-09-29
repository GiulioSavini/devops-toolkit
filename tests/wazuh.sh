#!/usr/bin/env bash
# Validates baselines/wazuh/. Run from the repository root:
#
#   bash tests/wazuh.sh
#
# Host requirements: bash and docker. Everything runs inside the real Wazuh
# manager image, pinned by digest.
#
# What this proves:
#   1. Every XML file is well-formed — after being wrapped, because Wazuh rule,
#      decoder and agent configuration files are FRAGMENTS with several roots and
#      plain xmllint rejects them with "Extra content at the end of the document".
#   2. The custom ruleset and decoders load in the real wazuh-analysisd.
#   3. Every custom rule FIRES on the log line it is written for, and does NOT
#      fire on the benign line next to it, through the real
#      wazuh-logtest-legacy. A rule nobody has seen fire is a rule that does not
#      work; a rule that fires on everything is worse.
#   4. The custom decoder extracts the exact field names the rules match on
#      (status, srcuser, srcip). A decoder whose prematch never matches produces
#      no fields and therefore no alert, silently.
#   5. agent.conf is accepted by the real verify-agent-conf, with no warnings —
#      and an unknown option in it is both reported in the output and reflected
#      in a non-zero exit status, which this suite measures rather than assumes.
#   6. Four controls, each proving one of the above can fail: a static field
#      written as <field name="...">, a rule id inside the built-in range,
#      malformed XML, and an unknown agent.conf option.
#   7. The baseline ships no enabled active response, which is a deliberate
#      policy (see baselines/wazuh/active-response/README.md) and not an
#      omission.
#
# What this does NOT do:
#   - It does not run a manager, an agent, or the indexer, so nothing here
#     exercises enrolment, the cluster or the API.
#   - The FIM rules (100040-100042) are checked for syntax by analysisd, but they
#     are NOT fired: syscheck events arrive as JSON from wazuh-syscheckd, and
#     wazuh-logtest-legacy reads syslog-shaped lines. Proving those would need a
#     running agent with a real file change, which is an integration test with a
#     manager and an agent, not a container check.
#   - The correlation rule (100021, frequency 5 in 120s) is not fired either:
#     logtest evaluates one event at a time and cannot build correlation state.
#   - Nothing here validates that the manager-side fragment merges into a real
#     ossec.conf; it is checked as XML and read for the two settings the guide
#     makes claims about.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE="baselines/wazuh"
[[ -d "$BASE" ]] || { echo "run from the repository root" >&2; exit 2; }

# Digests were current on 2026-09-29; the tag each belonged to is in the comment.
WAZUH_IMAGE="wazuh/wazuh-manager@sha256:6b53d4cc5c013b08157471d11f7a7c2c45f9e8238f3958e3b2f04ec1773ecbd4" # wazuh/wazuh-manager:4.14.8
DEBIAN_IMAGE="debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"             # debian:13-slim

WORK="$(mktemp -d)"
cleanup() {
  docker run --rm -v "$WORK:/w" "$DEBIAN_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is required: this suite runs the real Wazuh binaries, it cannot be skipped into passing"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

### 1. XML well-formedness (of fragments) ---------------------------------
step "xmllint: every XML file, wrapped, is well-formed"
# Wazuh reads these files as fragments, so each is wrapped in a single root
# before checking. Checking them unwrapped fails on every correct file, which is
# how a "validation" step ends up being disabled by whoever hits it first.
mkdir -p "$WORK/xml"
XML_FILES=()
while IFS= read -r f; do XML_FILES+=("$f"); done < <(find "$BASE" -name '*.xml' | sort)
[[ ${#XML_FILES[@]} -ge 3 ]] || fail "expected at least 3 XML files under $BASE, found ${#XML_FILES[@]}"
for f in "${XML_FILES[@]}"; do
  name="$(echo "$f" | tr '/' '_')"
  { echo '<wazuh_fragment_wrapper>'; cat "$f"; echo '</wazuh_fragment_wrapper>'; } > "$WORK/xml/$name"
done
docker run --rm -v "$WORK/xml:/x:ro" "$DEBIAN_IMAGE" bash -c '
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y libxml2-utils >/dev/null 2>&1
  rc=0
  for f in /x/*; do xmllint --noout "$f" || rc=1; done
  exit $rc
' || fail "at least one XML file is not well-formed even when wrapped"
pass "${#XML_FILES[@]} XML files well-formed"

step "control: an unwrapped multi-root file must be rejected by xmllint"
# This is the finding, asserted: if xmllint ever accepts the raw file, the
# wrapping above is unnecessary and the comment explaining it is wrong.
mkdir -p "$WORK/raw"
cp "$BASE/rules/local_rules.xml" "$WORK/raw/"
if docker run --rm -v "$WORK/raw:/x:ro" "$DEBIAN_IMAGE" bash -c '
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y libxml2-utils >/dev/null 2>&1
  xmllint --noout /x/local_rules.xml' >/dev/null 2>&1; then
  fail "xmllint accepted a multi-root Wazuh rule file — the wrapping above is pointless and the comments must be corrected"
fi
pass "raw multi-root file rejected, as documented"

### 2-6. the real Wazuh binaries -----------------------------------------
step "wazuh-analysisd, wazuh-logtest-legacy and verify-agent-conf"
docker run --rm \
  -v "$ROOT/$BASE:/w:ro" \
  -v "$ROOT/tests/lib/wazuh-harness.sh:/harness.sh:ro" \
  --entrypoint /bin/sh "$WAZUH_IMAGE" /harness.sh > "$WORK/harness.out" 2> "$WORK/harness.err" \
  || fail "the harness itself failed to run:\n$(tail -20 "$WORK/harness.err")"

token() { grep -m1 "^$1:" "$WORK/harness.out" | cut -d: -f2- || true; }
has()   { grep -qx "$1" "$WORK/harness.out"; }

has "ANALYSISD:LOADED" \
  || fail "the ruleset did not load in the real analysisd:\n$(grep -E 'ANALYSISD|Invalid|static' "$WORK/harness.out" "$WORK/harness.err" | head -10)"
pass "the custom ruleset and decoders load in wazuh-analysisd"

step "every custom rule fires on its own log line, and not on the benign one"
# case | rule that must fire | rule that must NOT be the answer
while IFS='|' read -r case expect; do
  [[ -n "$case" ]] || continue
  got="$(grep -m1 "^LOGTEST:$case:" "$WORK/harness.out" | cut -d: -f3)"
  [[ -n "$got" ]] || fail "no logtest result for '$case' — the harness did not run that case"
  if [[ "$expect" == NOT_* ]]; then
    forbidden="${expect#NOT_}"
    [[ "$got" != "$forbidden" ]] \
      || fail "$case matched rule $got, which it must NOT: the rule is too broad"
    echo "    ok: $case -> $got (not $forbidden)"
  else
    [[ "$got" == "$expect" ]] \
      || fail "$case matched rule '$got', expected '$expect'"
    echo "    ok: $case -> $got"
  fi
done <<'EXPECT'
root_ssh|100010
normal_ssh|NOT_100010
sudo_unauthorised|100011
sudo_normal|NOT_100011
app_authfail|100020
app_authok|NOT_100020
app_grant_admin|100030
app_grant_viewer|NOT_100030
EXPECT
pass "4 rules fire, and 4 benign lines do not"

step "the custom decoder extracts the fields the rules match on"
for f in status srcuser srcip; do
  has "FIELD:OK:$f" || fail "the decoder did not extract '$f' — every rule matching on it is dead:\n$(grep FIELD "$WORK/harness.out")"
done
pass "status, srcuser and srcip extracted by the local decoder"

step "verify-agent-conf accepts agent.conf, with no warnings"
has "AGENTCONF:OK" || fail "verify-agent-conf did not report OK:\n$(grep AGENTCONF "$WORK/harness.out")"
has "AGENTCONF:NOWARNING" \
  || fail "verify-agent-conf warned about agent.conf; a warning on every push trains people to ignore the validator:\n$(grep AGENTCONF "$WORK/harness.out")"
pass "agent.conf verified clean"

step "controls: each check above must be able to fail"
has "CONTROL:STATIC_FIELD:REJECTED" \
  || fail "analysisd accepted a static field written as <field name=...>, so the ruleset check proves nothing"
echo "    ok: a static field written as a dynamic one stops the ruleset loading"
has "CONTROL:BAD_XML:REJECTED" \
  || fail "analysisd accepted malformed XML in a rule file"
echo "    ok: malformed XML rejected by analysisd"
has "CONTROL:AGENTCONF:REJECTED" \
  || fail "verify-agent-conf accepted an unknown option — reading its output proves nothing"
echo "    ok: an unknown agent.conf option is reported"
# verify-agent-conf's exit status, measured rather than assumed: on 4.14.8 it
# does exit non-zero for a bad config. Piping its output through `tail` (the
# obvious way to read it in a script) throws that status away, which is how a
# validation step ends up reporting success on a broken config.
EXIT_LINE="$(grep -m1 '^CONTROL:AGENTCONF:EXIT=' "$WORK/harness.out" | cut -d= -f2)"
[[ -n "$EXIT_LINE" ]] || fail "the harness did not record verify-agent-conf's exit status"
[[ "$EXIT_LINE" != "0" ]] \
  || fail "verify-agent-conf exited 0 on a config it reported an ERROR for — a pipeline that checks only the exit status would pass, and this test must keep reading the output"
echo "    ok: verify-agent-conf also exits non-zero ($EXIT_LINE) on a bad config"
# Whether analysisd rejects a rule id that collides with a built-in one is
# recorded rather than assumed; it is the reason the baseline stays in 100000+.
if has "CONTROL:DUPLICATE_ID:REJECTED"; then
  echo "    ok: reusing a built-in rule id is rejected outright"
else
  echo "    ok: reusing a built-in rule id is ACCEPTED silently — which is why the baseline stays in the 100000+ range"
fi
pass "4 controls, all behaving"

### 7. the policy assertions ---------------------------------------------
step "the baseline ships no enabled active response"
if grep -rqE '^[^#<]*<active-response>' --include='*.xml' --include='*.conf' "$BASE"; then
  fail "an <active-response> block is enabled in the baseline: see $BASE/active-response/README.md for why that is deliberate, and make it a reviewed change rather than a default"
fi
grep -q 'rules_id' "$BASE/active-response/README.md" \
  || fail "the active-response README no longer shows the rules_id-scoped form it recommends"
pass "no active response enabled; the README documents how to add one"

step "the manager fragment keeps the settings the guide claims"
grep -q '<logall_json>no</logall_json>' "$BASE/manager-ossec-fragment.xml" \
  || fail "logall_json is not 'no': the guide says storing every event is a deliberate choice with retention attached"
grep -q '<log_alert_level>3</log_alert_level>' "$BASE/manager-ossec-fragment.xml" \
  || fail "log_alert_level is not 3"
grep -q '<email_alert_level>12</email_alert_level>' "$BASE/manager-ossec-fragment.xml" \
  || fail "email_alert_level is not 12: the point of the pair is that everything is searchable and only 12+ interrupts a human"
pass "alert levels and logall_json are what the guide describes"

echo
echo "All Wazuh baseline checks passed."
