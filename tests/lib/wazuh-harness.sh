#!/bin/sh
# Runs inside the Wazuh manager image. Stages the baseline, then prints one
# token per check so the host side can assert on them. Never exits non-zero on a
# failed check: the host decides, so a missing token is a failure rather than a
# silent skip.
set -u

# The image stages its real configuration under data_tmp/exclusion and copies it
# into place from its entrypoint on first boot. Nothing here boots the manager,
# so the copy has to happen explicitly — without it every binary fails with
# "Could not open file 'etc/internal_options.conf'".
cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/ 2>/dev/null
cd /var/ossec || exit 9

cp /w/rules/local_rules.xml etc/rules/local_rules.xml
cp /w/decoders/local_decoder.xml etc/decoders/local_decoder.xml
mkdir -p etc/shared/default
cp /w/agent.conf etc/shared/default/agent.conf

# --- the ruleset must load in the real analysisd -------------------------
if ./bin/wazuh-analysisd -t 2>&1 | grep -qE "Error loading the rules|Invalid option|is static"; then
  echo "ANALYSISD:REJECTED"
else
  echo "ANALYSISD:LOADED"
fi

# --- verify-agent-conf on the shipped agent.conf -------------------------
AGENTCONF_OUT="$(./bin/verify-agent-conf 2>&1)"
case "$AGENTCONF_OUT" in
  *"verify-agent-conf: OK"*) echo "AGENTCONF:OK" ;;
  *ERROR*)                   echo "AGENTCONF:ERROR" ;;
  *)                         echo "AGENTCONF:UNKNOWN" ;;
esac
printf '%s' "$AGENTCONF_OUT" | grep -qi warning && echo "AGENTCONF:WARNING" || echo "AGENTCONF:NOWARNING"

# --- one logtest per case ------------------------------------------------
# "<case>|<log line>": the rule id that fires is printed as LOGTEST:<case>:<id>,
# or LOGTEST:<case>:NONE when nothing matched. Both are explicit, so an empty
# result cannot satisfy an assertion.
while IFS='|' read -r case line; do
  [ -n "$case" ] || continue
  out="$(printf '%s\n' "$line" | timeout 120 ./bin/wazuh-logtest-legacy -q 2>&1)"
  id="$(printf '%s' "$out" | grep -o "Rule id: '[0-9]*'" | tail -1 | tr -dc '0-9')"
  [ -n "$id" ] || id=NONE
  echo "LOGTEST:$case:$id"
done <<'CASES'
root_ssh|Dec 29 10:00:00 host sshd[1]: Accepted publickey for root from 10.0.0.9 port 22 ssh2: ED25519 SHA256:abc
normal_ssh|Dec 29 10:00:00 host sshd[1]: Accepted publickey for deploy from 10.0.0.9 port 22 ssh2: ED25519 SHA256:abc
sudo_unauthorised|Dec 29 10:00:05 host sudo:  mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash
sudo_normal|Dec 29 10:00:04 host sudo:  deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash
app_authfail|Dec 29 10:00:01 host exampleapp[9]: ACTION=login RESULT=fail USER=bob SRCIP=203.0.113.9
app_authok|Dec 29 10:00:07 host exampleapp[9]: ACTION=login RESULT=ok USER=bob SRCIP=203.0.113.9
app_grant_admin|Dec 29 10:00:02 host exampleapp[9]: ACTION=grant ROLE=admin USER=carol BY=bob
app_grant_viewer|Dec 29 10:00:08 host exampleapp[9]: ACTION=grant ROLE=viewer USER=carol BY=bob
CASES

# --- the decoder must extract the fields the rules match on -------------
DEC_OUT="$(printf 'Dec 29 10:00:01 host exampleapp[9]: ACTION=login RESULT=fail USER=bob SRCIP=203.0.113.9\n' \
  | timeout 120 ./bin/wazuh-logtest-legacy -q 2>&1)"
for f in "status: 'fail'" "srcuser: 'bob'" "srcip: '203.0.113.9'"; do
  if printf '%s' "$DEC_OUT" | grep -qF "$f"; then
    echo "FIELD:OK:$(printf '%s' "$f" | cut -d: -f1)"
  else
    echo "FIELD:MISSING:$(printf '%s' "$f" | cut -d: -f1)"
  fi
done

# --- controls: each must be REJECTED by the real parser ------------------
# 1. a static field written as <field name="...">, which is the mistake that
#    stops the whole file loading.
cat > etc/rules/local_rules.xml <<'XML'
<group name="local,">
  <rule id="100099" level="12">
    <if_sid>5715</if_sid>
    <field name="dstuser">^root$</field>
    <description>static field written as a dynamic one</description>
  </rule>
</group>
XML
if ./bin/wazuh-analysisd -t 2>&1 | grep -q "is static"; then
  echo "CONTROL:STATIC_FIELD:REJECTED"
else
  echo "CONTROL:STATIC_FIELD:ACCEPTED"
fi

# 2. a rule id inside the built-in range, which silently replaces an upstream
#    rule. analysisd has an opinion about this; whichever way it goes is
#    recorded rather than assumed.
cat > etc/rules/local_rules.xml <<'XML'
<group name="local,">
  <rule id="5715" level="0">
    <if_sid>5715</if_sid>
    <description>overriding a built-in rule id</description>
  </rule>
</group>
XML
if ./bin/wazuh-analysisd -t 2>&1 | grep -qE "Error loading the rules|duplicat"; then
  echo "CONTROL:DUPLICATE_ID:REJECTED"
else
  echo "CONTROL:DUPLICATE_ID:ACCEPTED"
fi

# 3. malformed XML in a rule file.
printf '<group name="local,">\n  <rule id="100098" level="5">\n' > etc/rules/local_rules.xml
if ./bin/wazuh-analysisd -t 2>&1 | grep -qE "Error loading the rules|XML|syntax"; then
  echo "CONTROL:BAD_XML:REJECTED"
else
  echo "CONTROL:BAD_XML:ACCEPTED"
fi

# 4. an unknown option in agent.conf, which verify-agent-conf must report as an
#    ERROR in its OUTPUT — its exit status is 0 either way.
sed 's#<disabled>no</disabled>#<disabled>no</disabled><bogus_option>x</bogus_option>#' \
  /w/agent.conf > etc/shared/default/agent.conf
BAD_AGENT_OUT="$(./bin/verify-agent-conf 2>&1)"
BAD_AGENT_RC=$?
case "$BAD_AGENT_OUT" in
  *ERROR*) echo "CONTROL:AGENTCONF:REJECTED" ;;
  *)       echo "CONTROL:AGENTCONF:ACCEPTED" ;;
esac
echo "CONTROL:AGENTCONF:EXIT=$BAD_AGENT_RC"
