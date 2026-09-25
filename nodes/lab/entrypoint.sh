#!/bin/bash
# Lab agent entrypoint (owner: Wazuh). Renders the agent configuration from
# the package default, then runs the agent in the foreground. The same
# three changes are what a real endpoint needs:
#   1. the manager address (WAZUH_MANAGER_ADDR);
#   2. automatic enrollment with the enrollment password (port 1515);
#   3. (lab only) a test log file that nodes/lab/trigger.sh writes to.
# client.keys lives in a volume, so the agent enrolls only once.
set -euo pipefail

: "${WAZUH_MANAGER_ADDR:?WAZUH_MANAGER_ADDR is not set}"
: "${WAZUH_ENROLLMENT_PASSWORD:?WAZUH_ENROLLMENT_PASSWORD is not set}"
AGENT_NAME=${WAZUH_AGENT_NAME:-lab-agent}
TEST_LOG=/var/log/asox-lab/test.log
OSSEC=/var/ossec

# Enrollment password, read by the agent from etc/authd.pass.
umask 027
printf '%s\n' "$WAZUH_ENROLLMENT_PASSWORD" > "$OSSEC/etc/authd.pass"
chown root:wazuh "$OSSEC/etc/authd.pass"

# ossec.conf from the package default.
enrollment="    <enrollment>\n      <enabled>yes</enabled>\n      <agent_name>${AGENT_NAME}</agent_name>\n      <authorization_pass_path>etc/authd.pass</authorization_pass_path>\n    </enrollment>"
sed -e "s|<address>MANAGER_IP</address>|<address>${WAZUH_MANAGER_ADDR}</address>|" \
    -e "0,/^  <\/client>/s||${enrollment}\n  </client>|" \
    /opt/asox/ossec.conf.dist > "$OSSEC/etc/ossec.conf"
cat >> "$OSSEC/etc/ossec.conf" <<CONF

<!-- ASOX lab: test events written by nodes/lab/trigger.sh -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>${TEST_LOG}</location>
  </localfile>
</ossec_config>
CONF
chown root:wazuh "$OSSEC/etc/ossec.conf"
chmod 640 "$OSSEC/etc/ossec.conf"

umask 022
mkdir -p "$(dirname "$TEST_LOG")"
touch "$TEST_LOG"

# A stop during the previous start can leave this lock behind.
rm -rf "$OSSEC/var/start-script-lock"

stop() {
  "$OSSEC/bin/wazuh-control" stop || true
  exit 0
}
trap stop TERM INT

"$OSSEC/bin/wazuh-control" start
tail -n 0 -F "$OSSEC/logs/ossec.log" &
wait $!
