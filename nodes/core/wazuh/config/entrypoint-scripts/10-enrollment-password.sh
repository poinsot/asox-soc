#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh). Writes the agent enrollment password from
# WAZUH_ENROLLMENT_PASSWORD (nodes/core/.env) to authd.pass, so changing the
# value in .env and recreating the manager is enough to rotate it.
# If the variable is empty, authd.pass is removed and authd, which requires a
# password (ossec.conf <use_password>), generates a random one: enrollment
# fails closed.
set -euo pipefail
PASS_FILE=/var/ossec/etc/authd.pass
if [[ -z ${WAZUH_ENROLLMENT_PASSWORD:-} ]]; then
  echo "ERROR: WAZUH_ENROLLMENT_PASSWORD is empty; agents cannot enroll" >&2
  rm -f "$PASS_FILE"
  exit 1
fi
umask 027
printf '%s\n' "$WAZUH_ENROLLMENT_PASSWORD" > "$PASS_FILE"
chown root:wazuh "$PASS_FILE"
chmod 640 "$PASS_FILE"
echo "Agent enrollment password written to $PASS_FILE"
