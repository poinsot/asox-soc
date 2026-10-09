#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh), after the config copy (05-restart-fixes.sh).
# Agent groups as code (W5.1): groups/<name>/agent.conf in the repo is
# mounted under /wazuh-config-mount/etc/shared and copied to
# /var/ossec/etc/shared/<name>/ with the rest of the config. Wazuh registers a
# group for every folder there when it starts, so no group is created here;
# this only gives the copied files the owner and mode the manager expects.
set -euo pipefail
SHARED=/var/ossec/etc/shared

groups=()
for dir in "$SHARED"/*/; do
  [[ -f $dir/agent.conf ]] || continue
  chown wazuh:wazuh "$dir" "$dir/agent.conf"
  chmod 770 "$dir"
  chmod 660 "$dir/agent.conf"
  groups+=("$(basename "$dir")")
done
echo "agent groups: ${groups[*]}"
