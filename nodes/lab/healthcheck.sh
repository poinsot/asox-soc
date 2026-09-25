#!/bin/bash
# Lab agent healthcheck (owner: Wazuh). Healthy when the agent is ready to
# collect test events, not merely connected: after enrolling, the agent
# receives the manager's shared configuration (merged.mg) and reloads, and
# lines written before its log collector restarts are never read.
set -euo pipefail
OSSEC=/var/ossec
grep -q "status='connected'" "$OSSEC/var/run/wazuh-agentd.state"
merged="$OSSEC/etc/shared/merged.mg"
test -f "$merged"
pid=$(pgrep -o -x wazuh-logcollec || pgrep -o -f "$OSSEC/bin/wazuh-logcollector")
# The collector must have (re)started after the shared configuration arrived.
(( $(stat -c %Y "/proc/$pid") >= $(stat -c %Y "$merged") ))
