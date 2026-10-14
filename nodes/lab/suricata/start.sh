#!/bin/bash
# Suricata start (owner: Wazuh, W3.2). Runs in the suricata service, which
# shares the lab agent's network namespace (network_mode: service:lab-agent),
# so it sees that container's traffic on eth0 (its own network, with the
# default route) and eth1 (soc-net, single-host mode only).
#
# ET Open rules come from suricata-update (no account needed). They are kept
# in the suricata-lib volume and refreshed at most once a day, so a restart
# doesn't need the internet. Then the image's own entrypoint starts Suricata
# with the ASOX overrides (asox.yaml: alerts only in eve.json).
set -euo pipefail
RULES=/var/lib/suricata/rules/suricata.rules

# A changed enable.conf forces a fresh update.
[[ /asox/enable.conf -nt $RULES ]] && rm -f "$RULES"

if [[ ! -s $RULES ]] || [[ -n $(find "$RULES" -mmin +1440 2>/dev/null) ]]; then
  echo "suricata-update: fetching ET Open rules"
  if ! suricata-update --no-test --no-reload --enable-conf /asox/enable.conf; then
    [[ -s $RULES ]] || { echo "ERROR: no rules and suricata-update failed (internet access needed once)" >&2; exit 1; }
    echo "WARNING: suricata-update failed; keeping the rules from $(date -r "$RULES" '+%F %T')" >&2
  fi
fi

ifaces=()
for i in eth0 eth1; do [[ -e /sys/class/net/$i ]] && ifaces+=(-i "$i"); done

# HOME_NET is the host this sensor protects: the lab agent's own addresses.
# ET rules alert on $EXTERNAL_NET -> $HOME_NET; the default (every private
# range) would count the other lab containers, e.g. ids-scan's attacker, as
# home, and inbound scans would never alert.
home=$(ip -4 -o addr show | awk '$2 != "lo" {sub(/\/.*/, "", $4); print $4}' | paste -sd, -)
[[ -n $home ]] || { echo "ERROR: no IPv4 address on the lab agent's interfaces" >&2; exit 1; }
echo "HOME_NET=[$home]"
exec /docker-entrypoint.sh "${ifaces[@]}" --include /asox/asox.yaml \
  --set "vars.address-groups.HOME_NET=[$home]"
