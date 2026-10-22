#!/usr/bin/env bash
# The Wazuh demo (owner: Wazuh, WD.5): one attack told as a story, step by
# step, on the running stack. Each step runs a lab scenario, waits until its
# alerts are searchable, and lists them, then waits for Enter so the
# presenter can show them in Grafana and n8n. The talk track is in
# nodes/core/wazuh/DEMO.md.
#
#   step  scenario                what the audience sees
#   1     ids-scan                Suricata sees an nmap scan: 101010 (10, T1046)
#   2     opnsense-scan           the firewall blocks the same kind of scan: 103000 (10)
#   3     ssh-success-after-fail  SSH brute force, then a login: 5763 (10), 40112 (12)
#   4     new-user                a backdoor account added to sudo: 5902, 100211 (10),
#                                 often 40501 (15) after the attacks of step 3
#   5     persistence             sudoers, authorized_keys, cron: 100300-100302 (10, FIM)
#   6     web-attack              SQL injection on a web server: 31103 (7), 31152 (10)
#   7     ioc-ip                  a login attempt from a MISP IOC: 108000 (12); skipped
#                                 when the intel node (MISP) isn't running
#
# Usage: nodes/core/wazuh/tests/demo.sh [--auto] [--from N]
#   --auto    don't wait for Enter between steps (a rehearsal; about 4 minutes)
#   --from N  start at step N (e.g. after an interruption)
# Needs: scripts/soc.sh up core (and up intel for step 7). The brute-force
# rules stay quiet for 60-120 s after firing: wait 5 minutes between runs,
# or after tests/e2e.sh.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTS_DIR/../../../.." && pwd)"
TRIGGER="$REPO_DIR/nodes/lab/trigger.sh"
QUERY="$REPO_DIR/scripts/wazuh-query.sh"
WAIT=25   # seconds from the scenario to its alerts being searchable

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

auto=0 from=1
while (( $# > 0 )); do
  case $1 in
    --auto) auto=1 ;;
    --from) from=${2:-}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
[[ $from =~ ^[1-7]$ ]] || { echo "ERROR --from takes a step number, 1 to 7" >&2; exit 2; }

# scenario | title | where to look
STEPS=(
  "ids-scan|Reconnaissance seen by the network IDS (Suricata)|Grafana SOC Status: Top rules; n8n: recv-wazuh-alert executions"
  "opnsense-scan|The same scan, blocked and reported by the firewall (OPNsense syslog)|Grafana SOC Status: Top source IPs (203.0.113.77)"
  "ssh-success-after-fail|SSH brute force, then a successful login|Grafana Attack Scenarios: Login after failures; the red mark is the attack start"
  "new-user|A backdoor account, added to sudo|Grafana SOC Status: Critical (24h) if 40501 fired; Top targeted users"
  "persistence|Persistence: sudoers, SSH key, cron job (real files, FIM)|Grafana SOC Status: File changes (FIM), Most changed files"
  "web-attack|SQL injection against a web server (Apache access log)|Grafana SOC Overview: Recent alerts (data.url)"
  "ioc-ip|A login attempt from an address MISP knows as malicious|Grafana Attack Scenarios: IOC IP (MISP); rule 108000, level 12"
)

intel_up() { docker ps --format '{{.Names}}' | grep -q misp; }

[[ -x $TRIGGER ]] || { echo "ERROR $TRIGGER not found" >&2; exit 2; }
"$QUERY" -s 1m -n 1 >/dev/null 2>&1 || [[ $? == 1 ]] \
  || { echo "ERROR the indexer doesn't answer: scripts/soc.sh up core" >&2; exit 2; }

n=0
for entry in "${STEPS[@]}"; do
  n=$(( n + 1 ))
  (( n >= from )) || continue
  IFS='|' read -r scenario title look <<<"$entry"
  echo
  echo "== Step $n of ${#STEPS[@]}: $title"
  echo "   scenario: $scenario"
  if [[ $scenario == ioc-ip ]] && ! intel_up; then
    echo "   SKIP: the intel node (MISP) isn't running (scripts/soc.sh up intel)"
    continue
  fi
  t0=$SECONDS
  if ! id=$("$TRIGGER" --scenario "$scenario" 2>/dev/null); then
    echo "   ERROR the scenario failed; run it by hand to see why: nodes/lab/trigger.sh --scenario $scenario" >&2
    continue
  fi
  echo "   run id: $id; waiting ${WAIT}s for the alerts to be indexed..."
  sleep "$WAIT"
  echo "   Alerts of this step sent to n8n (level >= 7, newest first):"
  "$QUERY" -s "$(( SECONDS - t0 + 5 ))s" -l 7 -n 12 2>/dev/null | sed 's/^/     /' \
    || echo "     (none yet: wait a few seconds and look in Grafana)"
  echo "   Show: $look"
  if (( ! auto )) && (( n < ${#STEPS[@]} )); then
    read -r -p "   Enter for the next step (Ctrl-C to stop) " _ </dev/tty
  fi
done
echo
echo "== Done. Every alert at level >= 7 was sent to n8n (C1): n8n, workflow recv-wazuh-alert, Executions."
