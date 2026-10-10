#!/usr/bin/env bash
# End-to-end check of the Wazuh component (owner: Wazuh, WD.3-WD.5): runs
# every lab scenario of nodes/lab/trigger.sh on the running stack, then checks
# that each produced its expected rules in the indexer and that every alert at
# level >= 7 reached n8n's recv-wazuh-alert (C1). One PASS/FAIL line per check;
# exit 1 if any fails. Also the demo script: the scenarios run in a fixed
# order with the waits the rules need.
#
# Usage: nodes/core/wazuh/tests/e2e.sh [--no-n8n] [--skip-ids] [SCENARIO...]
#   --no-n8n    don't check n8n (e.g. n8n not running)
#   --skip-ids  skip ids-test and ids-scan (no Suricata, or no internet)
#   SCENARIO    run only these (default: all)
#
# Needs: scripts/soc.sh up core (core + lab, Suricata for the IDS ones).
# Takes about 6 minutes. Several rules stay quiet for 60-120 s after they
# fire (5763, 5712, 103000, 103011, 108000), so wait 5 minutes between runs.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTS_DIR/../../../.." && pwd)"
TRIGGER="$REPO_DIR/nodes/lab/trigger.sh"
QUERY="$REPO_DIR/scripts/wazuh-query.sh"
WAIT=25   # seconds from the scenario to its alerts being searchable

# The comment block at the top of this file.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

n8n=1 skip_ids=0 only=()
while (( $# > 0 )); do
  case $1 in
    --no-n8n) n8n=0 ;;
    --skip-ids) skip_ids=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) only+=("$1") ;;
  esac
  shift
done

# scenario | expected rules (a|b: either one) | seconds to wait afterwards
# Order matters: ssh-bruteforce and ssh-success-after-fail both need 5763,
# which is quiet for 60 s after firing, so they run first and near the end.
PLAN=(
  "ssh-bruteforce|5763|0"
  "sudo-fail|5404|0"
  "new-user|5901 5902 100211|0"
  "root-login|100200|0"
  "persistence|100300 100301 100302|0"
  "ids-test|101001|0"
  "ids-scan|101010|0"
  "opnsense-scan|103000|0"
  "opnsense-gui-bruteforce|103011|0"
  "ssh-success-after-fail|5763 40112|0"
  "ioc-ip|5712|108000|0"
)

fails=0 passes=0
pass() { echo "PASS  $*"; passes=$((passes + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

# Alerts of one rule since $1 seconds ago, as "id level" lines.
alerts() {  # seconds rule
  "$QUERY" -s "${1}s" -r "$2" -n 50 -j 2>/dev/null \
    | jq -r '(if type == "array" then .[] else . end) | "\(.id) \(.rule.level)"' 2>/dev/null || true
}

declare -a forwarded=()   # alert IDs at level >= 7, to find in n8n
started=$SECONDS
c1_id=$("$TRIGGER" 2>/dev/null) || { echo "ERROR the lab trigger failed (scripts/soc.sh up core)" >&2; exit 2; }
echo "== C1 test event $c1_id, then the scenarios (about 6 minutes)"

for entry in "${PLAN[@]}"; do
  IFS='|' read -r scenario rest <<<"$entry"
  expect=${rest%|*}            # everything but the trailing wait field
  if (( ${#only[@]} )) && [[ " ${only[*]} " != *" $scenario "* ]]; then continue; fi
  if (( skip_ids )) && [[ $scenario == ids-* ]]; then echo "SKIP  $scenario (--skip-ids)"; continue; fi
  t0=$SECONDS
  if ! "$TRIGGER" --scenario "$scenario" >/dev/null 2>&1; then
    fail "$scenario: trigger.sh failed (run it by hand to see why)"; continue
  fi
  sleep "$WAIT"
  window=$(( SECONDS - t0 + 5 ))
  for want in $expect; do
    got=""
    for r in ${want//|/ }; do
      got=$(alerts "$window" "$r")
      [[ -n $got ]] && { want=$r; break; }
    done
    if [[ -n $got ]]; then
      pass "$scenario: rule $want ($(wc -l <<<"$got") alert(s), level $(head -1 <<<"$got" | cut -d' ' -f2))"
      while read -r aid lvl; do (( lvl >= 7 )) && forwarded+=("$aid"); done <<<"$got"
    else
      fail "$scenario: no alert of rule ${want//|/ or } within ${window}s"
    fi
  done
  # The attack-start marker of this run.
  if [[ -n $(alerts "$window" 100101) ]]; then pass "$scenario: attack-start marker 100101"; else fail "$scenario: no attack-start marker 100101"; fi
done

c1=$(alerts $(( SECONDS - started + 5 )) 100100 | head -1)
if [[ -n $c1 ]]; then pass "C1 test event: rule 100100"; forwarded+=("${c1%% *}"); else fail "C1 test event: no rule 100100"; fi

# C1: every forwarded alert has a recv-wazuh-alert execution in n8n.
if (( n8n )); then
  # shellcheck source=scripts/lib/common.sh
  source "$REPO_DIR/scripts/lib/common.sh"
  # shellcheck source=scripts/lib/n8n.sh
  source "$REPO_DIR/scripts/lib/n8n.sh"
  if ! n8n_api_ok; then
    fail "n8n API not reachable (N8N_API_KEY); use --no-n8n to skip"
  else
    sleep 10
    wf=$(n8n_workflow_id_by_name recv-wazuh-alert)
    execs=$(n8n_api GET "/executions?workflowId=$wf&limit=100&includeData=true")
    seen=0 missing=()
    for aid in "${forwarded[@]}"; do
      if jq -e --arg a "$aid" '[.data[]? | select(tostring | contains($a))] | length > 0' <<<"$execs" >/dev/null; then
        seen=$((seen + 1))
      else
        missing+=("$aid")
      fi
    done
    if (( ${#missing[@]} == 0 )); then
      pass "C1: all ${#forwarded[@]} alerts at level >= 7 reached n8n's recv-wazuh-alert"
    else
      fail "C1: ${#missing[@]} of ${#forwarded[@]} alerts at level >= 7 not found in n8n: ${missing[*]}"
    fi
  fi
fi

echo
echo "$passes passed, $fails failed ($(( (SECONDS - started) / 60 )) min)"
(( fails == 0 ))
