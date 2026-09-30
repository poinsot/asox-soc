#!/usr/bin/env bash
# Create realistic test alerts in TheHive, shaped like the ones n8n will send
# from Wazuh (docs/ALERT-FORMAT.md), so the case templates, custom fields and
# triage procedure can be tried in `cases` mode, where Wazuh doesn't run.
# Alerts are created with n8n's own TheHive account (C3), so this also checks
# that account's permissions. Every test alert has source "asox-test".
#
# Usage: nodes/cases/thehive/scripts/thehive-test-alert.sh [SCENARIO...] [--critical-asset]
#        nodes/cases/thehive/scripts/thehive-test-alert.sh --cleanup
#   SCENARIO          ssh, malware, ids, generic, or all (default: ssh)
#   --critical-asset  mark the host as critical (severity +1, as in the mapping)
#   --cleanup         delete every alert with source "asox-test"
# Run it on the machine hosting cases, while cases is up.
set -euo pipefail
# shellcheck source=nodes/cases/thehive/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TEST_SOURCE=asox-test
SCENARIOS=(ssh malware ids generic)

CLEANUP=0 CRITICALITY=medium
wanted=()
for a in "$@"; do
  case $a in
    -h|--help) print_usage "$0"; exit 0 ;;
    --cleanup) CLEANUP=1 ;;
    --critical-asset) CRITICALITY=critical ;;
    all) wanted+=("${SCENARIOS[@]}") ;;
    ssh|malware|ids|generic) wanted+=("$a") ;;
    *) die "unknown argument: $a (scenarios: ${SCENARIOS[*]} all; options: --critical-asset --cleanup)" ;;
  esac
done
(( ${#wanted[@]} > 0 )) || wanted=(ssh)

[[ -f "$(node_dir cases)/.env" ]] || die "nodes/cases/.env not found; run scripts/soc.sh init cases"
N8N_KEY=$(cases_env THEHIVE_N8N_API_KEY)
[[ -n $N8N_KEY ]] || die "THEHIVE_N8N_API_KEY is empty in nodes/cases/.env; run scripts/bootstrap.sh cases"
as_n8n() { thehive_key "$N8N_KEY" "$@"; }
r=$(as_n8n GET /api/v1/user/current)
[[ $(http_code "$r") == 200 ]] \
  || die "TheHive refuses n8n's API key (HTTP $(http_code "$r")); is cases up? (scripts/soc.sh up cases)"

# ---- Cleanup ----
if (( CLEANUP )); then
  q=$(jq -nc --arg s "$TEST_SOURCE" '{query: [{_name: "listAlert"}, {_name: "filter", _eq: {_field: "source", _value: $s}}]}')
  r=$(as_n8n POST '/api/v1/query?name=testAlerts' "$q")
  th_expect "list test alerts" "$r" 200 || finish
  mapfile -t ids < <(http_body "$r" | jq -r '.[]._id')
  for id in ${ids[@]+"${ids[@]}"}; do
    th_expect "delete alert $id" "$(as_n8n DELETE "/api/v1/alert/$id")" 200 204 || true
  done
  pass "deleted ${#ids[@]} test alert(s) (source $TEST_SOURCE)"
  finish
  exit 0
fi

# ---- Scenarios: what Wazuh would have detected ----
# One line each: template, rule id, level, rule description, agent, MITRE
# technique, observables (JSON). 203.0.113.66 is the seed IOC published in
# MISP (C7), so the MISP analyzer finds it when the intel node runs.
scenario() {
  case $1 in
    ssh) printf '%s\n' ssh-bruteforce 5712 10 \
          "sshd: brute force trying to get access to the system. Non existent user." \
          lab-agent T1110 \
          '[{"dataType":"ip","data":"203.0.113.66","tags":["src"],"message":"Source of the failed logins"},{"dataType":"user-account","data":"admin","tags":["target"],"message":"Targeted user"},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    malware) printf '%s\n' malware-detection 87105 12 \
          "VirusTotal: Alert - /tmp/eicar.com - 60 engines detected this file" \
          lab-agent T1204 \
          '[{"dataType":"hash","data":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","tags":["sha256"],"message":"EICAR test file","ioc":true},{"dataType":"filename","data":"/tmp/eicar.com","tags":["path"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    ids) printf '%s\n' ids-network-alert 20101 8 \
          "IDS event: ET SCAN Nmap Scripting Engine User-Agent Detected" \
          lab-agent T1046 \
          '[{"dataType":"ip","data":"198.51.100.23","tags":["src"],"message":"Scanner"},{"dataType":"ip","data":"192.168.1.20","tags":["dst"]},{"dataType":"user-agent","data":"Mozilla/5.00 (Nmap Scripting Engine)"}]' ;;
    generic) printf '%s\n' wazuh-generic 31151 10 \
          "Multiple web server 400 error codes from same source ip." \
          lab-agent T1595 \
          '[{"dataType":"ip","data":"198.51.100.77","tags":["src"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
  esac
}

for s in "${wanted[@]}"; do
  mapfile -t f < <(scenario "$s")
  template=${f[0]} rule=${f[1]} level=${f[2]} desc=${f[3]} agent=${f[4]} mitre=${f[5]} obs=${f[6]}
  now=$(date +%s)
  alert_id="$now.$RANDOM$RANDOM"
  severity=$(th_severity "$level" "$CRITICALITY")
  body=$(jq -nc \
    --arg src "$TEST_SOURCE" --arg ref "$alert_id" --arg tpl "$template" --arg desc "$desc" \
    --arg agent "$agent" --arg mitre "$mitre" --arg crit "$CRITICALITY" \
    --argjson rule "$rule" --argjson level "$level" --argjson sev "$severity" \
    --argjson date "$((now * 1000))" --argjson obs "$obs" '{
      type: "wazuh", source: $src, sourceRef: $ref,
      title: "\($desc) (\($agent))",
      description: "**Test alert** created by thehive-test-alert.sh (not a real detection).\n\n| Field | Value |\n|---|---|\n| Wazuh rule | \($rule), level \($level) |\n| Description | \($desc) |\n| Agent | \($agent) |\n| MITRE ATT&CK | \($mitre) |\n| Wazuh alert ID | \($ref) |",
      severity: $sev, tlp: 2, pap: 2, date: $date,
      tags: ["wazuh", "test", "rule:\($rule)", "agent:\($agent)", "attack.\($mitre | ascii_downcase)"],
      caseTemplate: $tpl,
      customFields: [
        {name: "wazuh-alert-id", value: $ref},
        {name: "wazuh-rule-id", value: $rule},
        {name: "wazuh-rule-level", value: $level},
        {name: "wazuh-agent-name", value: $agent},
        {name: "mitre-technique", value: $mitre},
        {name: "asset-criticality", value: $crit},
        {name: "playbook", value: "manual-test"}
      ],
      observables: $obs
    }')
  r=$(as_n8n POST /api/v1/alert "$body")
  if th_expect "$s: create alert" "$r" 200 201; then
    pass "$s: alert $(http_body "$r" | jq -r '._id') created (severity $severity, template $template) -> ${THEHIVE_API}/alerts"
  fi
done

finish
