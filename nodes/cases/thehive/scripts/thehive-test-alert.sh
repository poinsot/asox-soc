#!/usr/bin/env bash
# Create realistic test alerts in TheHive, shaped like the ones n8n will send
# from Wazuh (docs/ALERT-FORMAT.md), so the case templates, custom fields and
# triage procedure can be tried in `cases` mode, where Wazuh doesn't run.
# Alerts are created with n8n's own TheHive account (C3), so this also checks
# that account's permissions. Every test alert has source "asox-test".
#
# Usage: nodes/cases/thehive/scripts/thehive-test-alert.sh [SCENARIO...] [--critical-asset] [--promote]
#        nodes/cases/thehive/scripts/thehive-test-alert.sh --cleanup
#   SCENARIO          ssh, malware, ids, generic (the 4 base templates), login,
#                     sudo, newuser, ioc, portscan, fwlogin (templates for the
#                     Wazuh detections in progress), or all (default: ssh)
#   --critical-asset  mark the host as critical (severity +1, as in the mapping)
#   --promote         also promote each alert to a case with n8n's account, as
#                     n8n's auto-promotion will (D-N4), and check the case got
#                     its template's tasks (X-15)
#   --cleanup         delete every test alert (source "asox-test") and the
#                     test cases promoted from them (tag "asox-test"; cases are
#                     deleted as an org-admin, through a temporary API key)
# Run it on the machine hosting cases, while cases is up.
set -euo pipefail
# shellcheck source=nodes/cases/thehive/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TEST_SOURCE=asox-test
SCENARIOS=(ssh malware ids generic login sudo newuser ioc portscan fwlogin)

CLEANUP=0 PROMOTE=0 CRITICALITY=medium
wanted=()
for a in "$@"; do
  case $a in
    -h|--help) print_usage "$0"; exit 0 ;;
    --cleanup) CLEANUP=1 ;;
    --critical-asset) CRITICALITY=critical ;;
    --promote) PROMOTE=1 ;;
    all) wanted+=("${SCENARIOS[@]}") ;;
    ssh|malware|ids|generic|login|sudo|newuser|ioc|portscan|fwlogin) wanted+=("$a") ;;
    *) die "unknown argument: $a (scenarios: ${SCENARIOS[*]} all; options: --critical-asset --promote --cleanup)" ;;
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
  q=$(jq -nc --arg t "$TEST_SOURCE" '{query: [{_name: "listCase"}, {_name: "filter", _eq: {_field: "tags", _value: $t}}]}')
  r=$(as_n8n POST '/api/v1/query?name=testCases' "$q")
  if th_expect "list test cases" "$r" 200; then
    mapfile -t cids < <(http_body "$r" | jq -r '.[]._id')
    deleted=0
    # Deleting a case needs an org-admin (n8n's analyst profile can't): use a
    # temporary key of the bootstrap account, revoked on exit.
    if (( ${#cids[@]} > 0 )); then th_require_ready; th_org_key; fi
    for id in ${cids[@]+"${cids[@]}"}; do
      r=$(thehive_org DELETE "/api/v1/case/$id")
      if [[ $(http_code "$r") =~ ^20[04]$ ]]; then
        deleted=$((deleted + 1))
      else
        warn "case $id: could not delete it (HTTP $(http_code "$r")); delete it in the UI (tag $TEST_SOURCE)"
      fi
    done
    pass "deleted $deleted of ${#cids[@]} test case(s) (tag $TEST_SOURCE)"
  fi
  finish
  exit 0
fi

# ---- Scenarios: what Wazuh would have detected ----
# One line each: template, rule id, level, rule description, agent, MITRE
# technique (may be empty), observables (JSON). 203.0.113.66 is the seed IOC
# published in MISP (C7), so the MISP analyzer finds it when intel runs.
# Rule IDs, groups and fields as seen in live alerts (Wazuh 4.14.8) and
# Daniel's rule plan (W1.3): 1002xx Linux auth, 103xxx pfSense, 108xxx MISP
# IOC matches. portscan is a syslog alert: agent 000, so the host is the
# firewall's predecoder.hostname and its address the syslog sender (location).
# ioc / portscan rules don't exist yet (C14, W4.3); their IDs are placeholders
# in the right range.
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
    ids) printf '%s\n' ids-network-alert 86601 10 \
          "Suricata: Alert - ET SCAN Nmap Scripting Engine User-Agent Detected" \
          lab-agent T1046 \
          '[{"dataType":"ip","data":"198.51.100.23","tags":["src"],"message":"data.src_ip (scanner)"},{"dataType":"ip","data":"192.168.1.20","tags":["dst"],"message":"data.dest_ip, data.dest_port 80"},{"dataType":"user-agent","data":"Mozilla/5.00 (Nmap Scripting Engine)"},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    generic) printf '%s\n' wazuh-generic 31151 10 \
          "Multiple web server 400 error codes from same source ip." \
          lab-agent T1595 \
          '[{"dataType":"ip","data":"198.51.100.77","tags":["src"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    login) printf '%s\n' suspicious-login 40112 12 \
          "Multiple authentication failures followed by a success." \
          lab-agent T1078 \
          '[{"dataType":"ip","data":"203.0.113.66","tags":["src"]},{"dataType":"user-account","data":"admin","tags":["target"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    sudo) printf '%s\n' privilege-escalation 5404 10 \
          "Three failed attempts to run sudo." \
          lab-agent T1548.003 \
          '[{"dataType":"user-account","data":"labuser","tags":["src"],"message":"data.srcuser (ran sudo)"},{"dataType":"user-account","data":"root","tags":["target"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    newuser) printf '%s\n' account-change 5902 8 \
          "New user added to the system." \
          lab-agent T1136 \
          '[{"dataType":"user-account","data":"backup2","tags":["new"]},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    ioc) printf '%s\n' ioc-match 108001 12 \
          "IOC match: source IP found in MISP list misp-ip." \
          lab-agent "" \
          '[{"dataType":"ip","data":"203.0.113.66","tags":["src"],"message":"Seed IOC published in MISP","ioc":true},{"dataType":"hostname","data":"lab-agent","tags":["agent"]}]' ;;
    fwlogin) printf '%s\n' login-bruteforce 103011 10 \
          "OPNsense: multiple failed web GUI logins from the same source." \
          opnsense T1110 \
          '[{"dataType":"ip","data":"198.51.100.40","tags":["src"]},{"dataType":"user-account","data":"root","tags":["target"]},{"dataType":"ip","data":"10.99.0.1","tags":["agent"],"message":"location (syslog sender)"},{"dataType":"hostname","data":"opnsense","tags":["agent"],"message":"predecoder.hostname (syslog alert, agent 000)"}]' ;;
    portscan) printf '%s\n' network-scan 103010 10 \
          "pfSense: multiple blocked connections from the same source (port scan)." \
          pfsense T1046 \
          '[{"dataType":"ip","data":"198.51.100.23","tags":["src"]},{"dataType":"ip","data":"10.99.0.50","tags":["agent"],"message":"location (syslog sender)"},{"dataType":"hostname","data":"pfsense","tags":["agent"],"message":"predecoder.hostname (syslog alert, agent 000)"}]' ;;
  esac
}

# promote ALERT_ID TEMPLATE: promote the alert to a case as n8n would, then
# count the case's tasks (they come from the template).
promote() {
  local r case_id number tasks
  r=$(as_n8n POST "/api/v1/alert/$1/case" "$(jq -nc --arg t "$2" '{caseTemplate: $t}')")
  th_expect "promote alert $1" "$r" 200 201 || return 1
  case_id=$(http_body "$r" | jq -r '._id')
  number=$(http_body "$r" | jq -r '.number // "?"')
  r=$(as_n8n POST '/api/v1/query?name=testCaseTasks' \
      "$(jq -nc --arg id "$case_id" '{query: [{_name: "getCase", idOrName: $id}, {_name: "tasks"}]}')")
  th_expect "read tasks of case $case_id" "$r" 200 || return 1
  tasks=$(http_body "$r" | jq 'length')
  if (( tasks > 0 )); then
    pass "  promoted to case #$number with $tasks tasks from $2 (n8n's account can promote: X-15)"
  else
    fail "  case #$number has no tasks: template $2 wasn't applied"
  fi
}

for s in "${wanted[@]}"; do
  mapfile -t f < <(scenario "$s")
  template=${f[0]} rule=${f[1]} level=${f[2]} desc=${f[3]} agent=${f[4]} mitre=${f[5]} obs=${f[6]}
  now=$(date +%s)
  alert_id="$now.$RANDOM$RANDOM"
  severity=$(th_severity "$level" "$CRITICALITY")
  body=$(jq -nc \
    --arg src "$TEST_SOURCE" --arg ref "$alert_id" --arg tpl "$template" --arg desc "$desc" \
    --arg agent "$agent" --arg mitre "$mitre" --arg crit "$CRITICALITY" --arg tag "$TEST_SOURCE" \
    --argjson rule "$rule" --argjson level "$level" --argjson sev "$severity" \
    --argjson date "$((now * 1000))" --argjson obs "$obs" '{
      type: "wazuh", source: $src, sourceRef: $ref,
      title: "\($desc) (\($agent))",
      description: "**Test alert** created by thehive-test-alert.sh (not a real detection).\n\n| Field | Value |\n|---|---|\n| Wazuh rule | \($rule), level \($level) |\n| Description | \($desc) |\n| Agent | \($agent) |\n| MITRE ATT&CK | \(if $mitre == "" then "-" else $mitre end) |\n| Wazuh alert ID | \($ref) |",
      severity: $sev, tlp: 2, pap: 2, date: $date,
      tags: (["wazuh", $tag, "rule:\($rule)", "agent:\($agent)"] + (if $mitre == "" then [] else ["attack.\($mitre | ascii_downcase)"] end)),
      caseTemplate: $tpl,
      customFields: ([
        {name: "wazuh-alert-id", value: $ref},
        {name: "wazuh-rule-id", value: $rule},
        {name: "wazuh-rule-level", value: $level},
        {name: "wazuh-agent-name", value: $agent},
        {name: "asset-criticality", value: $crit},
        {name: "playbook", value: "manual-test"}
      ] + (if $mitre == "" then [] else [{name: "mitre-technique", value: $mitre}] end)),
      observables: $obs
    }')
  r=$(as_n8n POST /api/v1/alert "$body")
  if th_expect "$s: create alert" "$r" 200 201; then
    id=$(http_body "$r" | jq -r '._id')
    pass "$s: alert $id created (severity $severity, template $template) -> ${THEHIVE_API}/alerts"
    if (( PROMOTE )); then promote "$id" "$template" || true; fi
  fi
done

finish
