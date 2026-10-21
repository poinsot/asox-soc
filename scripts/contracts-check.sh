#!/usr/bin/env bash
# Check the integration contracts (PROJECT.md section 5): each one must
# connect and authenticate. Run on the machine hosting core (and lab), with
# the nodes the checked contracts need running (full mode for C1-C8, C10;
# core for C11; core and intel for C14).
#
# Usage: scripts/contracts-check.sh [--only C3,C4,C14,E2E]
#   checks: C1-C8, C10, C11, C14, E2E (default: all, in that order)
#   opt-in, only with --only: C1-RETRY (stops and starts n8n)
# One PASS/FAIL line per contract (and for E2E); exit code 1 if any contract fails.
# C3/C4 create a test alert in TheHive (source contract-check) and delete it;
# C1 deletes the TheHive alert n8n makes from its test alert (source asox-test).
# C10 prints SKIP (not a failure) when, in single-host mode, the intel node
# isn't running here (a mode without MISP, e.g. core or core-cases), and
# while its check workflow chk-misp-api is neither in n8n nor in
# nodes/core/n8n/workflows/ (not merged yet).
# C11 writes a test document (outcome contract-check) to asox-metrics through
# n8n and deletes it; it prints SKIP while its check workflow chk-metrics is
# neither in n8n nor in the repo (N8N-2.9).
# C14 looks inside the Wazuh manager (s6 service misp-sync, the three CDB
# lists, the seed IOC, the last sync's log line) and runs one synthetic sshd
# line from the seed IOC through wazuh-logtest (no alert, no side effects);
# SKIP when, in single-host mode, the intel node isn't running here, or when
# core's MISP_WAZUH_API_KEY is empty or a placeholder.
# E2E (after the contracts, not a contract; R-02) sends an sshd brute-force
# alert on the MISP seed IOC to n8n and expects the TheHive alert, the MISP
# verdict tag, the writeback and the asox-metrics document; it deletes what
# it created and prints SKIP unless core, cases and intel all run.
# C1-RETRY (opt-in; X-10, D51) stops the n8n container, fires C1's test event,
# starts n8n and expects the alert delivered once on a later try (custom-n8n.py's
# retries), one recv-wazuh-alert execution and one TheHive alert; it deletes
# the TheHive alert like C1 and always starts n8n again.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"
# shellcheck source=scripts/lib/cases.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/cases.sh"
# shellcheck source=scripts/lib/wazuh.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/wazuh.sh"

usage() { print_usage "$0"; }

ONLY=""
while (( $# > 0 )); do
  case $1 in
    --only) ONLY=${2:?--only needs a list, e.g. C3,C4 or E2E}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
ALL_CONTRACTS=(C1 C2 C3 C4 C5 C6 C7 C8 C10 C11 C14 E2E)
OPT_IN=(C1-RETRY)   # only with --only: they restart containers
if [[ -n $ONLY ]]; then
  IFS=',' read -r -a CONTRACTS <<<"${ONLY^^}"
  for c in "${CONTRACTS[@]}"; do
    [[ " ${ALL_CONTRACTS[*]} ${OPT_IN[*]} " == *" $c "* ]] || die "unknown check: $c (C1-C8, C10, C11, C14, E2E, C1-RETRY)"
  done
else
  CONTRACTS=("${ALL_CONTRACTS[@]}")
fi

CORE_ENV="$(node_dir core)/.env"   # core_env: lib/wazuh.sh
# Published on the core host; 127.0.0.1 works with either BIND_ADDR.
GRAFANA_URL=${GRAFANA_URL:-http://127.0.0.1:3000}
ALERT_TIMEOUT=${ALERT_TIMEOUT:-120}
EVENT_TIMEOUT=${EVENT_TIMEOUT:-60}
CASES_ENV="$(node_dir cases)/.env"
# TheHive's published port: on this machine in single-host mode, on
# CASES_HOST in distributed mode.
load_topology
if [[ $TOPO_DEPLOY_MODE == distributed ]]; then
  THEHIVE_API=http://$TOPO_CASES_HOST:9000
  CORTEX_API=http://$TOPO_CASES_HOST:9001
fi
# C7: the seed event (nodes/intel/misp/seed/) and its test IOC.
SEED_FILE="$REPO_ROOT/nodes/intel/misp/seed/seed-event.json"
C7_TIMEOUT=${C7_TIMEOUT:-180}

# ------------------------------------------------------------ test alert ---
# One test alert shared by the contracts that need it (C1, C8): fired through
# the lab agent, then waited for in the indexer. Sets TEST_EVENT_ID (the ID
# in the event) and TEST_ALERT_ID (the Wazuh alert id).
TEST_EVENT_ID="" TEST_ALERT_ID="" TEST_ALERT_ERROR=""
test_alert() {
  [[ -n $TEST_ALERT_ID ]] && return 0
  [[ -n $TEST_ALERT_ERROR ]] && return 1
  if ! TEST_EVENT_ID=$("$REPO_ROOT/nodes/lab/trigger.sh" 2>/dev/null); then
    TEST_ALERT_ERROR="could not fire the test event (is the lab node running?)"
    return 1
  fi
  local deadline=$(( SECONDS + ALERT_TIMEOUT )) out
  while (( SECONDS < deadline )); do
    if out=$("$REPO_ROOT/scripts/wazuh-query.sh" --rule 100100 --match "$TEST_EVENT_ID" --since 1h --json 2>/dev/null); then
      TEST_ALERT_ID=$(jq -r '.[0].id' <<<"$out")
      return 0
    fi
    sleep 3
  done
  TEST_ALERT_ERROR="test alert for event $TEST_EVENT_ID not indexed within ${ALERT_TIMEOUT}s"
  return 1
}

# <node>: true when, in single-host mode, <node> isn't running on this
# machine, i.e. the current run mode leaves it out (the rule of
# healthcheck.sh's target_absent). In distributed mode the node is on another
# machine and is always checked.
node_absent() {
  local node=$1
  [[ $TOPO_DEPLOY_MODE == single ]] || return 1
  [[ -f "$(node_dir "$node")/.env" \
    && -n $(compose "$node" ps --status running --services 2>/dev/null || true) ]] && return 1
  return 0
}

# ------------------------------------------------------------- contracts ---

# HTTP status of a POST to an n8n webhook; extra curl arguments follow.
webhook_status() {
  local path=$1; shift
  curl -s -o /dev/null -w '%{http_code}' -X POST "$N8N_URL/webhook/$path" \
    -H 'Content-Type: application/json' -d '{"contract_check": true}' "$@" || true
}

# n8n's pb-generic turns the C1 test alert into a TheHive alert (source
# asox-test, sourceRef = the Wazuh alert id). Delete it directly through
# TheHive's API with n8n's key; only alerts with source asox-test. Takes the
# alert id (default: C1's TEST_ALERT_ID). Never fails: without pb-generic, TheHive or the key, it prints an INFO line.
# Calls are bounded: an unreachable cases host must not stall the run.
c1_thehive() { _call -H "Authorization: Bearer $1" --max-time 10 -- "$2" "$THEHIVE_API$3" "${4:-}"; }
c1_thehive_cleanup() {
  local alert=${1:-$TEST_ALERT_ID} key q r ids deadline
  key=$(core_env THEHIVE_N8N_API_KEY)
  [[ -n $key ]] || { info "C1 cleanup: THEHIVE_N8N_API_KEY is empty, no TheHive alert to delete"; return 0; }
  # pb-generic runs after recv-wazuh-alert: wait for its alert only if n8n has it.
  deadline=$SECONDS
  [[ -n $(n8n_workflow_id_by_name pb-generic) ]] && deadline=$(( SECONDS + EVENT_TIMEOUT ))
  q=$(jq -nc --arg r "$alert" \
    '{query: [{_name: "listAlert"}, {_name: "filter", _field: "sourceRef", _value: $r}]}')
  while :; do
    r=$(c1_thehive "$key" POST /api/v1/query "$q")
    if [[ $(http_code "$r") != 200 ]]; then
      info "C1 cleanup: TheHive not reachable at $THEHIVE_API (HTTP $(http_code "$r")), nothing deleted"
      return 0
    fi
    ids=$(http_body "$r" | jq -r '.[]? | select(.source == "asox-test") | ._id')
    [[ -n $ids ]] && break
    if (( SECONDS >= deadline )); then
      info "C1 cleanup: no TheHive alert with source asox-test and sourceRef $alert (pb-generic not merged, or TheHive disabled)"
      return 0
    fi
    sleep 3
  done
  local id
  while IFS= read -r id; do
    r=$(c1_thehive "$key" DELETE "/api/v1/alert/$id")
    if [[ $(http_code "$r") == 204 ]]; then
      info "C1 cleanup: deleted TheHive test alert $id (sourceRef $alert)"
    else
      warn "C1 cleanup: deleting TheHive test alert $id returned HTTP $(http_code "$r"); delete it by hand"
    fi
  done <<<"$ids"
}

check_C1() {
  local c="C1 Wazuh -> n8n"
  # The webhook must refuse requests without the shared token, or with a wrong one.
  local no_token wrong_token
  no_token=$(webhook_status wazuh-alert)
  wrong_token=$(webhook_status wazuh-alert -H "X-ASOX-Token: wrong-$RANDOM")
  if [[ $no_token != 40[13] || $wrong_token != 40[13] ]]; then
    fail "$c: webhook must reject requests without a valid token (no token: HTTP $no_token, wrong token: HTTP $wrong_token)"
    return
  fi
  test_alert || { fail "$c: $TEST_ALERT_ERROR"; return; }
  n8n_api_ok || { fail "$c: n8n API not reachable with N8N_API_KEY (run scripts/bootstrap.sh core)"; return; }
  local wf_id deadline=$(( SECONDS + ALERT_TIMEOUT )) e
  wf_id=$(n8n_workflow_id_by_name recv-wazuh-alert)
  [[ -n $wf_id ]] || { fail "$c: workflow recv-wazuh-alert not found in n8n"; return; }
  while (( SECONDS < deadline )); do
    e=$(n8n_api GET "/executions?workflowId=$wf_id&limit=50&includeData=true" \
      | jq -r --arg a "$TEST_ALERT_ID" '[.data[]? | select(tostring | contains($a)) | .id] | first // empty')
    if [[ -n $e ]]; then
      pass "$c: alert $TEST_ALERT_ID recorded by recv-wazuh-alert (execution $e); requests without a valid token rejected (HTTP $no_token/$wrong_token)"
      c1_thehive_cleanup
      return
    fi
    sleep 3
  done
  fail "$c: no recv-wazuh-alert execution with alert $TEST_ALERT_ID within ${ALERT_TIMEOUT}s (see /var/ossec/logs/integrations.log in the manager)"
}

# C1-RETRY (opt-in, X-10, D51): C1's retries end to end. Not in the default
# run, because it stops and starts the n8n container. Tests the contract
# across the real manager, integratord and n8n; the Wazuh owner's
# nodes/core/wazuh/tests/c1-retry.sh tests custom-n8n.py's retry rules against
# a stub server. Steps: stop n8n; fire C1's test event (nodes/lab/trigger.sh);
# once the alert is in the manager's alerts.json (so integratord has it),
# start n8n; then within C1R_TIMEOUT: exactly one recv-wazuh-alert execution
# with that alert id, exactly one TheHive alert with it as sourceRef (source
# asox-test, from pb-generic), and "alert <id>: delivered on try N" (N > 1)
# in integrations.log. Cleans up like C1. n8n is started again whatever
# happens (EXIT trap). SKIP while custom-n8n.py's fast-fail mark is fresh:
# the alert would get one try only.
C1R_TIMEOUT=${C1R_TIMEOUT:-120}
C1R_MARK=/var/ossec/var/run/custom-n8n.down
C1R_LOG=/var/ossec/logs/integrations.log
C1R_FAST_FAIL=300   # custom-n8n.py FAST_FAIL_SECONDS
C1R_N8N="" C1R_STOPPED=""
c1r_n8n_start() {
  [[ -n $C1R_STOPPED ]] || return 0
  C1R_STOPPED=""
  docker start "$C1R_N8N" >/dev/null 2>&1 || warn "C1-RETRY: could not start $C1R_N8N; start it by hand (scripts/soc.sh up core)"
}
# recv-wazuh-alert executions whose data contains <alert id>; empty while
# n8n's API doesn't answer.
c1r_executions() {
  n8n_api GET "/executions?workflowId=$1&limit=100&includeData=true" 2>/dev/null \
    | jq -r --arg a "$2" '[.data[]? | select(tostring | contains($a)) | .id] | join(" ")' 2>/dev/null || true
}
c1r_thehive_alerts() {
  local q r
  q=$(jq -nc --arg r "$1" '{query: [{_name: "listAlert"}, {_name: "filter", _field: "sourceRef", _value: $r}]}')
  r=$(c1_thehive "$(core_env THEHIVE_N8N_API_KEY)" POST /api/v1/query "$q")
  [[ $(http_code "$r") == 200 ]] || return 0
  http_body "$r" | jq -r '[.[]? | select(.source == "asox-test") | ._id] | join(" ")'
}
check_C1-RETRY() {
  local c="C1-RETRY Wazuh -> n8n retries" manager mark retries event alert="" line="" t0 t_up \
    deadline execs="" th="" tries="" n_e n_t
  manager="$TOPO_SOC_INSTANCE-core-wazuh-manager-1"
  C1R_N8N="$TOPO_SOC_INSTANCE-core-n8n-1"
  if [[ $(docker inspect -f '{{.State.Running}}' "$manager" 2>/dev/null || true) != true ]]; then
    fail "$c: manager container $manager is not running (scripts/soc.sh up core)"; return
  fi
  if [[ $(docker inspect -f '{{.State.Running}}' "$C1R_N8N" 2>/dev/null || true) != true ]]; then
    fail "$c: n8n container $C1R_N8N is not running (scripts/soc.sh up core)"; return
  fi
  n8n_api_ok || { fail "$c: n8n API not reachable with N8N_API_KEY (run scripts/bootstrap.sh core)"; return; }
  local wf_id
  wf_id=$(n8n_workflow_id_by_name recv-wazuh-alert)
  [[ -n $wf_id ]] || { fail "$c: workflow recv-wazuh-alert not found in n8n"; return; }
  # Only the <retries> value; the integration block also holds the token.
  retries=$(docker exec "$manager" sed -n '/<name>custom-n8n</,/<\/integration>/s/.*<retries>\([0-9]*\)<\/retries>.*/\1/p' /var/ossec/etc/ossec.conf 2>/dev/null | head -n 1 || true)
  if [[ -z $retries || $retries == 0 ]]; then
    fail "$c: the custom-n8n integration has no <retries> in the manager's ossec.conf (20-n8n-integration.sh, X-10)"; return
  fi
  mark=$(docker exec "$manager" sh -c "[ -f $C1R_MARK ] && echo \$(( \$(date +%s) - \$(stat -c %Y $C1R_MARK) ))" 2>/dev/null || true)
  if [[ -n $mark ]] && (( mark < C1R_FAST_FAIL )); then
    skip "$c: custom-n8n.py's fast-fail mark is ${mark}s old (one try per alert for ${C1R_FAST_FAIL}s after a failed chain); run again in $(( C1R_FAST_FAIL - mark ))s"
    return
  fi

  t0=$SECONDS
  C1R_STOPPED=1
  if ! docker stop "$C1R_N8N" >/dev/null 2>&1; then
    C1R_STOPPED=""; fail "$c: could not stop $C1R_N8N"; return
  fi
  if ! event=$("$REPO_ROOT/nodes/lab/trigger.sh" 2>/dev/null); then
    c1r_n8n_start; fail "$c: could not fire the test event (is the lab node running?)"; return
  fi
  # The alert in alerts.json means integratord has it and its first try fails.
  deadline=$(( SECONDS + 30 ))
  while (( SECONDS < deadline )); do
    alert=$(docker exec "$manager" grep -F "$event" /var/ossec/logs/alerts/alerts.json 2>/dev/null \
      | jq -r 'select(.rule.id == "100100") | .id' 2>/dev/null | tail -n 1 || true)
    [[ -n $alert ]] && break
    sleep 1
  done
  t_up=$SECONDS
  c1r_n8n_start
  [[ -n $alert ]] || { fail "$c: test event $event not in the manager's alerts.json within 30s"; return; }
  info "$c: n8n stopped $(( t_up - t0 ))s; alert $alert written while it was down; n8n started"

  # Until the delivery is logged and n8n and TheHive show it.
  deadline=$(( t_up + C1R_TIMEOUT ))
  while (( SECONDS < deadline )); do
    [[ -z $line ]] && line=$(docker exec "$manager" grep -F "alert $alert:" "$C1R_LOG" 2>/dev/null | tail -n 1 || true)
    if [[ -n $line && $line != *'delivered'* ]]; then
      break   # a final failure: no delivery will follow
    fi
    if [[ -n $line ]]; then
      execs=$(c1r_executions "$wf_id" "$alert")
      th=$(c1r_thehive_alerts "$alert")
      [[ -n $execs && -n $th ]] && break
    fi
    sleep 3
  done
  tries=$(sed -n 's/.*delivered on try \([0-9]*\).*/\1/p' <<<"$line")
  read -r -a n_e <<<"$execs"; read -r -a n_t <<<"$th"
  if [[ -z $line ]]; then
    fail "$c: no integrations.log line for alert $alert within ${C1R_TIMEOUT}s after n8n's start"
  elif [[ -z $tries ]]; then
    line=${line#* custom-n8n: }
    fail "$c: no delivery on a retry: ${line:0:300}"
  elif (( tries < 2 )); then
    fail "$c: alert $alert delivered on try $tries, expected a retry (n8n was down)"
  elif (( ${#n_e[@]} != 1 || ${#n_t[@]} != 1 )); then
    fail "$c: alert $alert delivered on try $tries, but ${#n_e[@]} recv-wazuh-alert execution(s) (${execs:-none}) and ${#n_t[@]} TheHive alert(s) (${th:-none}); expected one each"
  else
    pass "$c: alert $alert delivered on try $tries, $(( SECONDS - t_up ))s after n8n's start ($(( SECONDS - t0 ))s after the stop); one recv-wazuh-alert execution (${n_e[0]}), one TheHive alert (${n_t[0]})"
  fi
  c1_thehive_cleanup "$alert"
}

check_C2() {
  local c="C2 n8n -> Wazuh API" resp
  resp=$(curl -s -X POST "$N8N_URL/webhook/chk-wazuh-api" -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" || true)
  if ! jq -e '.authenticated == true' >/dev/null 2>&1 <<<"$resp"; then
    fail "$c: check workflow chk-wazuh-api failed (active? credential?): ${resp:0:200}"
    return
  fi
  if [[ $(jq -r '.active_response_status' <<<"$resp") != 403 ]]; then
    fail "$c: active response was NOT rejected (HTTP $(jq -r '.active_response_status' <<<"$resp")): the n8n-api role is not read-only"
    return
  fi
  pass "$c: credential logs in and lists $(jq -r '.agents' <<<"$resp") agents; active response rejected (HTTP 403)"
}

# ------------------------------------------------------ TheHive test alert ---
# One test alert shared by C3 and C4, created through n8n's TheHive
# credential (check workflow chk-thehive-api) and deleted the same way.
# TheHive sends its webhook asynchronously, so C4's execution is looked for
# before the alert is deleted.
TH_ALERT_ID="" TH_ALERT_BY="" TH_ALERT_ERROR="" TH_EVENT_EXEC="" TH_EVENT_ERROR=""

chk_thehive() {
  curl -s -X POST "$N8N_URL/webhook/chk-thehive-api" -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" \
    -H 'Content-Type: application/json' -d "$1" || true
}

# Create the alert (source contract-check) and read it back.
thehive_test_alert() {
  [[ -n $TH_ALERT_ID ]] && return 0
  [[ -n $TH_ALERT_ERROR ]] && return 1
  local ref resp
  ref="contract-check-$(date +%s)-$RANDOM"
  resp=$(chk_thehive "$(jq -nc --arg r "$ref" '{step: "create", sourceRef: $r}')")
  if ! jq -e --arg r "$ref" '.id != null and .source == "contract-check" and .sourceRef == $r' >/dev/null 2>&1 <<<"$resp"; then
    TH_ALERT_ERROR="check workflow chk-thehive-api could not create and read back a test alert (active? credential? cases node running?): ${resp:0:200}"
    return 1
  fi
  TH_ALERT_ID=$(jq -r '.id' <<<"$resp")
  TH_ALERT_BY=$(jq -r '.createdBy' <<<"$resp")
}

# Wait for the recv-thehive-event execution carrying the test alert's ID.
thehive_event_wait() {
  [[ -n $TH_EVENT_EXEC || -n $TH_EVENT_ERROR ]] && return 0
  local wf_id e deadline=$(( SECONDS + EVENT_TIMEOUT ))
  if ! n8n_api_ok; then TH_EVENT_ERROR="n8n API not reachable with N8N_API_KEY (run scripts/bootstrap.sh core)"; return 0; fi
  wf_id=$(n8n_workflow_id_by_name recv-thehive-event)
  [[ -n $wf_id ]] || { TH_EVENT_ERROR="workflow recv-thehive-event not found in n8n"; return 0; }
  while (( SECONDS < deadline )); do
    e=$(n8n_api GET "/executions?workflowId=$wf_id&limit=50&includeData=true" \
      | jq -r --arg a "$TH_ALERT_ID" '[.data[]? | select(tostring | contains($a)) | .id] | first // empty')
    [[ -n $e ]] && { TH_EVENT_EXEC=$e; return 0; }
    sleep 3
  done
  TH_EVENT_ERROR="no recv-thehive-event execution for alert $TH_ALERT_ID within ${EVENT_TIMEOUT}s (TheHive webhook: scripts/bootstrap.sh cases; license: scripts/soc.sh info cases; TheHive logs)"
}

# Delete the test alert through n8n; sets TH_DELETE_STATUS to the HTTP
# status TheHive returned.
TH_DELETE_STATUS=""
thehive_test_alert_delete() {
  [[ -n $TH_ALERT_ID ]] || return 0
  TH_DELETE_STATUS=$(chk_thehive "$(jq -nc --arg i "$TH_ALERT_ID" '{step: "delete", id: $i}')"     | jq -r '.deleted_status // "none"' 2>/dev/null || true)
  TH_ALERT_ID=""
}

check_C3() {
  local c="C3 n8n -> TheHive" id by
  thehive_test_alert || { fail "$c: $TH_ALERT_ERROR"; return; }
  id=$TH_ALERT_ID by=$TH_ALERT_BY
  [[ " ${CONTRACTS[*]} " == *" C4 "* ]] && thehive_event_wait
  thehive_test_alert_delete
  if [[ $TH_DELETE_STATUS != 204 ]]; then
    fail "$c: test alert $id created and read back, but deleting it returned ${TH_DELETE_STATUS:-nothing}"
    return
  fi
  pass "$c: test alert $id created (as $by), read back and deleted through n8n's credential"
}

check_C4() {
  local c="C4 TheHive -> n8n" no_token wrong_token
  # TheHive sends the token as "Authorization: Bearer <token>" (A64).
  no_token=$(webhook_status thehive-event)
  wrong_token=$(webhook_status thehive-event -H "Authorization: Bearer wrong-$RANDOM")
  if [[ $no_token != 40[13] || $wrong_token != 40[13] ]]; then
    fail "$c: webhook must reject requests without a valid token (no token: HTTP $no_token, wrong token: HTTP $wrong_token)"
    return
  fi
  if [[ -z $TH_EVENT_EXEC && -z $TH_EVENT_ERROR ]]; then
    # Not run together with C3: create (and delete) a test alert here.
    thehive_test_alert || { fail "$c: $TH_ALERT_ERROR"; return; }
    thehive_event_wait
    thehive_test_alert_delete
  fi
  if [[ -n $TH_EVENT_EXEC ]]; then
    pass "$c: creating the test alert produced execution $TH_EVENT_EXEC of recv-thehive-event; requests without a valid token rejected (HTTP $no_token/$wrong_token)"
  else
    fail "$c: $TH_EVENT_ERROR"
  fi
}

check_C6() {
  local c="C6 n8n -> Cortex" resp
  resp=$(curl -s -X POST "$N8N_URL/webhook/chk-cortex-api" -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" || true)
  if ! jq -e '.status == 200' >/dev/null 2>&1 <<<"$resp"; then
    fail "$c: check workflow chk-cortex-api failed (active? credential? Cortex running?): ${resp:0:200}"
    return
  fi
  pass "$c: credential lists the enabled analyzers: $(jq -r '.analyzers | if length == 0 then "none enabled yet" else join(", ") end' <<<"$resp")"
}

check_C5() {
  local c="C5 TheHive -> Cortex" r status servers analyzers
  [[ -f $CASES_ENV ]] || { fail "$c: nodes/cases/.env not found (the cases node's logins are needed)"; return; }
  r=$(thehive_admin GET /api/v1/status)
  if [[ $(http_code "$r") != 200 ]]; then
    fail "$c: TheHive status not available at $THEHIVE_API (HTTP $(http_code "$r"))"; return
  fi
  status=$(http_body "$r" | jq -r '.connectors.cortex.status // "missing"')
  servers=$(http_body "$r" | jq -r '[.connectors.cortex.servers[]? | "\(.name) \(.version) \(.status)"] | join(", ")')
  if [[ $status != OK ]]; then
    fail "$c: Cortex connector status $status (servers: ${servers:-none}); run scripts/bootstrap.sh cases"; return
  fi
  # Analyzers enabled in Cortex, as TheHive's analysts see them.
  r=$(thehive_as "$(cases_env THEHIVE_ANALYST_USER)" "$(cases_env THEHIVE_ANALYST_PASSWORD)" GET /api/connector/cortex/analyzer)
  if [[ $(http_code "$r") != 200 ]]; then
    fail "$c: analyzer list refused (HTTP $(http_code "$r"))"; return
  fi
  analyzers=$(http_body "$r" | jq -r '[.[].name] | if length == 0 then "none enabled yet" else join(", ") end')
  pass "$c: connected ($servers); analyzers: $analyzers"
}

check_C7() {
  local c="C7 Cortex -> MISP" r aid jid info ioc status found
  [[ -f $CASES_ENV ]] || { fail "$c: nodes/cases/.env not found (the cases node's logins are needed)"; return; }
  info=$(jq -r '.Event.info' "$SEED_FILE")
  ioc=$(jq -r '.Event.Attribute[0].value' "$SEED_FILE")
  r=$(cortex_orgadmin GET /api/analyzer)
  aid=$(http_body "$r" | jq -r '[.[]? | select(.workerDefinitionId | startswith("MISP_")) | .id] | first // empty')
  [[ -n $aid ]] || { fail "$c: MISP analyzer not enabled in Cortex (run scripts/bootstrap.sh intel, then cases)"; return; }
  r=$(cortex_orgadmin POST "/api/analyzer/$aid/run" "$(jq -nc --arg d "$ioc" '{data: $d, dataType: "ip", tlp: 0, pap: 0, force: true}')")
  jid=$(http_body "$r" | jq -r '.id // empty')
  [[ -n $jid ]] || { fail "$c: Cortex refused the job (HTTP $(http_code "$r"))"; return; }
  # force: a new job (and container) even if a cached report exists;
  # waitreport returns when the analyzer container has exited.
  r=$(cortex_orgadmin GET "/api/job/$jid/waitreport?atMost=${C7_TIMEOUT}seconds")
  status=$(http_body "$r" | jq -r '.status // "unknown"')
  if [[ $status != Success ]]; then
    # The error's last line is the analyzer's own message (earlier lines are
    # often Python warnings).
    fail "$c: analyzer job $jid on $ioc: $status: $(http_body "$r" | jq -r '.errorMessage // "" | split("\n") | map(select(length > 0)) | last // ""' | cut -c1-200)"
    return
  fi
  found=$(http_body "$r" | jq -r --arg i "$info" '[.report.full.results[]?.result[]? | select(.info == $i) | .id] | first // empty')
  if [[ -n $found ]]; then
    pass "$c: MISP analyzer job on $ioc finds the seed event (MISP event $found)"
  else
    fail "$c: analyzer job $jid succeeded but its report doesn't contain the seed event \"$info\" (bootstrap intel creates it)"
  fi
}

# C10: through n8n's own credential "MISP API (n8n)", by the check workflow
# chk-misp-api (n8n's, like C2's and C6's): 8.8.8.8 must be on a public DNS
# resolver warninglist, and a write (POST /events/add) must be refused.
# There is no direct call to MISP from here: misp-config.sh apply already
# checks the key itself, and C10 is about n8n's side. Until chk-misp-api
# exists the contract can't be checked: SKIP while n8n has no workflow of
# that name and the repo has no file for it; once the file is in the repo
# (the n8n branch merged) a missing workflow is a failure. MISP not being
# part of the running setup (single-host mode, intel node not running) is a
# SKIP too (R-29); with intel running, a failing check is a failure.
C10_WORKFLOW=chk-misp-api
C10_VALUE=8.8.8.8
check_C10() {
  local c="C10 n8n -> MISP" resp status hit write
  if node_absent intel; then
    skip "$c: not checked: node intel not running (not part of this mode)"
    return
  fi
  n8n_api_ok || { fail "$c: n8n API not reachable with N8N_API_KEY (run scripts/bootstrap.sh core)"; return; }
  if [[ -z $(n8n_workflow_id_by_name "$C10_WORKFLOW") ]]; then
    if [[ -f $N8N_WORKFLOW_DIR/$C10_WORKFLOW.json ]]; then
      fail "$c: check workflow $C10_WORKFLOW is in nodes/core/n8n/workflows/ but not in n8n (run scripts/n8n-import.sh)"
    else
      skip "$c: not checked: check workflow $C10_WORKFLOW doesn't exist yet (neither in n8n nor in nodes/core/n8n/workflows/; it comes with the n8n branch, N8N-2.11)"
    fi
    return
  fi
  resp=$(curl -s -X POST "$N8N_URL/webhook/$C10_WORKFLOW" -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" || true)
  status=$(jq -r '.status // empty' <<<"$resp" 2>/dev/null || true)
  if [[ $status != 200 ]]; then
    fail "$c: check workflow $C10_WORKFLOW failed (active? credential \"MISP API (n8n)\"? MISP running? MISP_URL in n8n's environment?): ${resp:0:200}"
    return
  fi
  hit=$(jq -r '[.matches[]? | select(test("public dns"; "i"))] | first // empty' <<<"$resp" 2>/dev/null || true)
  if [[ -z $hit ]]; then
    fail "$c: $C10_VALUE is on no public DNS warninglist (matches: $(jq -c '.matches // []' <<<"$resp" 2>/dev/null | cut -c1-160)); run scripts/bootstrap.sh intel"
    return
  fi
  write=$(jq -r '.write_status // empty' <<<"$resp" 2>/dev/null || true)
  if [[ $write != 403 ]]; then
    fail "$c: a write (POST /events/add) was NOT refused (HTTP ${write:-none}): n8n's MISP user is not read-only"
    return
  fi
  pass "$c: credential checks $C10_VALUE against the warninglists (\"$hit\"); a write is refused (HTTP 403)"
}

# C11: n8n writes asox-metrics as n8n-indexer (its credential "Wazuh indexer
# (n8n-indexer)") through its check workflow chk-metrics, Grafana reads it as
# grafana-ro. chk-metrics takes {step: "write", id} (upserts document <id>
# with outcome contract-check and t_event / t_alert = now; answers
# {status: <indexer HTTP status>, id}) and {step: "delete", id} (answers
# {deleted_status: <indexer HTTP status>}), like chk-thehive-api. The read
# goes through Grafana's datasource asox-metrics (GRAF-0.8) when it is
# provisioned, else as grafana-ro straight to the indexer (said in the
# result). A write as grafana-ro must get 403. SKIP while chk-metrics is
# neither in n8n nor in the repo, as for C10.
C11_WORKFLOW=chk-metrics
C11_DS=asox-metrics
C11_TIMEOUT=${C11_TIMEOUT:-20}
C11_DOC_ID=""
c11_chk() {
  curl -s --max-time 30 -X POST "$N8N_URL/webhook/$C11_WORKFLOW" -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" \
    -H 'Content-Type: application/json' -d "$1" || true
}
c11_gro() { indexer_as "$(core_env GRAFANA_INDEXER_USER)" "$(core_env GRAFANA_INDEXER_PASSWORD)" "$@"; }
C11_DELETE_STATUS=""
c11_doc_delete() {
  [[ -n $C11_DOC_ID ]] || return 0
  C11_DELETE_STATUS=$(c11_chk "$(jq -nc --arg i "$C11_DOC_ID" '{step: "delete", id: $i}')" \
    | jq -r '.deleted_status // "none"' 2>/dev/null || true)
  C11_DOC_ID=""
}
# True when Grafana's query (datasource asox-metrics) returns document <id>.
c11_grafana_has() {
  local auth body
  auth="$(core_env GRAFANA_ADMIN_USER):$(core_env GRAFANA_ADMIN_PASSWORD)"
  body=$(jq -nc --arg q "outcome:contract-check AND alert_id:\"$1\"" --arg ds "$C11_DS" '{
    from: "now-1h", to: "now+5m",
    queries: [{refId: "A", datasource: {uid: $ds}, queryType: "lucene", query: $q,
               timeField: "t_alert", metrics: [{id: "1", type: "raw_data", settings: {size: "10"}}], bucketAggs: []}]}')
  curl -s -u "$auth" -H 'Content-Type: application/json' "$GRAFANA_URL/api/ds/query" -d "$body" \
    | jq -e --arg id "$1" '[.results.A.frames[]?.data.values[]?[]?] | any(. == $id)' >/dev/null 2>&1
}
# The same as grafana-ro, straight to the indexer.
c11_indexer_has() {
  local q
  q=$(jq -nc --arg id "$1" '{query: {bool: {filter: [{term: {alert_id: $id}}, {term: {outcome: "contract-check"}}]}}}')
  http_body "$(c11_gro POST "/$ASOX_METRICS_INDEX/_search" "$q")" \
    | jq -e --arg id "$1" '[.hits.hits[]?._id] | index($id) != null' >/dev/null 2>&1
}
check_C11() {
  local c="C11 n8n -> indexer -> Grafana" id resp status via finder deadline found="" ro
  n8n_api_ok || { fail "$c: n8n API not reachable with N8N_API_KEY (run scripts/bootstrap.sh core)"; return; }
  if [[ -z $(n8n_workflow_id_by_name "$C11_WORKFLOW") ]]; then
    if [[ -f $N8N_WORKFLOW_DIR/$C11_WORKFLOW.json ]]; then
      fail "$c: check workflow $C11_WORKFLOW is in nodes/core/n8n/workflows/ but not in n8n (run scripts/n8n-import.sh)"
    else
      skip "$c: not checked: check workflow $C11_WORKFLOW doesn't exist yet (neither in n8n nor in nodes/core/n8n/workflows/; it comes with the n8n branch, N8N-2.9)"
    fi
    return
  fi
  id="contract-check-$(date +%s)-$RANDOM"
  resp=$(c11_chk "$(jq -nc --arg i "$id" '{step: "write", id: $i}')")
  status=$(jq -r '.status // empty' <<<"$resp" 2>/dev/null || true)
  if [[ $status != 20[01] ]]; then
    fail "$c: check workflow $C11_WORKFLOW could not write test document $id (active? credential \"Wazuh indexer (n8n-indexer)\"? root CA in n8n, NODE_EXTRA_CA_CERTS?): ${resp:0:200}"
    return
  fi
  C11_DOC_ID=$id
  if [[ $(curl -s -o /dev/null -w '%{http_code}' -u "$(core_env GRAFANA_ADMIN_USER):$(core_env GRAFANA_ADMIN_PASSWORD)" \
          "$GRAFANA_URL/api/datasources/uid/$C11_DS" || true) == 200 ]]; then
    via="by Grafana's datasource $C11_DS" finder=c11_grafana_has
  else
    via="as grafana-ro directly (Grafana's datasource $C11_DS isn't provisioned yet, GRAF-0.8)" finder=c11_indexer_has
  fi
  deadline=$(( SECONDS + C11_TIMEOUT ))
  while (( SECONDS < deadline )); do
    "$finder" "$id" && { found=1; break; }
    sleep 2
  done
  ro=$(http_code "$(c11_gro PUT "/$ASOX_METRICS_INDEX/_doc/$id-ro" '{"outcome": "contract-check"}')")
  c11_doc_delete
  if [[ -z $found ]]; then
    fail "$c: test document $id written, but not read back $via within ${C11_TIMEOUT}s"
  elif [[ $ro != 403 ]]; then
    [[ $ro == 20[01] ]] && indexer_api DELETE "/$ASOX_METRICS_INDEX/_doc/$id-ro" >/dev/null
    fail "$c: a write as grafana-ro was NOT refused (HTTP $ro): grafana-ro is not read-only"
  elif [[ $C11_DELETE_STATUS != 200 ]]; then
    fail "$c: test document $id written and read back, but deleting it through $C11_WORKFLOW returned ${C11_DELETE_STATUS:-nothing}"
  elif [[ $(http_code "$(c11_gro GET "/$ASOX_METRICS_INDEX/_doc/$id")") != 404 ]]; then
    fail "$c: test document $id is still in $ASOX_METRICS_INDEX after its delete"
  else
    pass "$c: test document $id (outcome contract-check) written as n8n-indexer, read back $via and deleted; a write as grafana-ro is refused (HTTP 403)"
  fi
}

# C14: MISP -> Wazuh CDB lists (D50). The Wazuh owner's misp-sync runs inside
# the manager (nodes/core/wazuh/lists/, README "MISP IOCs as CDB lists"), so
# everything is read inside the manager container, with no side effects:
# (a) the s6 service misp-sync is supervised (40-misp-sync.sh installs it
# only when the manager has a MISP URL and key); (b) the three lists exist,
# misp-ip isn't empty and holds the seed IOC (read from seed-event.json, as
# C7); (c) the manager log's last "misp-sync:" line isn't an error; (d) one
# synthetic sshd failure line from the seed IOC through wazuh-logtest gives
# rule 108000 (logtest raises no alert: no TheHive alert, and rule 108000's
# 60 s ignore window isn't touched). Not a live trigger (A100). SKIP (R-29's
# rule) when, in single-host mode, intel isn't running here, or when core's
# MISP_WAZUH_API_KEY is empty or a placeholder (no intel bootstrapped for this
# core: C14 is off by design).
C14_LISTS=/var/ossec/etc/lists/misp
C14_RULE=108000
c14_exec() { docker exec "$C14_MANAGER" "$@"; }
check_C14() {
  local c="C14 MISP -> Wazuh CDB lists" key ioc procs counts l n ip dom hash seed logs last sync ts results rule
  C14_MANAGER="$TOPO_SOC_INSTANCE-core-wazuh-manager-1"
  if node_absent intel; then
    skip "$c: not checked: node intel not running (not part of this mode)"
    return
  fi
  key=$(core_env MISP_WAZUH_API_KEY)
  if [[ -z $key || $key == __*__ || $key == '<'*'>' ]]; then
    skip "$c: not checked: MISP_WAZUH_API_KEY in nodes/core/.env is empty or a placeholder (C14 is off until scripts/bootstrap.sh intel and scripts/render-env.sh give core the key, R-08)"
    return
  fi
  ioc=$(jq -r '.Event.Attribute[0].value // empty' "$SEED_FILE" 2>/dev/null || true)
  [[ -n $ioc ]] || { fail "$c: no seed IOC in $SEED_FILE"; return; }
  if [[ $(docker inspect -f '{{.State.Running}}' "$C14_MANAGER" 2>/dev/null || true) != true ]]; then
    fail "$c: manager container $C14_MANAGER is not running (scripts/soc.sh up core)"
    return
  fi
  # (a) Captured first, then matched: grep -q on a pipe can fail on SIGPIPE.
  procs=$(c14_exec ps -eo args 2>/dev/null || true)
  if ! grep -qx 's6-supervise misp-sync' <<<"$procs"; then
    fail "$c: s6 service misp-sync is not supervised in $C14_MANAGER: C14 is off in the manager (WAZUH_MISP_URL or WAZUH_MISP_API_KEY empty in its environment? docker logs $C14_MANAGER | grep misp-sync)"
    return
  fi
  # (b) Entries per list; "missing" when a list file doesn't exist.
  counts=$(c14_exec sh -c "for l in misp-ip misp-domain misp-hash; do if [ -f $C14_LISTS/\$l ]; then echo \"\$l \$(grep -c . $C14_LISTS/\$l)\"; else echo \"\$l missing\"; fi; done" 2>/dev/null || true)
  ip="" dom="" hash=""
  while read -r l n; do
    case $l in misp-ip) ip=$n ;; misp-domain) dom=$n ;; misp-hash) hash=$n ;; esac
  done <<<"$counts"
  if [[ -z $ip || -z $dom || -z $hash || $ip$dom$hash == *missing* ]]; then
    fail "$c: list file(s) missing in $C14_LISTS (misp-ip ${ip:-?}, misp-domain ${dom:-?}, misp-hash ${hash:-?}); 40-misp-sync.sh creates them at every manager start"
    return
  fi
  if [[ $ip == 0 ]]; then
    fail "$c: lists empty although MISP_WAZUH_API_KEY is set (misp-ip 0, misp-domain $dom, misp-hash $hash): first sync failed at start (e.g. core started before intel); wait for the quick retries (every 60 s, up to 10) or restart the manager once intel is healthy (R-34)"
    return
  fi
  seed=$(c14_exec cat "$C14_LISTS/misp-ip" 2>/dev/null | awk -F: -v v="$ioc" '$1 == v { print; exit }' || true)
  if [[ -z $seed ]]; then
    fail "$c: seed IOC $ioc is not in misp-ip ($ip entries): seed event not published with to_ids, or on a warninglist (scripts/bootstrap.sh intel checks both), or not synced yet (next interval)"
    return
  fi
  # (c) The last misp-sync line, and the last completed sync (its counts).
  logs=$(docker logs "$C14_MANAGER" 2>&1 | grep 'misp-sync:' || true)
  last=$(tail -n 1 <<<"$logs")
  sync=$(grep ' attribute(s) -> ' <<<"$logs" | tail -n 1 || true)
  if [[ -z $last ]]; then
    fail "$c: no misp-sync line in $C14_MANAGER's log"
    return
  fi
  if [[ $last == *ERROR* || $last == *'first sync failed'* || $last == *'C14 off'* ]]; then
    fail "$c: the last sync failed: ${last:0:200}; wait for the quick retries (every 60 s, up to 10) or restart the manager once intel is healthy (R-34)"
    return
  fi
  [[ $last == *WARNING* ]] && warn "$c: last misp-sync line: ${last:0:200}"
  ts=${sync:0:19} sync=${sync#* misp-sync: } sync=${sync%%;*}
  # (d) One sshd failure from the seed IOC through wazuh-logtest. The result
  # lines are wazuh-logtest's own (tests/run.sh parses the same ones).
  results=$(printf '%s contracts-check sshd[4242]: Failed password for invalid user c14-check from %s port 42001 ssh2\n' \
      "$(LC_ALL=C date '+%b %e %H:%M:%S')" "$ioc" \
    | docker exec -i "$C14_MANAGER" /var/ossec/bin/wazuh-logtest 2>&1 || true)
  rule=$(sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" <<<"$results" | tail -n 1)
  if [[ $rule != "$C14_RULE" ]]; then
    fail "$c: wazuh-logtest: an sshd failure from $ioc gave rule ${rule:-none}, expected $C14_RULE (rules/1080-misp-ioc.xml in the manager? misp-ip.cdb rebuilt?)"
    return
  fi
  pass "$c: s6 service misp-sync supervised; lists misp-ip $ip / misp-domain $dom / misp-hash $hash; seed IOC $ioc in misp-ip ($seed); last sync ${ts:-?}: ${sync:-?}; wazuh-logtest: sshd failure from $ioc -> rule $C14_RULE"
}

# ------------------------------------------------------------ end to end ---
# E2E (R-02; not a contract): the 5763 sshd brute-force fixture, with a fresh
# id, the time now and data.srcip = the MISP seed IOC, POSTed to n8n's C1
# webhook through the published port. Then, within E2E_TIMEOUT: (a) exactly
# one TheHive alert with that sourceRef, source wazuh, caseTemplate
# ssh-bruteforce; (b) the IOC observable tagged with n8n's verdict for a MISP
# hit; (c) one writeback comment by n8n with "metrics: ok"; (d) the alert's
# asox-metrics document, read as grafana-ro (C11's reader). Not the 100100
# test rule: n8n writes no metrics for test alerts by design. Cleanup (the
# TheHive alert, the asox-metrics document) always runs, also on FAIL and on
# exit. SKIP unless core, cases and intel all run (single-host mode, R-29).
E2E_FIXTURE="$REPO_ROOT/nodes/core/n8n/fixtures/wazuh/5763-sshd-bruteforce.json"
E2E_TIMEOUT=${E2E_TIMEOUT:-120}
E2E_RULE=5763
E2E_SOURCE=wazuh
E2E_TEMPLATE=ssh-bruteforce
E2E_VERDICT_TAG='asox:verdict=suspicious'   # n8n README: MISP_2_1's verdict for a hit
E2E_N8N_USER=n8n@asox.local
E2E_METRICS_FIELDS='["alert_id", "rule_id", "playbook", "t_event", "t_alert", "thehive_alert_id"]'
E2E_ID="" E2E_IOC="" E2E_MISSING="" E2E_TH_ID=""

e2e_thehive() { c1_thehive "$(core_env THEHIVE_N8N_API_KEY)" "$@"; }
# TheHive alerts with sourceRef <id>, as a JSON array (empty on any error).
e2e_alerts() {
  local r
  r=$(e2e_thehive POST /api/v1/query "$(jq -nc --arg r "$1" \
    '{query: [{_name: "listAlert"}, {_name: "filter", _field: "sourceRef", _value: $r}]}')")
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -c 'if type == "array" then . else [] end' 2>/dev/null || echo '[]'
}
# <alert _id> <observables|comments>: that list of the alert, as a JSON array.
e2e_alert_list() {
  local r
  r=$(e2e_thehive POST /api/v1/query "$(jq -nc --arg a "$1" --arg l "$2" '{query: [{_name: "getAlert", idOrName: $a}, {_name: $l}]}')")
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -c 'if type == "array" then . else [] end' 2>/dev/null || echo '[]'
}

# One look at a-d for alert <id>. Sets E2E_MISSING to what doesn't hold yet
# ("; "-separated) and E2E_TH_ID; returns 0 when everything holds.
e2e_state() {
  local id=$1 alerts n obs comments wb doc
  local -a miss=()
  E2E_TH_ID=""
  alerts=$(e2e_alerts "$id")
  n=$(jq 'length' <<<"$alerts")
  if (( n == 1 )) && jq -e --arg s "$E2E_SOURCE" --arg t "$E2E_TEMPLATE" \
      '.[0].source == $s and .[0].caseTemplate == $t' >/dev/null <<<"$alerts"; then
    E2E_TH_ID=$(jq -r '.[0]._id' <<<"$alerts")
  else
    miss+=("a: $n TheHive alert(s) with sourceRef $id$( (( n > 0 )) && jq -r '" (" + ([.[] | "\(._id) source \(.source) caseTemplate \(.caseTemplate)"] | join(", ")) + ")"' <<<"$alerts")")
  fi
  if [[ -n $E2E_TH_ID ]]; then
    obs=$(e2e_alert_list "$E2E_TH_ID" observables)
    jq -e --arg v "$E2E_IOC" --arg t "$E2E_VERDICT_TAG" \
        'any(.[]; .data == $v and ((.tags // []) | index($t) != null))' >/dev/null <<<"$obs" \
      || miss+=("b: observable $E2E_IOC not tagged $E2E_VERDICT_TAG (tags: $(jq -r --arg v "$E2E_IOC" '[.[] | select(.data == $v) | .tags[]?] | join(", ") | if . == "" then "none" else . end' <<<"$obs"))")
    comments=$(e2e_alert_list "$E2E_TH_ID" comments)
    wb=$(jq -c --arg u "$E2E_N8N_USER" --arg p "[asox-n8n writeback] wazuh-alert-id=$id" \
      '[.[] | select(.createdBy == $u and (.message == $p or (.message | startswith($p + "\n"))))]' <<<"$comments")
    if [[ $(jq 'length' <<<"$wb") != 1 ]]; then
      miss+=("c: $(jq 'length' <<<"$wb") writeback comment(s) by $E2E_N8N_USER")
    elif ! jq -e '.[0].message | test("(^|\n)[-* ]*metrics: ok *(\n|$)")' >/dev/null <<<"$wb"; then
      miss+=("c: writeback has no \"metrics: ok\" line ($(jq -r '[.[0].message | split("\n")[] | select(test("metrics:"))] | first // "no metrics line"' <<<"$wb"))")
    fi
  else
    miss+=("b, c: no TheHive alert to look at")
  fi
  doc=$(c11_gro GET "/$ASOX_METRICS_INDEX/_doc/$id")
  if [[ $(http_code "$doc") != 200 ]]; then
    miss+=("d: no $ASOX_METRICS_INDEX document $id (HTTP $(http_code "$doc"))")
  elif ! http_body "$doc" | jq -e --arg id "$id" --arg r "$E2E_RULE" --arg th "$E2E_TH_ID" --argjson f "$E2E_METRICS_FIELDS" \
      '._source as $s | all($f[]; $s[.] != null) and $s.alert_id == $id and $s.rule_id == $r
       and ($th == "" or $s.thehive_alert_id == $th)' >/dev/null; then
    miss+=("d: $ASOX_METRICS_INDEX document $id incomplete: $(http_body "$doc" | jq -c --argjson f "$E2E_METRICS_FIELDS" '._source | with_entries(select(.key as $k | $f | index($k)))' | cut -c1-200)")
  fi
  E2E_MISSING=$(IFS=';'; printf '%s' "${miss[*]}" | sed 's/;/; /g')
  (( ${#miss[@]} == 0 ))
}

# n8n's parked lib-error executions mentioning <id>: "<execution> (<class>)".
e2e_parked() {
  local wf
  wf=$(n8n_workflow_id_by_name lib-error)
  [[ -n $wf ]] || return 0
  n8n_api GET "/executions?workflowId=$wf&status=error&limit=50&includeData=true" \
    | jq -r --arg a "$1" '[.data[]? | select(tostring | contains($a))
        | "\(.id) (\(.data.resultData.error.message // "" | capture("parked: (?<c>[^ ]+)").c // "unknown"))"] | join(", ")' 2>/dev/null || true
}

# Delete what the run left: every TheHive alert with sourceRef E2E_ID and
# its asox-metrics document. Prints what was deleted.
e2e_cleanup() {
  [[ -n $E2E_ID ]] || return 0
  local id=$E2E_ID th r deleted=()
  E2E_ID=""
  for th in $(e2e_alerts "$id" | jq -r '.[]._id'); do
    r=$(e2e_thehive DELETE "/api/v1/alert/$th")
    if [[ $(http_code "$r") == 204 ]]; then deleted+=("TheHive alert $th")
    else warn "E2E cleanup: deleting TheHive alert $th returned HTTP $(http_code "$r"); delete it by hand"; fi
  done
  r=$(indexer_api DELETE "/$ASOX_METRICS_INDEX/_doc/$id" | jq -r '.result // empty' 2>/dev/null || true)
  [[ $r == deleted ]] && deleted+=("$ASOX_METRICS_INDEX document $id")
  if (( ${#deleted[@]} > 0 )); then
    info "E2E cleanup: deleted $(IFS=';'; printf '%s' "${deleted[*]}" | sed 's/;/, /g') (alert $id)"
  else
    info "E2E cleanup: nothing to delete for alert $id"
  fi
}

check_E2E() {
  local c="E2E Wazuh alert -> n8n -> TheHive + MISP + metrics" n absent=() body code start deadline parked
  for n in core cases intel; do node_absent "$n" && absent+=("$n"); done
  if (( ${#absent[@]} > 0 )); then
    skip "$c: not checked: node(s) ${absent[*]} not running (needs core, cases and intel)"
    return
  fi
  [[ -f $E2E_FIXTURE ]] || { fail "$c: fixture $E2E_FIXTURE not found"; return; }
  E2E_IOC=$(jq -r '.Event.Attribute[0].value // empty' "$SEED_FILE" 2>/dev/null || true)
  [[ -n $E2E_IOC ]] || { fail "$c: no seed IOC in $SEED_FILE"; return; }
  E2E_ID="$(date +%s).$$$(printf '%05d' "$RANDOM")"   # a Wazuh alert id's shape, kept a string
  body=$(jq -c --arg id "$E2E_ID" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)" --arg ip "$E2E_IOC" \
    '.id = $id | .timestamp = $ts | .data.srcip = $ip' "$E2E_FIXTURE")
  start=$SECONDS
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "$N8N_URL/webhook/wazuh-alert" \
    -H 'Content-Type: application/json' -H "X-ASOX-Token: $(core_env N8N_WEBHOOK_TOKEN)" --data-binary "$body" || true)
  if [[ $code != 200 ]]; then
    fail "$c: POST of alert $E2E_ID to $N8N_URL/webhook/wazuh-alert returned HTTP $code"
    e2e_cleanup
    return
  fi
  deadline=$(( start + E2E_TIMEOUT ))
  until e2e_state "$E2E_ID" || (( SECONDS >= deadline )); do sleep 3; done
  if [[ -z $E2E_MISSING ]]; then
    pass "$c: alert $E2E_ID (rule $E2E_RULE, srcip $E2E_IOC) became TheHive alert $E2E_TH_ID ($E2E_SOURCE, $E2E_TEMPLATE), $E2E_IOC tagged $E2E_VERDICT_TAG, one writeback by $E2E_N8N_USER with metrics: ok, $ASOX_METRICS_INDEX document complete; $(( SECONDS - start ))s"
  else
    parked=$(e2e_parked "$E2E_ID")
    fail "$c: alert $E2E_ID not complete within ${E2E_TIMEOUT}s: $E2E_MISSING${parked:+; parked in lib-error: $parked}"
  fi
  e2e_cleanup
}

# Never leave a test object behind, even if the script stops early.
trap 'c1r_n8n_start; thehive_test_alert_delete; c11_doc_delete; e2e_cleanup' EXIT

check_C8() {
  local auth health body resp
  auth="$(core_env GRAFANA_ADMIN_USER):$(core_env GRAFANA_ADMIN_PASSWORD)"
  health=$(curl -s -u "$auth" "$GRAFANA_URL/api/datasources/uid/wazuh-indexer/health" || true)
  if [[ $(jq -r '.status // empty' <<<"$health" 2>/dev/null) != OK ]]; then
    fail "C8 Grafana -> Wazuh indexer: datasource health check: ${health:-no response from $GRAFANA_URL}"
    return
  fi
  test_alert || { fail "C8 Grafana -> Wazuh indexer: $TEST_ALERT_ERROR"; return; }
  body=$(jq -nc --arg q "rule.id:100100 AND id:\"$TEST_ALERT_ID\"" '{
    from: "now-1h", to: "now",
    queries: [{refId: "A", datasource: {uid: "wazuh-indexer"}, queryType: "lucene", query: $q,
               timeField: "timestamp", metrics: [{id: "1", type: "raw_data", settings: {size: "10"}}], bucketAggs: []}]}')
  resp=$(curl -s -u "$auth" -H 'Content-Type: application/json' "$GRAFANA_URL/api/ds/query" -d "$body" || true)
  if jq -e --arg id "$TEST_ALERT_ID" \
      '[.results.A.frames[]?.data.values[]?[]?] | any(. == $id)' >/dev/null 2>&1 <<<"$resp"; then
    pass "C8 Grafana -> Wazuh indexer: datasource healthy, query returns test alert $TEST_ALERT_ID"
  else
    fail "C8 Grafana -> Wazuh indexer: query did not return test alert $TEST_ALERT_ID: $(jq -c '.results.A.error // .message // .' <<<"$resp" 2>/dev/null | cut -c1-200)"
  fi
}

if [[ ! -f $CORE_ENV && " ${CONTRACTS[*]} " =~ \ (C([123468]|1[014])|E2E|C1-RETRY)\  ]]; then
  die "nodes/core/.env not found; run this on the core machine after scripts/soc.sh init"
fi
echo "== Integration contracts (${CONTRACTS[*]})"
for c in "${CONTRACTS[@]}"; do
  "check_$c"
done
finish
