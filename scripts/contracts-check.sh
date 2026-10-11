#!/usr/bin/env bash
# Check the integration contracts (PROJECT.md section 5): each one must
# connect and authenticate. Run on the machine hosting core (and lab), with
# the nodes the checked contracts need running (full mode for C1-C8, C10).
#
# Usage: scripts/contracts-check.sh [--only C3,C4]
# One PASS/FAIL line per contract; exit code 1 if any contract fails.
# C3/C4 create a test alert in TheHive (source contract-check) and delete it;
# C1 deletes the TheHive alert n8n makes from its test alert (source asox-test).
# C10 prints SKIP (not a failure) while its check workflow chk-misp-api is
# neither in n8n nor in nodes/core/n8n/workflows/ (not merged yet).
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"
# shellcheck source=scripts/lib/cases.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/cases.sh"

usage() { print_usage "$0"; }

ONLY=""
while (( $# > 0 )); do
  case $1 in
    --only) ONLY=${2:?--only needs a list, e.g. C3,C4}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
ALL_CONTRACTS=(C1 C2 C3 C4 C5 C6 C7 C8 C10)
if [[ -n $ONLY ]]; then
  IFS=',' read -r -a CONTRACTS <<<"${ONLY^^}"
  for c in "${CONTRACTS[@]}"; do
    [[ " ${ALL_CONTRACTS[*]} " == *" $c "* ]] || die "unknown contract: $c (C1-C8, C10)"
  done
else
  CONTRACTS=("${ALL_CONTRACTS[@]}")
fi

CORE_ENV="$(node_dir core)/.env"
core_env() { env_get "$CORE_ENV" "$1"; }
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

# ------------------------------------------------------------- contracts ---

# HTTP status of a POST to an n8n webhook; extra curl arguments follow.
webhook_status() {
  local path=$1; shift
  curl -s -o /dev/null -w '%{http_code}' -X POST "$N8N_URL/webhook/$path" \
    -H 'Content-Type: application/json' -d '{"contract_check": true}' "$@" || true
}

# n8n's pb-generic turns the C1 test alert into a TheHive alert (source
# asox-test, sourceRef = the Wazuh alert id). Delete it directly through
# TheHive's API with n8n's key; only alerts with source asox-test. Never
# fails: without pb-generic, TheHive or the key, it prints an INFO line.
# Calls are bounded: an unreachable cases host must not stall the run.
c1_thehive() { _call -H "Authorization: Bearer $1" --max-time 10 -- "$2" "$THEHIVE_API$3" "${4:-}"; }
c1_thehive_cleanup() {
  local key q r ids deadline
  key=$(core_env THEHIVE_N8N_API_KEY)
  [[ -n $key ]] || { info "C1 cleanup: THEHIVE_N8N_API_KEY is empty, no TheHive alert to delete"; return 0; }
  # pb-generic runs after recv-wazuh-alert: wait for its alert only if n8n has it.
  deadline=$SECONDS
  [[ -n $(n8n_workflow_id_by_name pb-generic) ]] && deadline=$(( SECONDS + EVENT_TIMEOUT ))
  q=$(jq -nc --arg r "$TEST_ALERT_ID" \
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
      info "C1 cleanup: no TheHive alert with source asox-test and sourceRef $TEST_ALERT_ID (pb-generic not merged, or TheHive disabled)"
      return 0
    fi
    sleep 3
  done
  local id
  while IFS= read -r id; do
    r=$(c1_thehive "$key" DELETE "/api/v1/alert/$id")
    if [[ $(http_code "$r") == 204 ]]; then
      info "C1 cleanup: deleted TheHive test alert $id (sourceRef $TEST_ALERT_ID)"
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
# Never leave the test alert behind, even if the script stops early.
trap thehive_test_alert_delete EXIT

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
# (the n8n branch merged) a missing workflow is a failure.
C10_WORKFLOW=chk-misp-api
C10_VALUE=8.8.8.8
check_C10() {
  local c="C10 n8n -> MISP" resp status hit write
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

if [[ ! -f $CORE_ENV && " ${CONTRACTS[*]} " =~ \ C([123468]|10)\  ]]; then
  die "nodes/core/.env not found; run this on the core machine after scripts/soc.sh init"
fi
echo "== Integration contracts (${CONTRACTS[*]})"
for c in "${CONTRACTS[@]}"; do
  "check_$c"
done
finish
