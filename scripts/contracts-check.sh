#!/usr/bin/env bash
# Check the integration contracts (PROJECT.md section 5): each one must
# connect and authenticate. Run on the machine hosting core (and lab), with
# the nodes the checked contracts need running (full mode for C1-C8).
#
# Usage: scripts/contracts-check.sh [--only C3,C4]
# One PASS/FAIL/SKIP line per contract; exit code 1 if any contract fails.
# Contracts not implemented yet report SKIP with the build step that adds them.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"


usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }

ONLY=""
while (( $# > 0 )); do
  case $1 in
    --only) ONLY=${2:?--only needs a list, e.g. C3,C4}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
ALL_CONTRACTS=(C1 C2 C3 C4 C5 C6 C7 C8)
if [[ -n $ONLY ]]; then
  IFS=',' read -r -a CONTRACTS <<<"${ONLY^^}"
  for c in "${CONTRACTS[@]}"; do
    [[ " ${ALL_CONTRACTS[*]} " == *" $c "* ]] || die "unknown contract: $c (C1-C8)"
  done
else
  CONTRACTS=("${ALL_CONTRACTS[@]}")
fi

CORE_ENV="$(node_dir core)/.env"
core_env() { env_get "$CORE_ENV" "$1"; }
# Published on the core host; 127.0.0.1 works with either BIND_ADDR.
GRAFANA_URL=${GRAFANA_URL:-http://127.0.0.1:3000}
ALERT_TIMEOUT=${ALERT_TIMEOUT:-120}

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

# Build step that implements each contract still to come.
declare -A PENDING=([C3]=1.7 [C4]=1.7 [C5]=1.5 [C6]=1.7 [C7]=1.6)

[[ -f $CORE_ENV ]] || die "nodes/core/.env not found; run this on the core machine after scripts/soc.sh init"
echo "== Integration contracts (${CONTRACTS[*]})"
for c in "${CONTRACTS[@]}"; do
  if declare -F "check_$c" >/dev/null; then
    "check_$c"
  else
    skip "$c not implemented yet (build step ${PENDING[$c]})"
  fi
done
finish
