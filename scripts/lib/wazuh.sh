# shellcheck shell=bash
# Wazuh API and indexer helpers for scripts that manage the core node.
# Source after lib/common.sh. Calls run inside the core containers, so they
# work in every deployment mode, whatever the published addresses.

core_env() { env_get "$(node_dir core)/.env" "$1"; }

# Wazuh API call from inside the manager container (works in every mode,
# whatever the published address). Prints the JSON response.
wazuh_api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(-sk -X "$method" -H "Authorization: Bearer $WAZUH_TOKEN" "https://localhost:55000$path")
  if [[ -n $data ]]; then
    printf '%s' "$data" | compose core exec -T wazuh-manager curl "${args[@]}" -H 'Content-Type: application/json' --data-binary @-
  else
    compose core exec -T wazuh-manager curl "${args[@]}"
  fi
}

wazuh_token() {
  local user=$1 password=$2
  compose core exec -T wazuh-manager curl -sk -u "$user:$password" -X POST \
    "https://localhost:55000/security/user/authenticate?raw=true"
}

# Indexer call from inside the indexer container, as the indexer admin.
indexer_api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(-s --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem
    -u "$(core_env INDEXER_ADMIN_USER):$(core_env INDEXER_ADMIN_PASSWORD)"
    -X "$method" "$(core_env WAZUH_INDEXER_URL)$path")
  if [[ -n $data ]]; then
    printf '%s' "$data" | compose core exec -T wazuh-indexer curl "${args[@]}" -H 'Content-Type: application/json' --data-binary @-
  else
    compose core exec -T wazuh-indexer curl "${args[@]}"
  fi
}

# Indexer call as <user>, from inside the indexer container (the indexer is
# internal to core, D32). Prints the body, then the HTTP status on a last
# line (read them with http_body / http_code). The password goes to curl
# through stdin, never on a command line.
indexer_as() {
  local user=$1 password=$2 method=$3 path=$4 data=${5:-}
  local -a args=(-s -w '\n%{http_code}' --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem
    -K - -X "$method" "$(core_env WAZUH_INDEXER_URL)$path")
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' --data-binary "$data")
  local cred="$user:$password"
  cred=${cred//\\/\\\\}; cred=${cred//\"/\\\"}
  printf 'user = "%s"\n' "$cred" \
    | compose core exec -T wazuh-indexer curl "${args[@]}" || printf '\n000'
}

# ---- C11: the asox-metrics index (PROJECT.md 5) ----
# One document per Wazuh alert, written by n8n as n8n-indexer and read by
# Grafana as grafana-ro. The mapping is strict: a field outside this list is
# refused, so a new field is a change to C11 (and to this list) first.
# Settings per the Wazuh owner (W1.7): 1 primary shard, 0 replicas (single
# node), no ISM / deletion policy before the 2026-12-01 delivery.
ASOX_METRICS_INDEX=asox-metrics
ASOX_METRICS_KEYWORD=(alert_id thehive_alert_id case_id rule_id playbook n8n_execution_id outcome resolution)
ASOX_METRICS_INTEGER=(rule_level severity)
ASOX_METRICS_BOOLEAN=(auto_promoted)
ASOX_METRICS_DATE=(t_attack_start t_event t_alert t_ack t_case t_contained t_closed)

asox_metrics_mappings() {
  local f
  {
    for f in "${ASOX_METRICS_KEYWORD[@]}"; do printf '%s keyword\n' "$f"; done
    for f in "${ASOX_METRICS_INTEGER[@]}"; do printf '%s integer\n' "$f"; done
    for f in "${ASOX_METRICS_BOOLEAN[@]}"; do printf '%s boolean\n' "$f"; done
    for f in "${ASOX_METRICS_DATE[@]}"; do printf '%s date\n' "$f"; done
  } | jq -Rnc '{dynamic: "strict",
                properties: ([inputs | split(" ") | {(.[0]): {type: .[1]}}] | add)}'
}

asox_metrics_template() {
  jq -nc --arg i "$ASOX_METRICS_INDEX" --argjson m "$(asox_metrics_mappings)" '{
    index_patterns: [$i],
    priority: 100,
    template: {
      settings: {index: {number_of_shards: 1, number_of_replicas: 0}},
      mappings: $m
    },
    _meta: {description: "ASOX C11: one document per Wazuh alert (PROJECT.md 5); scripts/bootstrap.sh core"}
  }'
}

# Log in as the Wazuh API administrator and set WAZUH_TOKEN.
wazuh_admin_login() {
  WAZUH_TOKEN=$(wazuh_token "$(core_env WAZUH_API_ADMIN_USER)" "$(core_env WAZUH_API_ADMIN_PASSWORD)")
  [[ $WAZUH_TOKEN == ey* ]]
}

# True if the core node is initialised on this machine and its manager runs.
wazuh_manager_running() {
  [[ -f "$(node_dir core)/.env" ]] \
    && compose core ps --status running --services 2>/dev/null | grep -qx wazuh-manager
}

# Remove the registration of agent <name> from the manager, so a fresh agent
# with the same name can enroll again. Prints the removed ID, or nothing if
# no such agent exists. Needs wazuh_admin_login first.
wazuh_remove_agent() {
  local name=$1 id resp
  id=$(wazuh_api GET "/agents?name=$name&select=id" | jq -r '.data.affected_items[0].id // empty')
  [[ -n $id ]] || return 0
  resp=$(wazuh_api DELETE "/agents?agents_list=$id&status=all&older_than=0s")
  jq -e --arg id "$id" '.data.affected_items | index($id)' >/dev/null <<<"$resp" || return 1
  printf '%s' "$id"
}
