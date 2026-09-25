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
