#!/usr/bin/env bash
# Create the service users, API keys and seed data of a running node.
# Idempotent: existing objects are updated to match the repo and .env.
#
# Usage: scripts/bootstrap.sh <node>
#   core : Wazuh API user n8n-api with a read-only role (C2);
#          indexer user grafana-ro, read-only on wazuh-alerts-* (C8)
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- core ---

# Read-only Wazuh API role for n8n (C2), built from Wazuh's own read-only
# policies (Wazuh rejects a custom policy identical to a built-in one).
# Active response is deliberately absent: it is added only through contract
# C9 (PROJECT.md section 5).
N8N_ROLE=n8n-api-readonly
N8N_POLICIES=(
  agents_read_agents agents_read_groups
  rules_read_rules decoders_read_decoders lists_read_rules mitre_read_mitre
  syscheck_read_syscheck syscollector_read_syscollector sca_read_sca
  rootcheck_read_rootcheck ciscat_read_ciscat
  cluster_read_resourceless
)

# Indexer role for Grafana (C8): read wazuh-alerts-* only.
GRAFANA_ROLE=asox_grafana_ro

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

# Fail with the API response unless it reports no failed items.
wazuh_ok() {
  local what=$1 resp=$2
  if jq -e '(.error // 0) == 0 and ((.data.total_failed_items // 0) == 0)' >/dev/null 2>&1 <<<"$resp"; then
    return 0
  fi
  fail "$what: $(jq -c '.data.failed_items // .detail // .' <<<"$resp" 2>/dev/null || printf '%s' "$resp")"
  return 1
}

bootstrap_wazuh_api() {
  local admin_user admin_pw user pw resp
  admin_user=$(core_env WAZUH_API_ADMIN_USER)
  admin_pw=$(core_env WAZUH_API_ADMIN_PASSWORD)
  user=$(core_env WAZUH_N8N_API_USER)
  pw=$(core_env WAZUH_N8N_API_PASSWORD)

  WAZUH_TOKEN=$(wazuh_token "$admin_user" "$admin_pw")
  [[ $WAZUH_TOKEN == ey* ]] || { fail "Wazuh API: admin login as $admin_user failed"; return; }
  pass "Wazuh API: admin login"

  # Built-in read-only policies to link to the role.
  local existing name id
  local -a policy_ids=()
  existing=$(wazuh_api GET "/security/policies?limit=500")
  for name in "${N8N_POLICIES[@]}"; do
    id=$(jq -r --arg n "$name" '.data.affected_items[] | select(.name == $n) | .id' <<<"$existing")
    [[ -n $id ]] || { fail "Wazuh API: built-in policy $name not found"; return; }
    policy_ids+=("$id")
  done

  # Role, linked to exactly these policies.
  local role_id linked missing
  existing=$(wazuh_api GET "/security/roles?limit=500")
  role_id=$(jq -r --arg n "$N8N_ROLE" '.data.affected_items[] | select(.name == $n) | .id' <<<"$existing")
  if [[ -z $role_id ]]; then
    resp=$(wazuh_api POST /security/roles "{\"name\": \"$N8N_ROLE\"}")
    wazuh_ok "role $N8N_ROLE" "$resp" || return
    role_id=$(jq -r '.data.affected_items[0].id' <<<"$resp")
    linked=""
  else
    linked=$(jq -r --arg n "$N8N_ROLE" '.data.affected_items[] | select(.name == $n) | .policies[]' <<<"$existing")
  fi
  missing=$(comm -23 <(printf '%s\n' "${policy_ids[@]}" | sort) <(printf '%s\n' "$linked" | sed '/^$/d' | sort) | paste -sd, -)
  if [[ -n $missing ]]; then
    resp=$(wazuh_api POST "/security/roles/$role_id/policies?policy_ids=$missing")
    wazuh_ok "role $N8N_ROLE policies" "$resp" || return
  fi
  pass "Wazuh API: role $N8N_ROLE (${#policy_ids[@]} read-only policies)"

  # User, with the password from .env, assigned only to this role.
  local user_id roles
  existing=$(wazuh_api GET "/security/users?limit=500")
  user_id=$(jq -r --arg u "$user" '.data.affected_items[] | select(.username == $u) | .id' <<<"$existing")
  if [[ -z $user_id ]]; then
    resp=$(wazuh_api POST /security/users "$(jq -nc --arg u "$user" --arg p "$pw" '{username: $u, password: $p}')")
    wazuh_ok "user $user" "$resp" || return
    user_id=$(jq -r '.data.affected_items[0].id' <<<"$resp")
  elif [[ $(wazuh_token "$user" "$pw") != ey* ]]; then
    resp=$(wazuh_api PUT "/security/users/$user_id" "$(jq -nc --arg p "$pw" '{password: $p}')")
    wazuh_ok "user $user password" "$resp" || return
  fi
  roles=$(jq -r --arg u "$user" '.data.affected_items[] | select(.username == $u) | .roles[]?' <<<"$existing")
  if ! grep -qx "$role_id" <<<"$roles"; then
    resp=$(wazuh_api POST "/security/users/$user_id/roles?role_ids=$role_id")
    wazuh_ok "user $user role" "$resp" || return
  fi
  local extra
  extra=$(grep -vx "$role_id" <<<"$roles" | paste -sd, - || true)
  if [[ -n $extra ]]; then
    resp=$(wazuh_api DELETE "/security/users/$user_id/roles?role_ids=$extra")
    wazuh_ok "user $user extra roles" "$resp" || return
  fi

  # Check: the user can log in and read agents. Wazuh revokes tokens issued
  # in the same second as an RBAC change, so allow a few retries.
  local token attempt
  for attempt in 1 2 3 4 5; do
    sleep 2
    token=$(wazuh_token "$user" "$pw")
    if [[ $token == ey* ]] && [[ $(WAZUH_TOKEN=$token wazuh_api GET /agents | jq -r '.error') == 0 ]]; then
      pass "Wazuh API: user $user (role $N8N_ROLE) can log in and list agents"
      return
    fi
  done
  fail "Wazuh API: user $user cannot log in or list agents (after $attempt attempts)"
}

bootstrap_indexer() {
  local user pw resp
  user=$(core_env GRAFANA_INDEXER_USER)
  pw=$(core_env GRAFANA_INDEXER_PASSWORD)

  resp=$(indexer_api PUT "/_plugins/_security/api/roles/$GRAFANA_ROLE" '{
    "description": "ASOX: Grafana read-only access to Wazuh alerts (C8)",
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*"],
      "allowed_actions": ["read", "indices:admin/mappings/get", "indices:admin/resolve/index"]
    }]
  }')
  jq -e '.status == "OK" or .status == "CREATED"' >/dev/null <<<"$resp" \
    || { fail "indexer role $GRAFANA_ROLE: $resp"; return; }

  resp=$(indexer_api PUT "/_plugins/_security/api/internalusers/$user" \
    "$(jq -nc --arg p "$pw" '{password: $p, description: "ASOX: Grafana datasource (C8)"}')")
  jq -e '.status == "OK" or .status == "CREATED"' >/dev/null <<<"$resp" \
    || { fail "indexer user $user: $resp"; return; }

  resp=$(indexer_api PUT "/_plugins/_security/api/rolesmapping/$GRAFANA_ROLE" \
    "$(jq -nc --arg u "$user" '{users: [$u]}')")
  jq -e '.status == "OK" or .status == "CREATED"' >/dev/null <<<"$resp" \
    || { fail "indexer role mapping $GRAFANA_ROLE: $resp"; return; }
  pass "indexer: user $user with role $GRAFANA_ROLE"

  # Check: it can search the alerts, and nothing else.
  local url count denied
  url=$(core_env WAZUH_INDEXER_URL)
  count=$(compose core exec -T wazuh-indexer curl -s --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -u "$user:$pw" "$url/wazuh-alerts-*/_count" | jq -r '.count // empty')
  denied=$(compose core exec -T wazuh-indexer curl -s -o /dev/null -w '%{http_code}' \
    --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -u "$user:$pw" "$url/.opendistro_security/_search")
  if [[ -n $count && $denied == 403 ]]; then
    pass "indexer: $user reads wazuh-alerts-* ($count alerts) and is denied elsewhere"
  else
    fail "indexer: $user access check (count='$count', other index HTTP $denied)"
  fi
}

bootstrap_core() {
  echo "== bootstrap core"
  bootstrap_wazuh_api
  bootstrap_indexer
}

# ---------------------------------------------------------------- main ---

main() {
  (( $# == 1 )) || { usage; exit 1; }
  local node=$1
  is_node "$node" || die "unknown node: $node"
  [[ -f "$(node_dir "$node")/.env" ]] || die "nodes/$node/.env not found; run scripts/render-env.sh"
  case $node in
    core) bootstrap_core ;;
    *)    skip "bootstrap $node: nothing to bootstrap yet" ;;
  esac
  finish
}

main "$@"
