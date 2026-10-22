#!/usr/bin/env bash
# Create the service users, API keys and seed data of a running node.
# Idempotent: existing objects are updated to match the repo and .env.
#
# Usage: scripts/bootstrap.sh <node>
#   core : Wazuh API user n8n-api with a read-only role (C2);
#          agent group asox-response and Wazuh API user n8n-response,
#          active response on that group's agents only (C9);
#          the asox-metrics index template and the empty index (C11);
#          indexer user grafana-ro, read-only on wazuh-alerts-* and
#          asox-metrics (C8, C11); indexer user n8n-indexer, documents of
#          asox-metrics and read on wazuh-alerts-* (C11, C13);
#          n8n recreated if its .env changed (docker compose up --wait),
#          n8n owner, n8n credentials (incl. TheHive, Cortex, MISP, the
#          indexer and Wazuh's response user, C3/C6/C9/C10/C11),
#          and the workflows from nodes/core/n8n/workflows/ that n8n
#          doesn't have yet
#   cases: Cortex indexes, superadmin, SOC organization, org admin and the
#          API users for TheHive (C5) and n8n (C6), with their keys;
#          TheHive admin password, SOC organisation, analyst, API user for
#          n8n (C3) with its key, the Cortex connector (C5) and the webhook
#          to n8n (C4); the MISP analyzer (C7) once intel has created its
#          MISP key; then the owners' configuration as code:
#          nodes/cases/cortex/analyzers/analyzers.sh apply (online
#          analyzers, keys from its git-ignored analyzer-keys.env) and
#          nodes/cases/thehive/scripts/thehive-import.sh (custom fields,
#          observable types, case templates)
#   intel: MISP admin API key, read-only user for Cortex with its key (C7),
#          the seed event (nodes/intel/misp/seed/seed-event.json), then
#          nodes/intel/misp/misp-config.sh apply: warninglists with the size
#          cap, feeds, and the read-only user for n8n with its key (C10)
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/wazuh.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/wazuh.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"
# shellcheck source=scripts/lib/cases.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/cases.sh"
# shellcheck source=scripts/lib/misp.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/misp.sh"
trap n8n_cleanup EXIT

usage() { print_usage "$0"; }

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

# Response role for n8n (C9, D44): active response and agent read, only on
# the agents of WAZUH_RESPONSE_AGENT_GROUP. A custom policy (no built-in one
# is scoped to a group), linked to its own role; n8n-api is never touched.
RESP_ROLE=n8n-response
RESP_POLICY=n8n-response
RESP_ACTIONS=(active-response:command agent:read)
# Harmless probe for the refusal checks (as C2's): no such script exists.
AR_PROBE='{"command": "!asox-contract-probe", "arguments": []}'

# Indexer roles: Grafana reads wazuh-alerts-* (C8) and asox-metrics (C11,
# R-11); n8n writes asox-metrics (C11) and reads wazuh-alerts-* (C13, R-16).
GRAFANA_ROLE=asox_grafana_ro
N8N_INDEXER_ROLE=asox_n8n_indexer

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

# C9 (D44): agent group, policy, role and user n8n-response. Each object is
# created when missing and set back to what is here when it drifted; the
# n8n-api user and role (C2) are never read or written here.
bootstrap_wazuh_response() {
  local user pw group resp existing policy
  user=$(core_env WAZUH_RESPONSE_USER)
  pw=$(core_env WAZUH_RESPONSE_PASSWORD)
  group=$(core_env WAZUH_RESPONSE_AGENT_GROUP)
  [[ -n $user && -n $pw && -n $group ]] || { fail "Wazuh API: WAZUH_RESPONSE_USER / _PASSWORD / _AGENT_GROUP empty in nodes/core/.env (run scripts/render-env.sh)"; return; }
  wazuh_admin_login || { fail "Wazuh API: admin login failed (C9)"; return; }

  # Agent group: agents join it by enrollment or through the API (Wazuh owner).
  existing=$(wazuh_api GET "/groups?limit=500&select=name")
  if ! jq -e --arg g "$group" 'any(.data.affected_items[]; .name == $g)' >/dev/null <<<"$existing"; then
    resp=$(wazuh_api POST /groups "$(jq -nc --arg g "$group" '{group_id: $g}')")
    wazuh_ok "agent group $group" "$resp" || return
  fi
  pass "Wazuh API: agent group $group exists"

  # Policy: exactly these actions on this group's agents.
  local policy_id want
  want=$(jq -nc --arg r "agent:group:$group" '$ARGS.positional as $a
    | {actions: $a, resources: [$r], effect: "allow"}' --args "${RESP_ACTIONS[@]}")
  existing=$(wazuh_api GET "/security/policies?limit=500")
  policy_id=$(jq -r --arg n "$RESP_POLICY" '.data.affected_items[] | select(.name == $n) | .id' <<<"$existing")
  if [[ -z $policy_id ]]; then
    resp=$(wazuh_api POST /security/policies "$(jq -nc --arg n "$RESP_POLICY" --argjson p "$want" '{name: $n, policy: $p}')")
    wazuh_ok "policy $RESP_POLICY" "$resp" || return
    policy_id=$(jq -r '.data.affected_items[0].id' <<<"$resp")
  else
    policy=$(jq -c --arg n "$RESP_POLICY" '.data.affected_items[] | select(.name == $n) | .policy' <<<"$existing")
    if [[ $(jq -cS '.actions |= sort | .resources |= sort' <<<"$policy") != $(jq -cS '.actions |= sort | .resources |= sort' <<<"$want") ]]; then
      resp=$(wazuh_api PUT "/security/policies/$policy_id" "$(jq -nc --argjson p "$want" '{policy: $p}')")
      wazuh_ok "policy $RESP_POLICY update" "$resp" || return
    fi
  fi
  pass "Wazuh API: policy $RESP_POLICY (${RESP_ACTIONS[*]} on agent:group:$group)"

  # Role, linked to this policy only.
  local role_id linked extra
  existing=$(wazuh_api GET "/security/roles?limit=500")
  role_id=$(jq -r --arg n "$RESP_ROLE" '.data.affected_items[] | select(.name == $n) | .id' <<<"$existing")
  if [[ -z $role_id ]]; then
    resp=$(wazuh_api POST /security/roles "$(jq -nc --arg n "$RESP_ROLE" '{name: $n}')")
    wazuh_ok "role $RESP_ROLE" "$resp" || return
    role_id=$(jq -r '.data.affected_items[0].id' <<<"$resp")
    linked=""
  else
    linked=$(jq -r --arg n "$RESP_ROLE" '.data.affected_items[] | select(.name == $n) | .policies[]' <<<"$existing")
  fi
  if ! grep -qx "$policy_id" <<<"$linked"; then
    resp=$(wazuh_api POST "/security/roles/$role_id/policies?policy_ids=$policy_id")
    wazuh_ok "role $RESP_ROLE policy" "$resp" || return
  fi
  extra=$(grep -vx "$policy_id" <<<"$linked" | sed '/^$/d' | paste -sd, - || true)
  if [[ -n $extra ]]; then
    resp=$(wazuh_api DELETE "/security/roles/$role_id/policies?policy_ids=$extra")
    wazuh_ok "role $RESP_ROLE extra policies" "$resp" || return
  fi
  pass "Wazuh API: role $RESP_ROLE (policy $RESP_POLICY only)"

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
  extra=$(grep -vx "$role_id" <<<"$roles" | sed '/^$/d' | paste -sd, - || true)
  if [[ -n $extra ]]; then
    resp=$(wazuh_api DELETE "/security/users/$user_id/roles?role_ids=$extra")
    wazuh_ok "user $user extra roles" "$resp" || return
  fi

  # Checks as the user (no side effects): it lists only the group's agents,
  # and active response on agent 000 (the manager, in no group) is refused.
  # Tokens issued in the same second as an RBAC change are revoked (A18).
  local token attempt listed outside ar
  for attempt in 1 2 3 4 5; do
    sleep 2
    token=$(wazuh_token "$user" "$pw")
    [[ $token == ey* ]] || continue
    resp=$(WAZUH_TOKEN=$token wazuh_api GET "/agents?limit=500&select=id,group")
    [[ $(jq -r '.error' <<<"$resp" 2>/dev/null) == 0 ]] || continue
    listed=$(jq -r '[.data.affected_items[].id] | join(",")' <<<"$resp")
    outside=$(jq -r --arg g "$group" '[.data.affected_items[] | select((.group // []) | index($g) | not) | .id] | join(",")' <<<"$resp")
    ar=$(http_code "$(WAZUH_TOKEN=$token wazuh_api_status PUT "/active-response?agents_list=000" "$AR_PROBE")")
    if [[ -z $outside && $ar == 403 ]]; then
      pass "Wazuh API: user $user (role $RESP_ROLE) lists only group $group's agents (${listed:-none yet}); active response on agent 000 refused (HTTP 403)"
    else
      fail "Wazuh API: user $user sees agents outside group $group (${outside:-none}) or active response on agent 000 got HTTP $ar (expected 403)"
    fi
    return
  done
  fail "Wazuh API: user $user cannot log in or list agents (after $attempt attempts)"
}

# Indexer roles (C8, C11, C13). Security-API objects are written only when
# they differ from what is here, so a second run changes nothing.
grafana_role_json() {
  jq -nc '{
    description: "ASOX: Grafana read-only access to Wazuh alerts (C8) and asox-metrics (C11)",
    cluster_permissions: ["cluster_composite_ops_ro", "cluster:monitor/main", "cluster:monitor/health"],
    index_permissions: [
      {index_patterns: ["wazuh-alerts-*"],
       allowed_actions: ["read", "indices:admin/get", "indices:admin/mappings/get", "indices:admin/resolve/index"]},
      {index_patterns: ["asox-metrics"],
       allowed_actions: ["read", "indices:admin/get", "indices:admin/mappings/get", "indices:admin/resolve/index"]}
    ]
  }'
}
# n8n (C11 writer, C13 lookups): documents of asox-metrics by id (index,
# update, delete; bulk) and read; wazuh-alerts-* read only. Cluster: only the
# multi-request entry points of search and bulk (not cluster_composite_ops,
# which adds alias administration and reindex). No index creation (an index
# call on a missing index is refused, not auto-created) and no mapping change.
n8n_indexer_role_json() {
  jq -nc '{
    description: "ASOX: n8n writes asox-metrics (C11) and reads wazuh-alerts-* (C13)",
    cluster_permissions: ["indices:data/read/msearch", "indices:data/read/scroll",
                          "indices:data/read/scroll/clear", "indices:data/write/bulk"],
    index_permissions: [
      {index_patterns: ["asox-metrics"],
       allowed_actions: ["read", "indices:data/write/index", "indices:data/write/update",
                         "indices:data/write/delete", "indices:data/write/bulk[s]"]},
      {index_patterns: ["wazuh-alerts-*"], allowed_actions: ["read"]}
    ]
  }'
}

# indexer_security_put <path> <json>: PUT a role or role mapping unless the
# one at <path> already has these values. Sets INDEXER_STATE to created,
# updated or unchanged; returns 1 (with INDEXER_STATE = the response) on error.
INDEXER_STATE=""
indexer_security_put() {
  local path=$1 want=$2 cur resp
  # The API adds empty fls / masked_fields to index permissions: compare
  # patterns and actions only.
  cur=$(indexer_api GET "$path" | jq -c --arg n "${path##*/}" '.[$n] // empty' 2>/dev/null || true)
  if [[ -n $cur ]] && jq -e --argjson w "$want" '
      def norm: if type == "array" then map(if type == "object" then {index_patterns, allowed_actions} else . end) else . end;
      . as $c | $w | to_entries | all(($c[.key] | norm) == (.value | norm))' >/dev/null <<<"$cur"; then
    INDEXER_STATE=unchanged; return 0
  fi
  resp=$(indexer_api PUT "$path" "$want")
  if jq -e '.status == "OK" or .status == "CREATED"' >/dev/null 2>&1 <<<"$resp"; then
    if [[ -n $cur ]]; then INDEXER_STATE=updated; else INDEXER_STATE=created; fi
    return 0
  fi
  INDEXER_STATE=$resp; return 1
}

# bootstrap_indexer_user <user> <password> <role> <role json> <description>:
# role, internal user (password set only when the one in .env doesn't log
# in) and role mapping (exactly this user).
bootstrap_indexer_user() {
  local user=$1 pw=$2 role=$3 role_json=$4 desc=$5 role_state user_state map_state r
  indexer_security_put "/_plugins/_security/api/roles/$role" "$role_json" \
    || { fail "indexer role $role: $INDEXER_STATE"; return 1; }
  role_state=$INDEXER_STATE

  r=$(indexer_as "$user" "$pw" GET /_plugins/_security/authinfo)
  if [[ $(http_code "$r") == 200 ]]; then
    user_state=unchanged
  else
    r=$(indexer_api PUT "/_plugins/_security/api/internalusers/$user" \
      "$(jq -nc --arg p "$pw" --arg d "$desc" '{password: $p, description: $d}')")
    jq -e '.status == "OK" or .status == "CREATED"' >/dev/null 2>&1 <<<"$r" \
      || { fail "indexer user $user: $r"; return 1; }
    user_state="created or password set"
  fi

  indexer_security_put "/_plugins/_security/api/rolesmapping/$role" "$(jq -nc --arg u "$user" '{users: [$u]}')" \
    || { fail "indexer role mapping $role: $INDEXER_STATE"; return 1; }
  map_state=$INDEXER_STATE
  pass "indexer: user $user with role $role (role $role_state, user $user_state, mapping $map_state)"
}

# The asox-metrics index template (C11), then the index itself, empty, so
# that Grafana's datasource health check passes before n8n writes anything.
# An existing index gets new template fields added to its mapping; a field
# whose type changed can't be, and is a failure (reindex by hand).
bootstrap_metrics_index() {
  local i=$ASOX_METRICS_INDEX want cur resp state
  want=$(asox_metrics_template)
  # Settings come back as strings: compare everything as strings.
  cur=$(indexer_api GET "/_index_template/$i" \
    | jq -c --arg n "$i" '.index_templates[]? | select(.name == $n) | .index_template' 2>/dev/null || true)
  if [[ -n $cur ]] && jq -e --argjson w "$want" '
      def s: walk(if type == "number" or type == "boolean" then tostring else . end);
      ({index_patterns, priority, template, _meta} | s) == ($w | s)' >/dev/null <<<"$cur"; then
    state=unchanged
  else
    resp=$(indexer_api PUT "/_index_template/$i" "$want")
    jq -e '.acknowledged == true' >/dev/null 2>&1 <<<"$resp" \
      || { fail "indexer: index template $i: $resp"; return 1; }
    if [[ -n $cur ]]; then state=updated; else state=created; fi
  fi
  pass "indexer: index template $i ($state; 1 shard, 0 replicas, strict mapping of $(jq '.template.mappings.properties | length' <<<"$want") fields)"

  resp=$(indexer_api GET "/$i/_settings")
  if jq -e '.error.type == "index_not_found_exception"' >/dev/null 2>&1 <<<"$resp"; then
    resp=$(indexer_api PUT "/$i")
    jq -e '.acknowledged == true' >/dev/null 2>&1 <<<"$resp" \
      || { fail "indexer: create index $i: $resp"; return 1; }
    state=created
  elif jq -e --arg n "$i" '.[$n].settings.index.number_of_shards' >/dev/null 2>&1 <<<"$resp"; then
    state=unchanged
    if [[ $(jq -r --arg n "$i" '.[$n].settings.index.number_of_replicas' <<<"$resp") != 0 ]]; then
      indexer_api PUT "/$i/_settings" '{"index": {"number_of_replicas": 0}}' | jq -e '.acknowledged == true' >/dev/null \
        || { fail "indexer: index $i: setting 0 replicas failed"; return 1; }
      state="replicas set to 0"
    fi
    cur=$(indexer_api GET "/$i/_mapping" | jq -c --arg n "$i" '.[$n].mappings')
    if ! jq -e --argjson w "$(jq -c '.template.mappings' <<<"$want")" '. == $w' >/dev/null <<<"$cur"; then
      resp=$(indexer_api PUT "/$i/_mapping" "$(jq -c '.template.mappings' <<<"$want")")
      jq -e '.acknowledged == true' >/dev/null 2>&1 <<<"$resp" \
        || { fail "indexer: index $i: its mapping differs from the template and can't be updated in place (reindex needed): $(jq -c '.error.reason // .' <<<"$resp" | cut -c1-200)"; return 1; }
      state="mapping updated"
    fi
  else
    fail "indexer: index $i: $resp"; return 1
  fi
  resp=$(indexer_api GET "/$i/_settings")
  if [[ $(jq -r --arg n "$i" '.[$n].settings.index | "\(.number_of_shards)/\(.number_of_replicas)"' <<<"$resp") != 1/0 ]]; then
    fail "indexer: index $i must have 1 shard and 0 replicas (has $(jq -r --arg n "$i" '.[$n].settings.index | "\(.number_of_shards)/\(.number_of_replicas)"' <<<"$resp"); a shard count can't change in place)"
    return 1
  fi
  pass "indexer: index $i ($state; $(indexer_api GET "/$i/_count" | jq -r '.count') documents)"
}

bootstrap_indexer() {
  local gro gro_pw n8u n8u_pw idx u r count denied
  gro=$(core_env GRAFANA_INDEXER_USER) gro_pw=$(core_env GRAFANA_INDEXER_PASSWORD)
  n8u=$(core_env N8N_INDEXER_USER) n8u_pw=$(core_env N8N_INDEXER_PASSWORD)
  [[ -n $n8u && -n $n8u_pw ]] || { fail "indexer: N8N_INDEXER_USER / N8N_INDEXER_PASSWORD empty in nodes/core/.env (run scripts/render-env.sh)"; return; }

  bootstrap_metrics_index || return
  bootstrap_indexer_user "$gro" "$gro_pw" "$GRAFANA_ROLE" "$(grafana_role_json)" "ASOX: Grafana datasources (C8, C11)" || return
  bootstrap_indexer_user "$n8u" "$n8u_pw" "$N8N_INDEXER_ROLE" "$(n8n_indexer_role_json)" "ASOX: n8n (C11 writer, C13 lookups)" || return

  # Checks, read-only: each user reads what it should and nothing else.
  idx=$ASOX_METRICS_INDEX
  for u in "$gro:$gro_pw" "$n8u:$n8u_pw"; do
    r=$(indexer_as "${u%%:*}" "${u#*:}" GET "/wazuh-alerts-*/_count")
    count=$(http_body "$r" | jq -r '.count // empty' 2>/dev/null || true)
    r=$(indexer_as "${u%%:*}" "${u#*:}" GET "/$idx/_count")
    [[ $(http_code "$r") == 200 ]] || count=""
    denied=$(http_code "$(indexer_as "${u%%:*}" "${u#*:}" GET /.opendistro_security/_search)")
    if [[ -n $count && $denied == 403 ]]; then
      pass "indexer: ${u%%:*} reads wazuh-alerts-* ($count alerts) and $idx, and is denied elsewhere"
    else
      fail "indexer: ${u%%:*} access check (wazuh-alerts-* count '$count', $idx HTTP $(http_code "$r"), other index HTTP $denied)"
    fi
  done
}

bootstrap_n8n() {
  local body out
  # Apply the freshly rendered .env (e.g. THEHIVE_ENABLED, R-18): Compose
  # recreates n8n only when its configuration changed.
  if out=$(compose core up -d --wait n8n 2>&1); then
    pass "n8n: container matches nodes/core/.env"
  else
    printf '%s\n' "$out" >&2
    fail "n8n: docker compose up -d --wait n8n failed"; return
  fi
  if n8n_owner_exists; then
    n8n_login || { fail "n8n: owner exists but the login from nodes/core/.env is refused"; return; }
    pass "n8n: owner $(core_env N8N_OWNER_EMAIL) can log in"
  else
    body=$(jq -nc --arg e "$(core_env N8N_OWNER_EMAIL)" --arg p "$(core_env N8N_OWNER_PASSWORD)" \
      '{email: $e, firstName: "SOC", lastName: "Admin", password: $p}')
    if curl -sf -H 'Content-Type: application/json' "$N8N_URL/rest/owner/setup" -d "$body" >/dev/null && n8n_login; then
      pass "n8n: owner $(core_env N8N_OWNER_EMAIL) created"
    else
      fail "n8n: owner setup failed"; return
    fi
  fi

  # API key for the scripts (public API; the UI login is rate-limited).
  if n8n_api_ok; then
    pass "n8n: API key for scripts works"
  else
    local key
    key=$(n8n_create_api_key)
    if [[ -n $key ]]; then
      env_set "$(node_dir core)/.env" N8N_API_KEY "$key"
      if n8n_api_ok; then pass "n8n: API key for scripts created (stored in nodes/core/.env)"
      else fail "n8n: new API key does not work"; return; fi
    else
      fail "n8n: could not create an API key"; return
    fi
  fi

  # Created, or updated to the values in nodes/core/.env (lib/n8n.sh).
  if n8n_import_credentials; then
    pass "n8n: credentials $N8N_CREDENTIALS created or updated from nodes/core/.env"
  else
    fail "n8n: credential import failed"; return
  fi
  # TheHive and Cortex keys come from the cases node (__from:cases__), the
  # MISP key from the intel node (__from:intel__).
  local k
  for k in THEHIVE_N8N_API_KEY CORTEX_N8N_API_KEY; do
    [[ -n $(core_env "$k") ]] || skip "n8n: $k is empty, so its credential can't log in yet (C3, C6): bootstrap cases, then scripts/render-env.sh && scripts/bootstrap.sh core (distributed mode: paste it from the cases machine's nodes/cases/.env)"
  done
  [[ -n $(core_env MISP_N8N_API_KEY) ]] || skip "n8n: MISP_N8N_API_KEY is empty, so its credential can't log in yet (C10): bootstrap intel, then scripts/render-env.sh && scripts/bootstrap.sh core (distributed mode: paste it from the intel machine's nodes/intel/.env)"

  # Only workflows n8n doesn't have: never overwrite a teammate's UI work
  # (scripts/n8n-import.sh does that on request).
  local existing f
  local -a missing=()
  existing=$(n8n_workflow_ids)
  for f in "$N8N_WORKFLOW_DIR"/*.json; do
    [[ -f $f ]] || continue
    grep -qx "$(jq -r '.id' "$f")" <<<"$existing" || missing+=("$f")
  done
  if (( ${#missing[@]} > 0 )); then
    n8n_import_workflows "${missing[@]}"
  else
    pass "n8n: all workflows from nodes/core/n8n/workflows/ already present"
  fi
}

bootstrap_core() {
  echo "== bootstrap core"
  bootstrap_wazuh_api
  bootstrap_wazuh_response
  bootstrap_indexer
  bootstrap_n8n
}

# --------------------------------------------------------------- cases ---

# Fail unless the HTTP status of response <r> is one of the given codes.
expect() {
  local what=$1 r=$2; shift 2
  local code c
  code=$(http_code "$r")
  for c in "$@"; do [[ $code == "$c" ]] && return 0; done
  fail "$what: HTTP $code $(http_body "$r" | head -c 200)"
  return 1
}

# Store a new API key for <login> in nodes/cases/.env under <key-var>,
# unless the current one still authenticates as that user.
# Usage: ensure_key <label> <login> <key-var> <check-fn> <renew-fn>
ensure_key() {
  local label=$1 login=$2 var=$3 check=$4 renew=$5 key
  key=$(cases_env "$var")
  if [[ -n $key && $("$check" "$key") == "$login" ]]; then
    pass "$label: API key of $login works"
    return 0
  fi
  key=$("$renew" "$login")
  if [[ -n $key && $("$check" "$key") == "$login" ]]; then
    env_set "$(node_dir cases)/.env" "$var" "$key"
    pass "$label: API key of $login created (stored in nodes/cases/.env)"
  else
    fail "$label: could not create a working API key for $login"
    return 1
  fi
}

cortex_renew_key() {
  local r
  r=$(cortex_admin POST "/api/user/$1/key/renew")
  [[ $(http_code "$r") == 200 ]] && http_body "$r"
  return 0
}

thehive_renew_key() {
  local r
  r=$(thehive_admin POST "/api/v1/user/$1/key/renew")
  [[ $(http_code "$r") == 200 ]] && http_body "$r"
  return 0
}

# Cortex user <login> in <org> with <roles> (JSON array); password optional.
cortex_ensure_user() {
  local login=$1 org=$2 roles=$3 pw=${4:-} r body
  r=$(cortex_admin GET "/api/user/$login")
  if [[ $(http_code "$r") == 200 ]]; then
    body=$(jq -nc --argjson r "$roles" '{roles: $r, status: "Ok"}')
    r=$(cortex_admin PATCH "/api/user/$login" "$body")
    expect "Cortex: user $login" "$r" 200 || return 1
  else
    body=$(jq -nc --arg l "$login" --arg o "$org" --argjson r "$roles" \
      '{login: $l, name: $l, organization: $o, roles: $r}')
    r=$(cortex_admin POST /api/user "$body")
    expect "Cortex: user $login" "$r" 201 || return 1
  fi
  if [[ -n $pw ]] && [[ $(http_code "$(cortex_as "$login" "$pw" GET /api/user/current)") != 200 ]]; then
    r=$(cortex_admin POST "/api/user/$login/password/set" "$(jq -nc --arg p "$pw" '{password: $p}')")
    expect "Cortex: password of $login" "$r" 204 200 || return 1
  fi
  pass "Cortex: user $login ($org, roles $(jq -r 'join(",")' <<<"$roles"))"
}

bootstrap_cortex() {
  local admin org r
  admin=$(cases_env CORTEX_ADMIN_USER)
  org=$(cases_env CORTEX_ORG)

  # Create or update Cortex's indexes in Elasticsearch (idempotent).
  r=$(cortex_noauth POST "$CORTEX_API/api/maintenance/migrate")
  expect "Cortex: index migration" "$r" 204 200 || return
  pass "Cortex: Elasticsearch indexes up to date"

  # Superadmin: Cortex accepts an unauthenticated user creation only while
  # it has no users at all.
  if [[ $(http_code "$(cortex_admin GET /api/user/current)") != 200 ]]; then
    r=$(cortex_noauth POST "$CORTEX_API/api/user" "$(jq -nc --arg l "$admin" --arg p "$(cases_env CORTEX_ADMIN_PASSWORD)" \
      '{login: $l, name: "SOC superadmin", roles: ["superadmin"], organization: "cortex", password: $p}')")
    if [[ $(http_code "$r") != 201 ]]; then
      fail "Cortex: superadmin $admin cannot log in with the password from nodes/cases/.env, and cannot be created (HTTP $(http_code "$r"))"
      return
    fi
    pass "Cortex: superadmin $admin created"
  else
    pass "Cortex: superadmin $admin can log in"
  fi

  if [[ $(http_code "$(cortex_admin GET "/api/organization/$org")") != 200 ]]; then
    r=$(cortex_admin POST /api/organization "$(jq -nc --arg o "$org" '{name: $o, description: "ASOX SOC", status: "Active"}')")
    expect "Cortex: organization $org" "$r" 201 || return
  fi
  pass "Cortex: organization $org"

  # Org admin (enables and configures analyzers, UI login), and the two API
  # users: read + analyze only.
  cortex_ensure_user "$(cases_env CORTEX_ORGADMIN_USER)" "$org" '["read","analyze","orgadmin"]' \
    "$(cases_env CORTEX_ORGADMIN_PASSWORD)" || return
  cortex_ensure_user "$(cases_env CORTEX_THEHIVE_USER)" "$org" '["read","analyze"]' || return
  cortex_ensure_user "$(cases_env CORTEX_N8N_USER)" "$org" '["read","analyze"]' || return
  ensure_key Cortex "$(cases_env CORTEX_THEHIVE_USER)" CORTEX_THEHIVE_API_KEY cortex_key_login cortex_renew_key || return
  ensure_key Cortex "$(cases_env CORTEX_N8N_USER)" CORTEX_N8N_API_KEY cortex_key_login cortex_renew_key || return

  # The Docker job runner: Cortex reports it available, and a container
  # started through its socket shares its job directory (PROJECT.md 6.5).
  local problem
  docker image inspect "$RUNNER_TEST_IMAGE" >/dev/null 2>&1 || docker pull -q "$RUNNER_TEST_IMAGE" >/dev/null
  if problem=$(cortex_test_container "$RUNNER_TEST_IMAGE"); then
    pass "Cortex: can start a container on network $(cases_env CORTEX_ANALYZER_NETWORK) sharing its job directory"
  else
    fail "Cortex: test container: $problem"
  fi
}

# TheHive user <login> of <type> (Normal or Service) in the SOC organisation
# with <profile>; password optional. The community license allows 2 Normal
# users; Service users (API only) are not counted (docs/decisions.md A53).
thehive_ensure_user() {
  local login=$1 type=$2 profile=$3 name=$4 pw=${5:-} org r body
  org=$(cases_env THEHIVE_ORG)
  r=$(thehive_admin GET "/api/v1/user/$login")
  if [[ $(http_code "$r") != 200 ]]; then
    body=$(jq -nc --arg l "$login" --arg t "$type" --arg n "$name" --arg o "$org" --arg p "$profile" \
      '{login: $l, type: $t, name: $n, organisation: $o, profile: $p}')
    r=$(thehive_admin POST /api/v1/user "$body")
    expect "TheHive: user $login" "$r" 201 || return 1
  elif [[ $(http_body "$r" | jq -r '.type') != "$type" ]]; then
    fail "TheHive: user $login exists with type $(http_body "$r" | jq -r '.type'), expected $type (TheHive can't change it; delete the user or run scripts/soc.sh reset cases)"
    return 1
  elif [[ $(http_body "$r" | jq -r --arg o "$org" '[.organisations[]? | select(.organisation == $o) | .profile] | first // empty') != "$profile" ]]; then
    r=$(thehive_admin PUT "/api/v1/user/$login/organisations" \
      "$(jq -nc --arg o "$org" --arg p "$profile" '{organisations: [{organisation: $o, profile: $p, default: true}]}')")
    expect "TheHive: profile of $login" "$r" 200 204 || return 1
  fi
  if [[ -n $pw ]] && [[ $(http_code "$(thehive_as "$login" "$pw" GET /api/v1/user/current)") != 200 ]]; then
    r=$(thehive_admin POST "/api/v1/user/$login/password/set" "$(jq -nc --arg p "$pw" '{password: $p}')")
    expect "TheHive: password of $login" "$r" 204 200 || return 1
  fi
  pass "TheHive: user $login ($type, $org, profile $profile)"
}

bootstrap_thehive() {
  local admin pw org r
  admin=$(cases_env THEHIVE_ADMIN_USER)
  pw=$(cases_env THEHIVE_ADMIN_PASSWORD)
  org=$(cases_env THEHIVE_ORG)

  # Replace the image's default admin password on first run.
  if [[ $(http_code "$(thehive_admin GET /api/v1/user/current)") == 200 ]]; then
    pass "TheHive: admin $admin can log in"
  else
    r=$(thehive_as "$admin" secret POST "/api/v1/user/$admin/password/change" \
      "$(jq -nc --arg p "$pw" '{currentPassword: "secret", password: $p}')")
    if [[ $(http_code "$r") =~ ^20[04]$ ]] && [[ $(http_code "$(thehive_admin GET /api/v1/user/current)") == 200 ]]; then
      pass "TheHive: default admin password replaced"
    else
      fail "TheHive: admin $admin refuses both the password from nodes/cases/.env and the default one"
      return
    fi
  fi

  if [[ $(http_code "$(thehive_admin GET "/api/v1/organisation/$org")") != 200 ]]; then
    r=$(thehive_admin POST /api/v1/organisation "$(jq -nc --arg o "$org" '{name: $o, description: "ASOX SOC"}')")
    expect "TheHive: organisation $org" "$r" 201 || return
  fi
  pass "TheHive: organisation $org"

  # The analyst is org-admin so the TheHive owner can manage case templates,
  # custom fields and the like in the UI (PROJECT.md D42). Scripts never use
  # this password.
  thehive_ensure_user "$(cases_env THEHIVE_ANALYST_USER)" Normal org-admin "SOC analyst" "$(cases_env THEHIVE_ANALYST_PASSWORD)" || return
  # n8n's API user (C3): a Service account (API key only, no password).
  thehive_ensure_user "$(cases_env THEHIVE_N8N_USER)" Service analyst "n8n (API)" || return
  ensure_key TheHive "$(cases_env THEHIVE_N8N_USER)" THEHIVE_N8N_API_KEY thehive_key_login thehive_renew_key || return
  # bootstrap.sh's own org-admin identity in SOC (organisation settings the
  # platform admin can't reach); its key lives only during this run.
  thehive_ensure_user "$(cases_env THEHIVE_BOOTSTRAP_USER)" Service org-admin "bootstrap.sh (API)" || return

  # Cortex connector (C5): Cortex as seen from TheHive (same node), with the
  # API key of Cortex's "thehive" user. Rewritten on every run so a renewed
  # key is picked up.
  local body
  body=$(jq -nc --arg url "$(cases_env CORTEX_URL)" --arg key "$(cases_env CORTEX_THEHIVE_API_KEY)" '{
    statusCheckInterval: "1 minute", refreshDelay: "5 seconds",
    maxRetryOnError: 3, jobTimeout: "3 hours",
    servers: [{
      name: "Cortex", url: $url,
      auth: {type: "bearer", key: $key},
      wsConfig: {},
      includedTheHiveOrganisations: ["*"], excludedTheHiveOrganisations: []
    }]}')
  r=$(thehive_admin PUT /api/v1/admin/config/cortex "$body")
  expect "TheHive: Cortex connector" "$r" 204 200 || return
  pass "TheHive: Cortex connector -> $(cases_env CORTEX_URL)"
  bootstrap_thehive_webhook
  thehive_license_check
  bootstrap_thehive_entities
}

# Webhook to n8n (C4). TheHive 5 splits it in two:
#  - a global endpoint (platform admin): URL and authentication. Webhook
#    endpoints drop custom headers, so the token goes as a bearer key, which
#    TheHive sends as "Authorization: Bearer <token>" (docs/decisions.md A64);
#  - a notification rule in the SOC organisation's settings (org-admin only):
#    every event (AnyEvent) goes to that endpoint. TheHive reads rules only
#    from the organisation's stored settings, not from application.conf.
# Both are replaced on every run, so a new token or URL is picked up.
THEHIVE_WEBHOOK_ENDPOINT=n8n
THEHIVE_WEBHOOK_RULE="n8n (C4)"

bootstrap_thehive_webhook() {
  local token url body r key login
  token=$(cases_env N8N_WEBHOOK_TOKEN)
  url="$(cases_env N8N_WEBHOOK_URL)/webhook/thehive-event"
  if [[ -z $token ]]; then
    skip "TheHive: webhook to n8n not configured: N8N_WEBHOOK_TOKEN is empty (render core first; distributed mode: paste it from the core machine's nodes/core/.env)"
    return 0
  fi
  body=$(jq -nc --arg n "$THEHIVE_WEBHOOK_ENDPOINT" --arg u "$url" --arg t "$token" '{
    name: $n, type: "webhook", url: $u, version: 1, wsConfig: {},
    auth: {type: "bearer", key: $t},
    includedTheHiveOrganisations: ["*"], excludedTheHiveOrganisations: []}')
  r=$(thehive_admin PUT /api/v1/admin/config/global/endpoint "$body")
  expect "TheHive: webhook endpoint $THEHIVE_WEBHOOK_ENDPOINT" "$r" 204 200 || return

  login=$(cases_env THEHIVE_BOOTSTRAP_USER)
  key=$(thehive_renew_key "$login")
  [[ -n $key ]] || { fail "TheHive: could not create a temporary API key for $login"; return; }
  body=$(jq -nc --arg n "$THEHIVE_WEBHOOK_RULE" --arg e "$THEHIVE_WEBHOOK_ENDPOINT" '{
    name: $n, enabled: true, delegate: false, trigger: {name: "AnyEvent"},
    notifiers: [{name: "Webhook", endpoint: $e, enabled: true}]}')
  r=$(thehive_key "$key" PUT /api/v1/notification/organisation "$body")
  # Revoke the key whatever happened.
  thehive_admin DELETE "/api/v1/user/$login/key" >/dev/null
  expect "TheHive: notification rule \"$THEHIVE_WEBHOOK_RULE\"" "$r" 204 200 || return
  pass "TheHive: webhook -> $url (every event of organisation $(cases_env THEHIVE_ORG); temporary key of $login revoked)"
}

# Custom fields, observable types and case templates are the TheHive owner's
# configuration as code: nodes/cases/thehive/entities/, loaded by their own
# idempotent script, which creates and updates by name and deletes nothing
# (a case template TheHive refuses to update is recreated). It makes and
# revokes its own temporary key for THEHIVE_BOOTSTRAP_USER, so it runs after
# the webhook rule has revoked bootstrap's. Without them an alert with a
# `user-account` observable gets HTTP 404 (handoff gotcha "TheHive alerts").
THEHIVE_IMPORT_SCRIPT="$REPO_ROOT/nodes/cases/thehive/scripts/thehive-import.sh"
bootstrap_thehive_entities() {
  if [[ ! -f $THEHIVE_IMPORT_SCRIPT ]]; then
    fail "TheHive: nodes/cases/thehive/scripts/thehive-import.sh not found"
    return 0
  fi
  if bash "$THEHIVE_IMPORT_SCRIPT" 2>&1 \
       | sed -e '/^$/d' -e '/^All checks passed\.$/d' -e '/^[0-9]* check(s) failed\.$/d'; then
    pass "TheHive: nodes/cases/thehive/scripts/thehive-import.sh (custom fields, observable types, case templates)"
  else
    fail "TheHive: nodes/cases/thehive/scripts/thehive-import.sh failed (its FAIL or ERROR lines are above)"
  fi
}

# The online analyzers are the Cortex + MISP owner's configuration as code:
# nodes/cases/cortex/analyzers/analyzers.json, applied by their own idempotent
# script as Cortex's org admin. Keys come from the git-ignored
# analyzer-keys.env on this machine: a missing file is a WARN and a blank key
# a SKIP that leaves the analyzer's configuration in Cortex as it is. MISP_2_1
# stays bootstrap_misp_analyzer's (C7). No return 1: TheHive's part still runs.
CORTEX_ANALYZERS_SCRIPT="$REPO_ROOT/nodes/cases/cortex/analyzers/analyzers.sh"
bootstrap_cortex_analyzers() {
  if [[ ! -f $CORTEX_ANALYZERS_SCRIPT ]]; then
    fail "Cortex: nodes/cases/cortex/analyzers/analyzers.sh not found"
    return 0
  fi
  if bash "$CORTEX_ANALYZERS_SCRIPT" apply 2>&1 \
       | sed -e '/^$/d' -e '/^All checks passed\.$/d' -e '/^[0-9]* check(s) failed\.$/d'; then
    pass "Cortex: nodes/cases/cortex/analyzers/analyzers.sh apply (online analyzers from analyzers.json)"
  else
    fail "Cortex: nodes/cases/cortex/analyzers/analyzers.sh apply failed (its FAIL or ERROR lines are above)"
  fi
}

bootstrap_cases() {
  echo "== bootstrap cases"
  bootstrap_cortex
  bootstrap_misp_analyzer
  bootstrap_cortex_analyzers
  bootstrap_thehive
}

# MISP analyzer in Cortex (C7): enabled in the SOC organisation by its org
# admin, pointing at MISP_URL (as seen from the cases node) with the key of
# MISP's read-only Cortex user. Certificate check off: MISP's certificate is
# self-signed (PROJECT.md 4.1, D25).

bootstrap_misp_analyzer() {
  local key url r id body image
  key=$(cases_env MISP_CORTEX_API_KEY)
  url=$(cases_env MISP_URL)
  if [[ -z $key ]]; then
    skip "Cortex: MISP analyzer not configured: MISP_CORTEX_API_KEY is empty (bootstrap intel first; C7 needs the intel node)"
    return 0
  fi
  body=$(jq -nc --arg a "$MISP_ANALYZER" --arg u "$url" --arg k "$key" '{
    name: $a,
    configuration: {name: ["ASOX MISP"], url: [$u], key: [$k], cert_check: false,
                    auto_extract_artifacts: false, check_tlp: true, max_tlp: 2, check_pap: true, max_pap: 2},
    jobCache: 10, jobTimeout: 30}')
  r=$(cortex_orgadmin GET /api/analyzer)
  id=$(http_body "$r" | jq -r --arg a "$MISP_ANALYZER" '[.[]? | select(.workerDefinitionId == $a or .name == $a) | .id] | first // empty')
  if [[ -z $id ]]; then
    r=$(cortex_orgadmin POST "/api/organization/analyzer/$MISP_ANALYZER" "$body")
    expect "Cortex: enable $MISP_ANALYZER" "$r" 201 || return
  else
    r=$(cortex_orgadmin PATCH "/api/analyzer/$id" "$(jq -c 'del(.name)' <<<"$body")")
    expect "Cortex: configure $MISP_ANALYZER" "$r" 200 || return
  fi
  # Pre-pull its image, so the first job doesn't wait for the download.
  image=$(cortex_analyzer_image "$MISP_ANALYZER")
  if [[ -n $image ]] && docker pull -q "$image" >/dev/null; then
    pass "Cortex: $MISP_ANALYZER enabled -> $url (image $image pulled)"
  else
    fail "Cortex: $MISP_ANALYZER enabled, but its image ($image) could not be pulled"
  fi
}

# --------------------------------------------------------------- intel ---

bootstrap_misp_admin_key() {
  local admin key out
  admin=$(intel_env MISP_ADMIN_EMAIL)
  if [[ $(misp_key_email "$(intel_env MISP_ADMIN_KEY)") == "$admin" ]]; then
    pass "MISP: admin API key works"
    return 0
  fi
  key=$(misp_new_key)
  out=$(misp_cake User change_authkey 1 "$key" 2>&1) || { fail "MISP: setting the admin API key failed: ${out:0:200}"; return 1; }
  if [[ $(misp_key_email "$key") == "$admin" ]]; then
    env_set "$(node_dir intel)/.env" MISP_ADMIN_KEY "$key"
    pass "MISP: admin API key created (stored in nodes/intel/.env)"
  else
    fail "MISP: the new admin API key is refused"
    return 1
  fi
}

# Read-only MISP user for Cortex's analyzer, in the admin's organisation.
bootstrap_misp_cortex_user() {
  local email r org_id role_id user_id key
  email=$(intel_env MISP_CORTEX_USER)
  org_id=$(http_body "$(misp_admin GET /users/view/me)" | jq -r '.User.org_id')
  role_id=$(http_body "$(misp_admin GET /roles)" | jq -r '[.[] | (.Role // .) | select(.name == "Read Only") | .id] | first // empty')
  [[ -n $role_id ]] || { fail "MISP: role \"Read Only\" not found"; return 1; }
  user_id=$(http_body "$(misp_admin GET /admin/users)" | jq -r --arg e "$email" '[.[] | select(.User.email == $e) | .User.id] | first // empty')
  if [[ -z $user_id ]]; then
    r=$(misp_admin POST /admin/users/add "$(jq -nc --arg e "$email" --arg o "$org_id" --arg r "$role_id" \
      '{email: $e, org_id: $o, role_id: $r, change_pw: false, notify: false, termsaccepted: true}')")
    expect "MISP: user $email" "$r" 200 || return 1
    user_id=$(http_body "$r" | jq -r '.User.id')
  else
    r=$(misp_admin POST "/admin/users/edit/$user_id" "$(jq -nc --arg r "$role_id" --arg o "$org_id" '{role_id: $r, org_id: $o, disabled: false}')")
    expect "MISP: user $email" "$r" 200 || return 1
  fi
  pass "MISP: user $email (Read Only, organisation $(intel_env MISP_ORG))"

  if [[ $(misp_key_email "$(intel_env MISP_CORTEX_API_KEY)") == "$email" ]]; then
    pass "MISP: API key of $email works"
    return 0
  fi
  r=$(misp_admin POST "/auth_keys/add/$user_id" '{"comment": "Cortex MISP analyzer (C7), created by bootstrap.sh"}')
  key=$(http_body "$r" | jq -r '.AuthKey.authkey_raw // empty')
  if [[ -n $key && $(misp_key_email "$key") == "$email" ]]; then
    env_set "$(node_dir intel)/.env" MISP_CORTEX_API_KEY "$key"
    pass "MISP: API key of $email created (stored in nodes/intel/.env)"
    # Cortex's MISP analyzer still has the old key until cases is bootstrapped
    # again (soc.sh init does it when both nodes are initialised together).
    info "Cortex's MISP analyzer needs this key: on the cases machine run scripts/render-env.sh && scripts/bootstrap.sh cases (distributed mode: paste MISP_CORTEX_API_KEY into nodes/cases/.env first)"
  else
    fail "MISP: could not create a working API key for $email (HTTP $(http_code "$r"))"
    return 1
  fi
}

# Seed event with the test IOC (C7), created once and published.
bootstrap_misp_seed() {
  local info r id
  info=$(jq -r '.Event.info' "$MISP_SEED_FILE")
  r=$(misp_admin POST /events/restSearch "$(jq -nc --arg i "$info" '{returnFormat: "json", eventinfo: $i, limit: 1, metadata: true}')")
  id=$(http_body "$r" | jq -r '[.response[]?.Event.id] | first // empty')
  if [[ -z $id ]]; then
    r=$(misp_admin POST /events/add "$(cat "$MISP_SEED_FILE")")
    expect "MISP: seed event" "$r" 200 || return 1
    id=$(http_body "$r" | jq -r '.Event.id')
  fi
  if [[ $(http_body "$(misp_admin GET "/events/view/$id")" | jq -r '.Event.published') != true ]]; then
    # Publish without e-mail notifications (there is no mail relay).
    r=$(misp_admin POST "/events/publish/$id/disable_email:1")
    expect "MISP: publish seed event" "$r" 200 || return 1
  fi
  pass "MISP: seed event $id published (\"$info\")"
}

# Warninglists (size cap, R-14), feeds and n8n's Read Only user (C10) are the
# MISP owner's configuration as code: nodes/intel/misp/misp-config.json,
# applied by their own idempotent script (R-22). Its PASS/FAIL/SKIP lines are
# shown as they come; its closing summary is dropped (this script prints one).
MISP_CONFIG_SCRIPT="$REPO_ROOT/nodes/intel/misp/misp-config.sh"
bootstrap_misp_config() {
  if [[ ! -f $MISP_CONFIG_SCRIPT ]]; then
    fail "MISP: nodes/intel/misp/misp-config.sh not found"
    return 1
  fi
  if bash "$MISP_CONFIG_SCRIPT" apply 2>&1 \
       | sed -e '/^$/d' -e '/^All checks passed\.$/d' -e '/^[0-9]* check(s) failed\.$/d'; then
    pass "MISP: nodes/intel/misp/misp-config.sh apply (warninglists, feeds, n8n user)"
  else
    fail "MISP: nodes/intel/misp/misp-config.sh apply failed (its FAIL or ERROR lines are above)"
    return 1
  fi
}

bootstrap_intel() {
  echo "== bootstrap intel"
  bootstrap_misp_admin_key || return
  bootstrap_misp_cortex_user || return
  bootstrap_misp_seed
  bootstrap_misp_config
}

# ---------------------------------------------------------------- main ---

main() {
  [[ ${1:-} == -h || ${1:-} == --help ]] && { usage; exit 0; }
  (( $# == 1 )) || { usage; exit 1; }
  local node=$1
  is_node "$node" || die "unknown node: $node"
  [[ -f "$(node_dir "$node")/.env" ]] || die "nodes/$node/.env not found; run scripts/render-env.sh"
  case $node in
    core)  bootstrap_core ;;
    cases) bootstrap_cases ;;
    intel) bootstrap_intel ;;
    *)    skip "bootstrap $node: nothing to bootstrap yet" ;;
  esac
  finish
}

main "$@"
