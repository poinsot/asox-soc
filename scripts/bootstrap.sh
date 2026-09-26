#!/usr/bin/env bash
# Create the service users, API keys and seed data of a running node.
# Idempotent: existing objects are updated to match the repo and .env.
#
# Usage: scripts/bootstrap.sh <node>
#   core : Wazuh API user n8n-api with a read-only role (C2);
#          indexer user grafana-ro, read-only on wazuh-alerts-* (C8);
#          n8n owner, n8n credentials, and the workflows from
#          nodes/core/n8n/workflows/ that n8n doesn't have yet
#   cases: Cortex indexes, superadmin, SOC organization, org admin and the
#          API users for TheHive (C5) and n8n (C6), with their keys;
#          TheHive admin password, SOC organisation, analyst, API user for
#          n8n (C3) with its key, and the Cortex connector (C5); the MISP
#          analyzer (C7) once intel has created its MISP key
#   intel: MISP admin API key, read-only user for Cortex with its key (C7),
#          and the seed event (nodes/intel/misp/seed/seed-event.json)
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

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

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
    "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/main", "cluster:monitor/health"],
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*"],
      "allowed_actions": ["read", "indices:admin/get", "indices:admin/mappings/get", "indices:admin/resolve/index"]
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

# n8n credentials, with fixed IDs so that exported workflows (which reference
# credentials by ID and name) work on every machine. Values come from .env.
n8n_credentials_json() {
  jq -nc \
    --arg token "$(core_env N8N_WEBHOOK_TOKEN)" \
    --arg wuser "$(core_env WAZUH_N8N_API_USER)" --arg wpass "$(core_env WAZUH_N8N_API_PASSWORD)" '[
    {id: "asoxWebhookToken", name: "ASOX webhook token", type: "httpHeaderAuth",
     data: {name: "X-ASOX-Token", value: $token}},
    {id: "asoxWazuhApiRo01", name: "Wazuh API (n8n-api)", type: "httpBasicAuth",
     data: {user: $wuser, password: $wpass}}
  ]'
}

bootstrap_n8n() {
  local body
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

  # Credential data goes through stdin, never to a file on the host.
  if n8n_credentials_json | n8n_cli -- import:credentials --input=/dev/stdin >/dev/null 2>&1; then
    pass "n8n: credentials \"ASOX webhook token\", \"Wazuh API (n8n-api)\""
  else
    fail "n8n: credential import failed"; return
  fi

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
  bootstrap_indexer
  bootstrap_n8n
}

# --------------------------------------------------------------- cases ---

# Image used to prove that Cortex can start containers (same pinned image as
# soc.sh's utility container).
RUNNER_TEST_IMAGE=alpine:3.24.2

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

  thehive_ensure_user "$(cases_env THEHIVE_ANALYST_USER)" Normal analyst "SOC analyst" "$(cases_env THEHIVE_ANALYST_PASSWORD)" || return
  # n8n's API user (C3): a Service account (API key only, no password).
  thehive_ensure_user "$(cases_env THEHIVE_N8N_USER)" Service analyst "n8n (API)" || return
  ensure_key TheHive "$(cases_env THEHIVE_N8N_USER)" THEHIVE_N8N_API_KEY thehive_key_login thehive_renew_key || return

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
  thehive_license_check
}

bootstrap_cases() {
  echo "== bootstrap cases"
  bootstrap_cortex
  bootstrap_misp_analyzer
  bootstrap_thehive
}

# MISP analyzer in Cortex (C7): enabled in the SOC organisation by its org
# admin, pointing at MISP_URL (as seen from the cases node) with the key of
# MISP's read-only Cortex user. Certificate check off: MISP's certificate is
# self-signed (PROJECT.md 4.1, D25).
MISP_ANALYZER=MISP_2_1

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
  image=$(http_body "$(cortex_orgadmin GET '/api/analyzerdefinition?range=all')" \
    | jq -r --arg a "$MISP_ANALYZER" '.[] | select(.id == $a) | .dockerImage')
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

bootstrap_intel() {
  echo "== bootstrap intel"
  bootstrap_misp_admin_key || return
  bootstrap_misp_cortex_user || return
  bootstrap_misp_seed
}

# ---------------------------------------------------------------- main ---

main() {
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
