# shellcheck shell=bash
# n8n helpers for scripts that manage the core node. Source after
# lib/common.sh.
#  - Scripts use n8n's public API (/api/v1) with N8N_API_KEY, created by
#    bootstrap.sh with only the scopes they need. The UI login (/rest/login)
#    is rate-limited to 5 attempts per window, so it is used by bootstrap.sh
#    only (owner check, API key creation).
#  - The published port is reached on 127.0.0.1, which works with either
#    BIND_ADDR.
#  - CLI commands run in a one-off container sharing n8n's data volume, so
#    they don't compete for memory with the running server.

N8N_URL=${N8N_URL:-http://127.0.0.1:5678}
# shellcheck disable=SC2034  # used by the scripts that source this file
N8N_WORKFLOW_DIR="$REPO_ROOT/nodes/core/n8n/workflows"
N8N_API_SCOPES='["workflow:list","workflow:read","workflow:activate","workflow:deactivate","execution:list","execution:read"]'
N8N_API_KEY_LABEL=asox-scripts
N8N_JAR=""

n8n_env() { env_get "$(node_dir core)/.env" "$1"; }

n8n_cleanup() { [[ -n $N8N_JAR ]] && rm -f "$N8N_JAR"; return 0; }

# ---- public API (API key) ----

# n8n_api METHOD PATH [JSON] -- prints the response body.
n8n_api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(-s -X "$method" -H "X-N8N-API-KEY: $(n8n_env N8N_API_KEY)" "$N8N_URL/api/v1$path")
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  curl "${args[@]}"
}

n8n_api_ok() {
  [[ -n $(n8n_env N8N_API_KEY) ]] \
    && [[ $(curl -s -o /dev/null -w '%{http_code}' -H "X-N8N-API-KEY: $(n8n_env N8N_API_KEY)" \
         "$N8N_URL/api/v1/workflows?limit=1") == 200 ]]
}

# IDs of the workflows in n8n, one per line.
n8n_workflow_ids() { n8n_api GET "/workflows?limit=250" | jq -r '.data[].id'; }

n8n_workflow_id_by_name() {
  n8n_api GET "/workflows?limit=250" | jq -r --arg n "$1" '.data[] | select(.name == $n) | .id' | head -n 1
}

# Activate (publish) a workflow on the running server, which registers its
# webhooks. When n8n refuses, its reason is left in N8N_ACTIVATE_ERROR.
N8N_ACTIVATE_ERROR=""
n8n_activate() {
  local resp
  resp=$(n8n_api POST "/workflows/$1/activate")
  [[ $(jq -r '.active // false' <<<"$resp" 2>/dev/null) == true ]] && return 0
  N8N_ACTIVATE_ERROR=$(jq -r '.message // empty' <<<"$resp" 2>/dev/null | tr '\n' ' ' | head -c 200)
  return 1
}
n8n_deactivate() { n8n_api POST "/workflows/$1/deactivate" >/dev/null; }

# ---- UI session (bootstrap only) ----

n8n_owner_exists() {
  [[ $(curl -sf "$N8N_URL/rest/settings" | jq -r '.data.userManagement.showSetupOnFirstLoad') == false ]]
}

n8n_login() {
  [[ -n $N8N_JAR ]] && return 0
  N8N_JAR=$(mktemp)
  local body
  body=$(jq -nc --arg e "$(n8n_env N8N_OWNER_EMAIL)" --arg p "$(n8n_env N8N_OWNER_PASSWORD)" \
    '{emailOrLdapLoginId: $e, password: $p}')
  if ! curl -sf -c "$N8N_JAR" -H 'Content-Type: application/json' "$N8N_URL/rest/login" -d "$body" >/dev/null; then
    rm -f "$N8N_JAR"; N8N_JAR=""
    return 1
  fi
}

# n8n_rest METHOD PATH [JSON] -- internal API with the owner session.
n8n_rest() {
  local method=$1 path=$2 data=${3:-}
  n8n_login || return 1
  local -a args=(-s -b "$N8N_JAR" -X "$method" "$N8N_URL/rest$path")
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  curl "${args[@]}"
}

# Replace the scripts' API key (label N8N_API_KEY_LABEL); prints the new key.
n8n_create_api_key() {
  local id resp
  for id in $(n8n_rest GET /api-keys | jq -r --arg l "$N8N_API_KEY_LABEL" '(.data.items // .data // [])[]? | select(.label == $l) | .id'); do
    n8n_rest DELETE "/api-keys/$id" >/dev/null
  done
  resp=$(n8n_rest POST /api-keys "$(jq -nc --arg l "$N8N_API_KEY_LABEL" --argjson s "$N8N_API_SCOPES" \
    '{label: $l, expiresAt: null, scopes: $s}')")
  jq -r '.data.rawApiKey // empty' <<<"$resp"
}

# ---- CLI ----

# n8n CLI in a one-off container (same image, volume and secrets as n8n).
# Extra "docker compose run" options may precede "--".
n8n_cli() {
  local -a opts=()
  while (( $# > 0 )) && [[ $1 != -- ]]; do opts+=("$1"); shift; done
  [[ ${1:-} == -- ]] && shift
  compose core run --rm --no-deps -T "${opts[@]}" --entrypoint n8n n8n "$@"
}

# ---- credentials ----

# n8n credentials, with fixed IDs so that exported workflows (which reference
# credentials by ID and name) work on every machine. Values come from .env.
# The webhook token has two forms: header X-ASOX-Token (Wazuh, scripts) and
# "Authorization: Bearer" (TheHive's webhooks can't send other headers, C4).
# MISP (C10) takes the bare key in the Authorization header; its self-signed
# certificate (PROJECT.md 4.1) is accepted by the HTTP Request node's own
# "ignore SSL issues" option, which a Header Auth credential can't carry.
# The Wazuh indexer (C11, C13) is verified against the root CA, which n8n
# trusts through NODE_EXTRA_CA_CERTS (PROJECT.md 4.1), not through the
# credential.
# shellcheck disable=SC2034  # used by the scripts that source this file
N8N_CREDENTIALS='"ASOX webhook token", "ASOX webhook token (Bearer)", "Wazuh API (n8n-api)", "TheHive API (n8n)", "Cortex API (n8n)", "MISP API (n8n)", "Wazuh indexer (n8n-indexer)"'
n8n_credentials_json() {
  jq -nc \
    --arg token "$(n8n_env N8N_WEBHOOK_TOKEN)" \
    --arg wuser "$(n8n_env WAZUH_N8N_API_USER)" --arg wpass "$(n8n_env WAZUH_N8N_API_PASSWORD)" \
    --arg thkey "$(n8n_env THEHIVE_N8N_API_KEY)" --arg thurl "$(n8n_env THEHIVE_URL)" \
    --arg cxkey "$(n8n_env CORTEX_N8N_API_KEY)" --arg cxurl "$(n8n_env CORTEX_URL)" \
    --arg mikey "$(n8n_env MISP_N8N_API_KEY)" \
    --arg ixuser "$(n8n_env N8N_INDEXER_USER)" --arg ixpass "$(n8n_env N8N_INDEXER_PASSWORD)" '[
    {id: "asoxWebhookToken", name: "ASOX webhook token", type: "httpHeaderAuth",
     data: {name: "X-ASOX-Token", value: $token}},
    {id: "asoxWebhookBear1", name: "ASOX webhook token (Bearer)", type: "httpHeaderAuth",
     data: {name: "Authorization", value: ("Bearer " + $token)}},
    {id: "asoxWazuhApiRo01", name: "Wazuh API (n8n-api)", type: "httpBasicAuth",
     data: {user: $wuser, password: $wpass}},
    {id: "asoxTheHiveApi01", name: "TheHive API (n8n)", type: "theHiveProjectApi",
     data: {ApiKey: $thkey, url: $thurl, allowUnauthorizedCerts: false}},
    {id: "asoxCortexApi001", name: "Cortex API (n8n)", type: "cortexApi",
     data: {cortexApiKey: $cxkey, host: $cxurl}},
    {id: "asoxMispApi00001", name: "MISP API (n8n)", type: "httpHeaderAuth",
     data: {name: "Authorization", value: $mikey}},
    {id: "asoxIndexerN8n01", name: "Wazuh indexer (n8n-indexer)", type: "httpBasicAuth",
     data: {user: $ixuser, password: $ixpass}}
  ]'
}

# Import the credentials above. n8n's import overwrites a credential with
# the same ID, so an existing one is updated to the values in .env (a rotated
# key arrives with the next run). Credential data goes through stdin, never
# to a file on the host. The running n8n isn't restarted: it reads
# credentials at execution time.
n8n_import_credentials() {
  n8n_credentials_json | n8n_cli -- import:credentials --input=/dev/stdin >/dev/null 2>&1
}

# The same for the one credential with ID <id>, leaving the others as they
# are (e.g. on an instance whose n8n must not be touched otherwise).
n8n_import_credential() {
  local id=$1 json
  json=$(n8n_credentials_json | jq -c --arg id "$id" 'map(select(.id == $id))')
  [[ $json != '[]' ]] || return 1
  printf '%s\n' "$json" | n8n_cli -- import:credentials --input=/dev/stdin >/dev/null 2>&1
}

# ---- workflow import ----

# Wait until the webhooks of an activated workflow file are registered (a
# fraction of a second after activation). Only webhooks that require
# authentication are probed, with an invalid token, so the probe can never
# start an execution; others just get a short pause.
n8n_wait_webhooks() {
  local f=$1 method path code i
  local probe=invalid-registration-probe   # deliberately wrong credentials
  while IFS=$'\t' read -r method path; do
    for (( i = 0; i < 100; i++ )); do
      code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" -H "X-ASOX-Token: $probe" \
        -u "$probe:$probe" "$N8N_URL/webhook/$path" || true)
      [[ $code != 404 ]] && break
      sleep 0.3
    done
    [[ $code != 404 ]] || return 1
  done < <(jq -r '.nodes[] | select(.type == "n8n-nodes-base.webhook" and (.parameters.authentication // "none") != "none")
                  | [(.parameters.httpMethod // "GET"), .parameters.path] | @tsv' "$f")
  if jq -e 'any(.nodes[]; .type == "n8n-nodes-base.webhook" and (.parameters.authentication // "none") == "none")' >/dev/null "$f"; then
    sleep 2
  fi
  return 0
}

# Import workflow files (overwriting workflows with the same ID), then
# activate those whose file says "active": true. Prints PASS/FAIL lines.
# n8n refuses to activate a workflow while a sub-workflow it calls is still
# inactive, and the files come in name order, not dependency order (R-25):
# activation is repeated over the refused ones until every workflow is active
# or a whole pass activates nothing. What is left gets a FAIL line with n8n's
# reason; a last check reads the active state back from the server.
n8n_import_workflows() {
  (( $# > 0 )) || return 0
  local tmp f id name active_ids
  # Deactivate existing active copies through the running server first, so
  # it unregisters their webhooks before the CLI changes the database.
  active_ids=$(n8n_api GET "/workflows?limit=250&active=true" | jq -r '.data[].id')
  for f in "$@"; do
    id=$(jq -r '.id' "$f")
    grep -qx "$id" <<<"$active_ids" && n8n_deactivate "$id"
  done
  tmp=$(mktemp -d)
  cp "$@" "$tmp/"
  chmod 755 "$tmp"; chmod 644 "$tmp"/*.json
  if ! n8n_cli -v "$tmp:/import:ro" -- import:workflow --separate --input=/import >/dev/null 2>&1; then
    rm -rf "$tmp"
    fail "n8n: import of $* failed"
    return 1
  fi
  rm -rf "$tmp"

  local -a pending=() refused=() wanted=()
  local -A reason=()
  for f in "$@"; do
    if [[ $(jq -r '.active // false' "$f") == true ]]; then pending+=("$f"); wanted+=("$(jq -r '.id' "$f")")
    else pass "n8n: workflow $(jq -r '.name' "$f") imported (inactive)"; fi
  done
  local progress=1
  while (( ${#pending[@]} > 0 && progress )); do
    progress=0; refused=()
    for f in "${pending[@]}"; do
      id=$(jq -r '.id' "$f"); name=$(jq -r '.name' "$f")
      if n8n_activate "$id"; then
        progress=1
        if n8n_wait_webhooks "$f"; then pass "n8n: workflow $name imported and active"
        else fail "n8n: workflow $name imported and active, but its webhook did not register"; fi
      else
        reason[$id]=$N8N_ACTIVATE_ERROR; refused+=("$f")
      fi
    done
    pending=("${refused[@]}")
    (( ${#pending[@]} > 0 && progress )) && info "n8n: ${#pending[@]} workflow(s) refused (a sub-workflow wasn't active yet), trying them again"
  done
  for f in "${pending[@]}"; do
    id=$(jq -r '.id' "$f")
    fail "n8n: workflow $(jq -r '.name' "$f") ($id) imported but could not be activated: ${reason[$id]:-no reason given by n8n}"
  done
  (( ${#wanted[@]} > 0 )) || return 0
  local inactive
  active_ids=$(n8n_api GET "/workflows?limit=250&active=true" | jq -r '.data[].id')
  inactive=$(comm -23 <(printf '%s\n' "${wanted[@]}" | sort) <(sort <<<"$active_ids") | paste -sd' ' -)
  if [[ -z $inactive ]]; then pass "n8n: all ${#wanted[@]} workflow(s) marked active are active on the server"
  elif (( ${#pending[@]} == 0 )); then fail "n8n: not active on the server after activation: $inactive"; fi
}
