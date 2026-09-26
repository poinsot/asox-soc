# shellcheck shell=bash
# MISP helpers for scripts that manage the intel node. Source after
# lib/common.sh (and lib/cases.sh for http_body / http_code).
#  - Calls go to the published port on 127.0.0.1 (works with either
#    BIND_ADDR), so run these scripts on the machine hosting intel.
#  - MISP's certificate is self-signed (PROJECT.md 4.1): curl -k.

MISP_API=${MISP_API:-https://127.0.0.1:9443}
# shellcheck disable=SC2034  # used by the scripts that source this file
MISP_SEED_FILE="$REPO_ROOT/nodes/intel/misp/seed/seed-event.json"

intel_env() { env_get "$(node_dir intel)/.env" "$1"; }

# misp_as KEY METHOD PATH [JSON]: body, then a last line with the HTTP status.
misp_as() {
  local key=$1 method=$2 path=$3 data=${4:-}
  local -a args=(-sk -w '\n%{http_code}' -X "$method" -H "Authorization: $key"
    -H 'Accept: application/json' -H 'Content-Type: application/json' "$MISP_API$path")
  [[ -n $data ]] && args+=(--data-binary "$data")
  curl "${args[@]}" || printf '\n000'
}
misp_admin() { misp_as "$(intel_env MISP_ADMIN_KEY)" "$@"; }

# E-mail of the user owning API key <key>, or nothing if MISP refuses it.
misp_key_email() {
  local r
  [[ -n $1 ]] || return 0
  r=$(misp_as "$1" GET /users/view/me)
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -r '.User.email // empty'
  return 0
}

# A new MISP API key: 40 characters, letters and digits.
misp_new_key() {
  openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 40
}

# MISP's CLI inside misp-core, as the web server user.
misp_cake() {
  compose intel exec -T misp-core sudo -u www-data /var/www/MISP/app/Console/cake "$@"
}
