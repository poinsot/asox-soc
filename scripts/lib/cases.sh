# shellcheck shell=bash
# TheHive and Cortex helpers for scripts that manage the cases node. Source
# after lib/common.sh.
#  - Calls go to the published ports on 127.0.0.1, which works with either
#    BIND_ADDR, so run these scripts on the machine hosting cases.
#  - Scripts authenticate with the admin logins from nodes/cases/.env (basic
#    authentication; Cortex enables it in its application.conf).

THEHIVE_API=${THEHIVE_API:-http://127.0.0.1:9000}
CORTEX_API=${CORTEX_API:-http://127.0.0.1:9001}

cases_env() { env_get "$(node_dir cases)/.env" "$1"; }

# _call AUTH-ARGS... -- METHOD URL [JSON]: prints the body, then a last line
# with the HTTP status. Callers split them with http_body / http_code.
_call() {
  local -a auth=()
  while [[ $1 != -- ]]; do auth+=("$1"); shift; done
  shift
  local method=$1 url=$2 data=${3:-}
  local -a args=(-s -w '\n%{http_code}' -X "$method" "${auth[@]}" "$url")
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' --data-binary "$data")
  curl "${args[@]}" || printf '\n000'
}
http_body() { sed '$d' <<<"$1"; }
http_code() { tail -n 1 <<<"$1"; }

# thehive_as USER PASSWORD METHOD PATH [JSON]  (PATH starts with /api)
thehive_as() { local u=$1 p=$2; shift 2; _call -u "$u:$p" -- "$1" "$THEHIVE_API$2" "${3:-}"; }
thehive_admin() { thehive_as "$(cases_env THEHIVE_ADMIN_USER)" "$(cases_env THEHIVE_ADMIN_PASSWORD)" "$@"; }
thehive_key() { local k=$1; shift; _call -H "Authorization: Bearer $k" -- "$1" "$THEHIVE_API$2" "${3:-}"; }

# cortex_as USER PASSWORD METHOD PATH [JSON]
cortex_as() { local u=$1 p=$2; shift 2; _call -u "$u:$p" -- "$1" "$CORTEX_API$2" "${3:-}"; }
cortex_admin() { cortex_as "$(cases_env CORTEX_ADMIN_USER)" "$(cases_env CORTEX_ADMIN_PASSWORD)" "$@"; }
cortex_orgadmin() { cortex_as "$(cases_env CORTEX_ORGADMIN_USER)" "$(cases_env CORTEX_ORGADMIN_PASSWORD)" "$@"; }
cortex_key() { local k=$1; shift; _call -H "Authorization: Bearer $k" -- "$1" "$CORTEX_API$2" "${3:-}"; }
cortex_noauth() { _call -- "$@"; }

# Login of the user owning API key <key>, or nothing if the key is refused.
thehive_key_login() {
  local r
  [[ -n $1 ]] || return 0
  r=$(thehive_key "$1" GET /api/v1/user/current)
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -r '.login'
  return 0
}
cortex_key_login() {
  local r
  [[ -n $1 ]] || return 0
  r=$(cortex_key "$1" GET /api/user/current)
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -r '.id'
  return 0
}

# Image used to prove that Cortex can start containers (same pinned image as
# soc.sh's utility container).
# shellcheck disable=SC2034  # used by the scripts that source this file
RUNNER_TEST_IMAGE=alpine:3.24.2
# The one analyzer enabled in Phase 1 (C7).
# shellcheck disable=SC2034
MISP_ANALYZER=MISP_2_1

# Docker image of analyzer <id> in Cortex's catalog (empty if unknown).
cortex_analyzer_image() {
  http_body "$(cortex_orgadmin GET '/api/analyzerdefinition?range=all')" \
    | jq -r --arg a "$1" '.[]? | select(.id == $a) | .dockerImage' 2>/dev/null
  return 0
}

# Start a throwaway container the way Cortex starts analyzers: through the
# Docker socket from inside the Cortex container, as Cortex's user, on the
# analyzer network, with a job folder mounted by its HOST path. The container
# writes a file that Cortex must then see under its own job directory path.
# Prints nothing on success, the problem otherwise; returns 1 on failure.
cortex_test_container() {
  local image=$1 host_dir net name out
  host_dir=$(cases_env CORTEX_JOBS_HOST_DIR)
  net=$(cases_env CORTEX_ANALYZER_NETWORK)
  name="asox-runner-test-$$"
  compose cases exec -T cortex mkdir -p "/tmp/cortex-jobs/$name" || { echo "cannot create a job folder"; return 1; }
  if ! out=$(compose cases exec -T cortex docker run --rm --network "$net" \
      -v "$host_dir/$name:/job" "$image" sh -c 'echo ok > /job/output' 2>&1); then
    compose cases exec -T cortex rm -rf "/tmp/cortex-jobs/$name"
    echo "docker run failed: ${out:0:200}"; return 1
  fi
  out=$(compose cases exec -T cortex cat "/tmp/cortex-jobs/$name/output" 2>/dev/null || true)
  # The file was written by the container's root user: remove it from a
  # container too, since Cortex's user may not own it.
  compose cases exec -T cortex docker run --rm -v "$host_dir:/jobs" "$image" rm -rf "/jobs/$name" >/dev/null 2>&1 || true
  [[ $out == ok ]] || { echo "the container's output is not visible in Cortex's job directory"; return 1; }
}

# ---- TheHive license (docs/decisions.md A57) ----

# Warn when a trial has this many days left or fewer.
THEHIVE_LICENSE_WARN_DAYS=${THEHIVE_LICENSE_WARN_DAYS:-3}

# Prints "<kind>|<plan>|<expires epoch s>|<isValid>|<webhooks>" from
# /api/v1/status (<webhooks>: true if the license includes webhook
# notifications, which C4 needs); returns 1 if TheHive doesn't answer.
thehive_license_status() {
  local r
  r=$(thehive_admin GET /api/v1/status)
  [[ $(http_code "$r") == 200 ]] || return 1
  http_body "$r" | jq -r '.license // {} | "\(.kind // "none")|\(.plan // "none")|\((.expiresAt // 0) / 1000 | floor)|\(.isValid // false)|\((.capabilities // []) | index("notification.webhook") != null)"'
}

# One-line description, e.g. "Platinum Trial, valid until 2026-10-11 (15 days left)".
thehive_license_describe() {
  local kind plan exp valid webhooks days
  IFS='|' read -r kind plan exp valid webhooks <<<"$1"
  days=$(( (exp - $(date +%s)) / 86400 ))
  if [[ $valid == true ]]; then
    printf '%s %s, valid until %s (%d days left)' "$plan" "$kind" "$(date -u -d "@$exp" +%F)" "$days"
  else
    printf '%s %s, NOT VALID (expiry date %s): TheHive is read-only' "$plan" "$kind" "$(date -u -d "@$exp" +%F)"
  fi
}

# PASS, or WARN when TheHive is read-only (no valid license), on a trial
# with THEHIVE_LICENSE_WARN_DAYS days left or fewer, or when the license
# doesn't include webhooks (C4). Never fails.
thehive_license_check() {
  local s kind plan exp valid webhooks days hint
  if ! s=$(thehive_license_status); then
    warn "TheHive license: status not available (is TheHive running?)"
    return 0
  fi
  IFS='|' read -r kind plan exp valid webhooks <<<"$s"
  days=$(( (exp - $(date +%s)) / 86400 ))
  hint="request a free Community license and apply it (nodes/cases/thehive/README.md, section License)"
  if [[ $valid != true ]]; then
    warn "TheHive license: $(thehive_license_describe "$s"); $hint"
  elif [[ $kind == Trial ]] && (( days <= THEHIVE_LICENSE_WARN_DAYS )); then
    warn "TheHive license: $(thehive_license_describe "$s"); then TheHive becomes read-only: $hint"
  else
    pass "TheHive license: $(thehive_license_describe "$s")"
  fi
  if [[ $valid == true && $webhooks != true ]]; then
    warn "TheHive license: $plan $kind doesn't include webhook notifications, so TheHive can't send events to n8n (C4)"
  fi
}
