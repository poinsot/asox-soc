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
