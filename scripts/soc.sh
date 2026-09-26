#!/usr/bin/env bash
# ASOX SOC entry point (PROJECT.md section 8.1).
#
# Usage: scripts/soc.sh <command> [args]
#   init  <mode|nodes...>   first-time setup on this machine (idempotent)
#   up    <mode|nodes...>   start nodes
#   down  [mode|nodes...]   stop nodes, keeping volumes (default: all)
#   status                  container state and health
#   info  [mode|nodes...]   URLs and UI logins of running services
#   reset <mode|nodes...> [--yes]
#                           delete volumes and generated secrets (and the
#                           Wazuh certificates for core); asks to confirm
#
# Modes: core (core + lab), cases, cases-intel, core-cases (core + cases + lab),
#        full (all). Nodes: core, cases, intel, lab.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/wazuh.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/wazuh.sh"
# shellcheck source=scripts/lib/cases.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/cases.sh"

SCRIPTS="$REPO_ROOT/scripts"
UP_TIMEOUT=${SOC_UP_TIMEOUT:-900}
# Throwaway container used to delete files created by containers as root.
UTIL_IMAGE=alpine:3.24.2

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

have_env() { [[ -f "$(node_dir "$1")/.env" ]]; }

has_services() { [[ -n $(compose "$1" config --services 2>/dev/null) ]]; }

require_env() {
  local n
  for n in "$@"; do
    have_env "$n" || die "nodes/$n/.env not found; run: scripts/soc.sh init <mode> first"
  done
}

# Nodes that have been initialised on this machine (have a .env).
initialised_nodes() {
  local n
  for n in "${ALL_NODES[@]}"; do have_env "$n" && printf '%s\n' "$n"; done
  return 0
}

ensure_soc_net() {
  [[ $TOPO_DEPLOY_MODE == single ]] || return 0
  if docker network inspect "$SOC_NET" >/dev/null 2>&1; then
    pass "network $SOC_NET exists"
  else
    docker network create "$SOC_NET" >/dev/null
    pass "network $SOC_NET created"
  fi
}

warn_stale_env() {
  local n
  for n in "$@"; do
    if [[ $TOPOLOGY_FILE -nt "$(node_dir "$n")/.env" ]]; then
      warn "$n: topology.env is newer than nodes/$n/.env; run scripts/render-env.sh"
    fi
  done
}

# Run an optional helper script (added by later build steps) if it exists.
run_step() {
  local script=$1; shift
  if [[ -x "$SCRIPTS/$script" ]]; then
    info "running $script $*"
    "$SCRIPTS/$script" "$@"
  else
    skip "$script not present yet"
  fi
}

start_nodes() {
  local n
  for n in "$@"; do
    if ! has_services "$n"; then skip "$n: no services defined yet"; continue; fi
    info "starting $n"
    compose "$n" up -d --wait --wait-timeout "$UP_TIMEOUT"
    pass "$n: up"
  done
}

cmd_init() {
  (( $# > 0 )) || die "usage: soc.sh init <mode|nodes...>"
  local -a nodes
  mapfile -t nodes < <(resolve_nodes "$@")
  info "init: ${nodes[*]}"

  "$SCRIPTS/preflight.sh" "$@"
  "$SCRIPTS/render-env.sh"
  load_topology

  local n
  for n in "${nodes[@]}"; do
    [[ $n == core ]] && run_step gen-certs.sh   # idempotent: keeps existing files
  done

  ensure_soc_net
  for n in "${nodes[@]}"; do
    has_services "$n" || continue
    info "pulling and building images for $n"
    compose "$n" pull --ignore-buildable --quiet
    compose "$n" build --quiet
  done
  start_nodes "${nodes[@]}"
  for n in "${nodes[@]}"; do
    run_step bootstrap.sh "$n"
  done
  run_step healthcheck.sh "${nodes[@]}"
  pass "init complete: ${nodes[*]} (run scripts/soc.sh info for URLs and logins)"
}

cmd_up() {
  (( $# > 0 )) || die "usage: soc.sh up <mode|nodes...>"
  local -a nodes
  mapfile -t nodes < <(resolve_nodes "$@")
  require_env "${nodes[@]}"
  load_topology
  warn_stale_env "${nodes[@]}"
  ensure_soc_net
  start_nodes "${nodes[@]}"
}

cmd_down() {
  local -a nodes
  if (( $# > 0 )); then mapfile -t nodes < <(resolve_nodes "$@"); else mapfile -t nodes < <(initialised_nodes); fi
  local i n
  # Stop in reverse order so dependants go first.
  for (( i = ${#nodes[@]} - 1; i >= 0; i-- )); do
    n=${nodes[$i]}
    have_env "$n" || { skip "$n: not initialised"; continue; }
    compose "$n" down
    pass "$n: down"
  done
}

cmd_status() {
  local n
  for n in $(initialised_nodes); do
    echo "== $n ($(env_get "$(node_dir "$n")/.env" SOC_INSTANCE)-$n)"
    if has_services "$n"; then
      compose "$n" ps --all --format 'table {{.Service}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'
    else
      echo "(no services defined yet)"
    fi
  done
}

# node | service | label | URL (HOST = address shown to the user) | user var | password var
INFO_ENTRIES=(
  "core|grafana|Grafana|http://HOST:3000|GRAFANA_ADMIN_USER|GRAFANA_ADMIN_PASSWORD"
  "core|n8n|n8n|http://HOST:5678|N8N_OWNER_EMAIL|N8N_OWNER_PASSWORD"
  "core|wazuh-manager|Wazuh API|https://HOST:55000|WAZUH_API_ADMIN_USER|WAZUH_API_ADMIN_PASSWORD"
  "cases|thehive|TheHive|http://HOST:9000|THEHIVE_ADMIN_USER|THEHIVE_ADMIN_PASSWORD"
  "cases|thehive|TheHive SOC|http://HOST:9000|THEHIVE_ANALYST_USER|THEHIVE_ANALYST_PASSWORD"
  "cases|cortex|Cortex|http://HOST:9001|CORTEX_ADMIN_USER|CORTEX_ADMIN_PASSWORD"
  "cases|cortex|Cortex SOC|http://HOST:9001|CORTEX_ORGADMIN_USER|CORTEX_ORGADMIN_PASSWORD"
  "intel|misp-nginx|MISP|https://HOST:9443|MISP_ADMIN_EMAIL|MISP_ADMIN_PASSWORD"
)

cmd_info() {
  local -a nodes
  if (( $# > 0 )); then mapfile -t nodes < <(resolve_nodes "$@"); else mapfile -t nodes < <(initialised_nodes); fi
  load_topology
  local entry n node svc label url uvar pvar envf host running shown=0
  for node in "${nodes[@]}"; do
    have_env "$node" || continue
    has_services "$node" || continue
    envf="$(node_dir "$node")/.env"
    running=$(compose "$node" ps --status running --services 2>/dev/null || true)
    for entry in "${INFO_ENTRIES[@]}"; do
      IFS='|' read -r n svc label url uvar pvar <<<"$entry"
      [[ $n == "$node" ]] || continue
      grep -qx "$svc" <<<"$running" || continue
      if [[ $TOPO_DEPLOY_MODE == single ]]; then
        host=localhost
      else
        host=$(env_get "$TOPOLOGY_FILE" "${node^^}_HOST")
      fi
      printf '%-11s %-28s user: %-24s password: %s\n' "$label" "${url//HOST/$host}" \
        "$(env_get "$envf" "$uvar")" "$(env_get "$envf" "$pvar")"
      shown=$((shown + 1))
    done
    # TheHive's license decides whether it is writable (docs/decisions.md A57).
    if [[ $node == cases ]] && grep -qx thehive <<<"$running"; then
      local lic
      if lic=$(thehive_license_status); then
        printf '%-11s %s\n' "" "license: $(thehive_license_describe "$lic")"
      fi
    fi
  done
  (( shown > 0 )) || echo "No running services with a UI. Start them with: scripts/soc.sh up <mode>"
}

cmd_reset() {
  local yes=0 arg
  local -a args=()
  for arg in "$@"; do
    if [[ $arg == --yes ]]; then yes=1; else args+=("$arg"); fi
  done
  (( ${#args[@]} > 0 )) || die "usage: soc.sh reset <mode|nodes...> [--yes]"
  local -a nodes
  mapfile -t nodes < <(resolve_nodes "${args[@]}")

  echo "This permanently deletes, for: ${nodes[*]}"
  echo "  - the containers and ALL data volumes"
  echo "  - the generated .env (secrets and API keys)"
  [[ " ${nodes[*]} " == *" core "* ]] && echo "  - the Wazuh certificates (agents must re-enroll)"
  [[ " ${nodes[*]} " == *" cases "* ]] && echo "  - the Cortex job directory"
  [[ " ${nodes[*]} " == *" lab "* && " ${nodes[*]} " != *" core "* ]] && echo "  - the lab agent's registration on the manager"
  if (( ! yes )); then
    local reply
    read -r -p "Type 'reset' to continue: " reply
    [[ $reply == reset ]] || die "aborted"
  fi

  local n dir
  for n in "${nodes[@]}"; do
    dir=$(node_dir "$n")
    # A fresh lab agent can only enroll once the manager forgets the old one
    # (resetting core forgets every agent anyway).
    if [[ $n == lab && " ${nodes[*]} " != *" core "* ]]; then
      forget_lab_agent "$(env_get "$dir/.env" LAB_AGENT_NAME)"
    fi
    if have_env "$n"; then
      compose "$n" down --volumes --remove-orphans
      rm -f "$dir/.env"
    fi
    case $n in
      core)  clear_dir "$dir/certs" ;;
      cases) clear_dir "$dir/cortex/jobs" ;;
    esac
    pass "$n: reset"
  done
}

forget_lab_agent() {
  local name=${1:-lab-agent} id
  if wazuh_manager_running && wazuh_admin_login; then
    if id=$(wazuh_remove_agent "$name"); then
      if [[ -n $id ]]; then pass "removed agent $name (ID $id) from the manager"
      else skip "agent $name is not registered on the manager"; fi
      return 0
    fi
  fi
  warn "could not remove agent $name from the manager (core not running here?)."
  warn "Before the lab agent enrolls again, on the core machine run:"
  warn "  docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/manage_agents -r <agent-id>"
}

# Empty a generated directory, keeping its .gitkeep. Falls back to a
# throwaway container for files written as root by containers.
clear_dir() {
  local d=$1
  [[ -d $d ]] || return 0
  if ! find "$d" -mindepth 1 ! -name .gitkeep -delete 2>/dev/null; then
    docker run --rm -v "$d:/d" "$UTIL_IMAGE" \
      find /d -mindepth 1 ! -name .gitkeep -delete
  fi
}

main() {
  local cmd=${1:-}
  [[ -n $cmd ]] || { usage; exit 1; }
  shift
  case $cmd in
    init)   cmd_init "$@" ;;
    up)     cmd_up "$@" ;;
    down)   cmd_down "$@" ;;
    status) cmd_status ;;
    info)   cmd_info "$@" ;;
    reset)  cmd_reset "$@" ;;
    -h|--help|help) usage ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
