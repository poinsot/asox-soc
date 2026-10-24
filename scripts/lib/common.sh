# shellcheck shell=bash
# Shared helpers for scripts/*.sh. Source it; don't run it.
# Globals below are used by the scripts that source this file.
# shellcheck disable=SC2034

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOPOLOGY_FILE="$REPO_ROOT/topology.env"
ALL_NODES=(core cases intel lab)
SOC_NET=soc-net

FAILURES=0

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
warn() { printf 'WARN  %s\n' "$*"; }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf '....  %s\n' "$*"; }
die()  { printf 'ERROR %s\n' "$*" >&2; exit 1; }

# Print a script's usage: its header comment block after the shebang, up to
# the first line that isn't a comment or is a shellcheck directive.
print_usage() {
  awk 'NR == 1 { next } !/^#/ || /^# shellcheck/ { exit } { sub(/^# ?/, ""); print }' "$1"
}

node_dir() { printf '%s/nodes/%s' "$REPO_ROOT" "$1"; }

is_node() {
  local n
  for n in "${ALL_NODES[@]}"; do [[ $n == "$1" ]] && return 0; done
  return 1
}

# Expand run modes (PROJECT.md 8.1) and node names into a unique node list.
# Prints one node per line, in ALL_NODES order.
resolve_nodes() {
  local -A want=()
  local arg n
  for arg in "$@"; do
    case "$arg" in
      core)        want[core]=1; want[lab]=1 ;;
      cases)       want[cases]=1 ;;
      cases-intel) want[cases]=1; want[intel]=1 ;;
      core-cases)  want[core]=1; want[cases]=1; want[lab]=1 ;;
      full)        for n in "${ALL_NODES[@]}"; do want[$n]=1; done ;;
      intel|lab)   want[$arg]=1 ;;
      *) die "unknown mode or node: $arg (modes: core cases cases-intel core-cases full; nodes: core cases intel lab; mode core includes lab)" ;;
    esac
  done
  for n in "${ALL_NODES[@]}"; do
    [[ -n ${want[$n]:-} ]] && printf '%s\n' "$n"
  done
  return 0
}

# Read KEY from a KEY=VALUE file without sourcing it. Prints nothing if absent.
env_get() {
  local file=$1 key=$2
  [[ -f $file ]] || return 0
  sed -n "s/^${key}=//p" "$file" | tail -n 1
}

# Set KEY=VALUE in a .env file (replacing the line, or appending it), keeping
# the file private. Used by bootstrap.sh for __bootstrap__ values.
env_set() {
  local file=$1 key=$2 value=$3 tmp
  tmp=$(mktemp "$(dirname "$file")/.env.XXXXXX")
  chmod 600 "$tmp"
  awk -v k="$key" -v v="$value" '
    BEGIN { done = 0 }
    index($0, k "=") == 1 { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }' "$file" > "$tmp"
  mv "$tmp" "$file"
}

# Load topology.env into TOPO_* variables and validate it.
load_topology() {
  [[ -f $TOPOLOGY_FILE ]] || die "topology.env not found; copy topology.env.example to topology.env and edit it"
  TOPO_DEPLOY_MODE=$(env_get "$TOPOLOGY_FILE" DEPLOY_MODE)
  TOPO_MEM_PROFILE=$(env_get "$TOPOLOGY_FILE" MEM_PROFILE)
  TOPO_SOC_INSTANCE=$(env_get "$TOPOLOGY_FILE" SOC_INSTANCE)
  TOPO_CORE_HOST=$(env_get "$TOPOLOGY_FILE" CORE_HOST)
  TOPO_CASES_HOST=$(env_get "$TOPOLOGY_FILE" CASES_HOST)
  TOPO_INTEL_HOST=$(env_get "$TOPOLOGY_FILE" INTEL_HOST)
  # Optional (R-06); validated by render-env.sh, which renders it.
  TOPO_SYSLOG_ALLOWED_IPS=$(env_get "$TOPOLOGY_FILE" SYSLOG_ALLOWED_IPS)
  # Optional (C9, A106); validated by render-env.sh, which renders them.
  TOPO_RESPONSE_MODE=$(env_get "$TOPOLOGY_FILE" RESPONSE_MODE)
  TOPO_RESPONSE_PROTECTED_CIDRS=$(env_get "$TOPOLOGY_FILE" RESPONSE_PROTECTED_CIDRS)
  export TOPO_DEPLOY_MODE TOPO_MEM_PROFILE TOPO_SOC_INSTANCE TOPO_CORE_HOST TOPO_CASES_HOST TOPO_INTEL_HOST \
    TOPO_SYSLOG_ALLOWED_IPS TOPO_RESPONSE_MODE TOPO_RESPONSE_PROTECTED_CIDRS

  [[ $TOPO_DEPLOY_MODE == single || $TOPO_DEPLOY_MODE == distributed ]] \
    || die "topology.env: DEPLOY_MODE must be 'single' or 'distributed' (got '$TOPO_DEPLOY_MODE')"
  [[ $TOPO_MEM_PROFILE == standard || $TOPO_MEM_PROFILE == low ]] \
    || die "topology.env: MEM_PROFILE must be 'standard' or 'low' (got '$TOPO_MEM_PROFILE')"
  [[ $TOPO_SOC_INSTANCE =~ ^[a-z0-9][a-z0-9-]*$ ]] \
    || die "topology.env: SOC_INSTANCE must be lowercase letters, digits and dashes (got '$TOPO_SOC_INSTANCE')"
  if [[ $TOPO_DEPLOY_MODE == distributed ]]; then
    local h
    for h in CORE_HOST CASES_HOST INTEL_HOST; do
      local v="TOPO_$h"
      [[ -n ${!v} ]] || die "topology.env: $h is required when DEPLOY_MODE=distributed"
    done
  fi
}

# docker compose for one node, with the soc-net override in single-host mode.
compose() {
  local node=$1; shift
  local dir
  dir=$(node_dir "$node")
  local -a files=(-f "$dir/docker-compose.yml")
  if [[ $(env_get "$dir/.env" DEPLOY_MODE) == single ]]; then
    files+=(-f "$dir/soc-net.yml")
  fi
  docker compose --project-directory "$dir" --env-file "$dir/.env" "${files[@]}" "$@"
}

# For responses printed as the body plus a last line with the HTTP status
# (cases.sh's _call, wazuh.sh's indexer_as).
http_body() { sed '$d' <<<"$1"; }
http_code() { tail -n 1 <<<"$1"; }

# Exit with the conventional status after a series of pass/fail checks.
finish() {
  if (( FAILURES > 0 )); then
    printf '\n%d check(s) failed.\n' "$FAILURES"
    exit 1
  fi
  printf '\nAll checks passed.\n'
}
