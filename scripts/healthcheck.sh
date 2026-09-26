#!/usr/bin/env bash
# Health of the nodes running on this machine (PROJECT.md 14.1): containers
# healthy (no OOM kills), UIs and APIs answering with this machine's logins,
# cluster and database status, Cortex's analyzer runner, TheHive's license.
#
# Usage: scripts/healthcheck.sh [--cross-node] [mode|nodes...]
#   Without arguments: every initialised node with a running container.
#   --cross-node : also check, from each node, the other nodes' URLs it
#                  depends on (the addresses in its .env). In single-host
#                  mode, a dependency on a node that isn't running (a dev
#                  mode without it) is skipped.
# One PASS/FAIL line per check (WARN never fails); exit code 1 on failure.
# shellcheck disable=SC2016
# (commands run inside containers expand their own variables: '$VAR')
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

usage() { print_usage "$0"; }

CROSS=0
ARGS=()
while (( $# > 0 )); do
  case $1 in
    --cross-node) CROSS=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

running_services() { compose "$1" ps --status running --services 2>/dev/null || true; }

# HTTP status of a GET (000 when there is no answer); extra curl args follow.
http_status() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true; }

# Every service of <node> (default profile) runs and is healthy, and none was
# killed for lack of memory.
check_containers() {
  local node=$1 svc cid state health oom restarts
  while IFS= read -r svc; do
    cid=$(compose "$node" ps --all -q "$svc" 2>/dev/null || true)
    if [[ -z $cid ]]; then fail "$node/$svc: container not created (scripts/soc.sh up)"; continue; fi
    IFS='|' read -r state health oom restarts < <(docker inspect -f \
      '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.OOMKilled}}|{{.RestartCount}}' "$cid")
    if [[ $oom == true ]]; then
      fail "$node/$svc: killed for lack of memory (OOM); see scripts/mem-report.sh"
    elif [[ $state != running || $health != healthy ]]; then
      fail "$node/$svc: $state, health $health"
    else
      pass "$node/$svc: running, healthy"
    fi
    (( restarts == 0 )) || warn "$node/$svc: restarted $restarts time(s) since it was created (docker logs)"
  done < <(compose "$node" config --services)
}

# ---------------------------------------------------------------- core ---

check_core() {
  local s
  s=$(indexer_api GET /_cluster/health | jq -r '.status // empty' 2>/dev/null || true)
  if [[ $s == green || $s == yellow ]]; then pass "core: Wazuh indexer cluster $s"
  else fail "core: Wazuh indexer cluster status '${s:-no answer}'"; fi

  if wazuh_admin_login; then pass "core: Wazuh API answers, admin $(core_env WAZUH_API_ADMIN_USER) logs in"
  else fail "core: Wazuh API admin login failed"; fi

  s=$(http_status "$N8N_URL/healthz/readiness")
  if [[ $s == 200 ]] && n8n_api_ok; then pass "core: n8n ready ($N8N_URL), scripts' API key works"
  else fail "core: n8n readiness HTTP $s or N8N_API_KEY refused (scripts/bootstrap.sh core)"; fi

  s=$(curl -s --max-time 10 -u "$(core_env GRAFANA_ADMIN_USER):$(core_env GRAFANA_ADMIN_PASSWORD)" \
    http://127.0.0.1:3000/api/user | jq -r '.login // empty' 2>/dev/null || true)
  if [[ -n $s ]]; then pass "core: Grafana UI answers, admin $s logs in"
  else fail "core: Grafana login as $(core_env GRAFANA_ADMIN_USER) failed on http://127.0.0.1:3000"; fi
}

# ---------------------------------------------------------------- cases ---

check_cases() {
  local s problem image
  if compose cases exec -T cassandra cqlsh -e 'describe keyspaces' 2>/dev/null | grep -qw thehive; then
    pass "cases: Cassandra answers CQL (keyspace thehive)"
  else
    fail "cases: Cassandra doesn't answer CQL or has no thehive keyspace"
  fi

  s=$(compose cases exec -T elasticsearch sh -c 'curl -s -u "elastic:$ELASTIC_PASSWORD" http://localhost:9200/_cluster/health' \
    | jq -r '.status // empty' 2>/dev/null || true)
  if [[ $s == green || $s == yellow ]]; then pass "cases: Elasticsearch cluster $s"
  else fail "cases: Elasticsearch cluster status '${s:-no answer}'"; fi

  s=$(http_code "$(thehive_admin GET /api/v1/user/current)")
  if [[ $s == 200 ]]; then pass "cases: TheHive answers ($THEHIVE_API), admin $(cases_env THEHIVE_ADMIN_USER) logs in"
  else fail "cases: TheHive admin login HTTP $s ($THEHIVE_API)"; fi

  s=$(http_code "$(cortex_admin GET /api/user/current)")
  if [[ $s == 200 ]]; then pass "cases: Cortex answers ($CORTEX_API), superadmin $(cases_env CORTEX_ADMIN_USER) logs in"
  else fail "cases: Cortex superadmin login HTTP $s ($CORTEX_API)"; fi

  # Analyzer runner (PROJECT.md 6.5): a container started through Cortex's
  # Docker socket, on the analyzer network, writing into the job directory.
  docker image inspect "$RUNNER_TEST_IMAGE" >/dev/null 2>&1 || docker pull -q "$RUNNER_TEST_IMAGE" >/dev/null
  if problem=$(cortex_test_container "$RUNNER_TEST_IMAGE"); then
    pass "cases: Cortex reaches the Docker socket; job directory writable and shared with analyzer containers"
  else
    fail "cases: Cortex analyzer runner: $problem"
  fi
  image=$(cortex_analyzer_image "$MISP_ANALYZER")
  if [[ -z $image ]]; then
    fail "cases: $MISP_ANALYZER not in Cortex's analyzer catalog (catalog download failed?)"
  elif docker image inspect "$image" >/dev/null 2>&1; then
    pass "cases: MISP analyzer image $image present"
  else
    fail "cases: MISP analyzer image $image missing (scripts/bootstrap.sh cases pulls it)"
  fi
  thehive_license_check
}

# ---------------------------------------------------------------- intel ---

check_intel() {
  local s
  if compose intel exec -T mariadb sh -c 'mariadb-admin --user="$MYSQL_USER" --password="$MYSQL_PASSWORD" status' >/dev/null 2>&1; then
    pass "intel: MariaDB answers"
  else
    fail "intel: MariaDB doesn't answer"
  fi
  if compose intel exec -T redis sh -c 'valkey-cli -a "$REDIS_PASSWORD" --no-auth-warning ping' 2>/dev/null | grep -q PONG; then
    pass "intel: Redis (Valkey) answers"
  else
    fail "intel: Redis (Valkey) doesn't answer"
  fi
  s=$(http_status -k "$MISP_API/users/login")
  if [[ $s == 200 ]]; then pass "intel: MISP UI answers ($MISP_API)"
  else fail "intel: MISP UI HTTP $s ($MISP_API)"; fi
  s=$(misp_key_email "$(intel_env MISP_ADMIN_KEY)")
  if [[ -n $s ]]; then pass "intel: MISP API answers, admin key of $s works"
  else fail "intel: MISP admin API key refused (scripts/bootstrap.sh intel)"; fi
}

# ------------------------------------------------------------------ lab ---

check_lab() {
  local name status
  name=$(env_get "$(node_dir lab)/.env" LAB_AGENT_NAME)
  if ! wazuh_manager_running; then
    skip "lab: agent status needs the core node on this machine"
    return 0
  fi
  wazuh_admin_login || { fail "lab: Wazuh API admin login failed"; return; }
  status=$(wazuh_api GET "/agents?name=$name&select=status" | jq -r '.data.affected_items[0].status // empty')
  if [[ $status == active ]]; then pass "lab: agent $name active on the manager"
  else fail "lab: agent $name is '${status:-not registered}' on the manager"; fi
}

# ---------------------------------------------------------- cross-node ---

# <node> <target>: true (and prints SKIP) when, in single-host mode, the
# <target> node isn't running here, i.e. the current run mode leaves it out.
# In distributed mode the target is on another machine and is always checked.
target_absent() {
  local node=$1 target=$2 label=$3
  [[ $(env_get "$(node_dir "$node")/.env" DEPLOY_MODE) == single ]] || return 1
  [[ -f "$(node_dir "$target")/.env" && -n $(running_services "$target") ]] && return 1
  skip "$node -> $label: node $target not running (not part of this mode)"
}

# <node> <service> <target node> <label> <url>: GET from inside <service> answers (any HTTP status).
reach() {
  local node=$1 svc=$2 target=$3 label=$4 url=$5 code
  if ! running_services "$node" | grep -qx "$svc"; then
    skip "$node -> $label: $svc not running here"; return 0
  fi
  target_absent "$node" "$target" "$label" && return 0
  code=$(compose "$node" exec -T "$svc" sh -c \
    'if command -v curl >/dev/null; then curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$1";
     else wget -q -S --no-check-certificate -T 10 -O /dev/null "$1" 2>&1 | awk "/HTTP\\//{c=\$2} END{print c}"; fi' _ "$url" || true)
  if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then pass "$node -> $label: $url answers (HTTP $code, from $svc)"
  else fail "$node -> $label: $url unreachable from $svc"; fi
}

check_cross() {
  local node=$1 env url net
  env="$(node_dir "$node")/.env"
  case $node in
    core)
      reach core n8n cases "TheHive (C3)" "$(env_get "$env" THEHIVE_URL)/api/status"
      reach core n8n cases "Cortex (C6)" "$(env_get "$env" CORTEX_URL)/api/status"
      ;;
    cases)
      reach cases thehive core "n8n (C4)" "$(env_get "$env" N8N_WEBHOOK_URL)/healthz"
      # Analyzers reach MISP from their own network (CORTEX_ANALYZER_NETWORK).
      url="$(env_get "$env" MISP_URL)/users/login"
      net=$(env_get "$env" CORTEX_ANALYZER_NETWORK)
      if target_absent cases intel "MISP (C7)"; then
        :
      elif docker run --rm --network "$net" "$RUNNER_TEST_IMAGE" \
          wget -q --no-check-certificate -T 10 -O /dev/null "$url" >/dev/null 2>&1; then
        pass "cases -> MISP (C7): $url answers from network $net (analyzer containers)"
      else
        fail "cases -> MISP (C7): $url unreachable from network $net (analyzer containers)"
      fi
      ;;
    lab)
      if target_absent lab core "Wazuh manager"; then
        :
      elif running_services lab | grep -qx lab-agent \
          && compose lab exec -T lab-agent bash -c 'timeout 5 bash -c "</dev/tcp/$WAZUH_MANAGER_ADDR/1515"' 2>/dev/null; then
        pass "lab -> Wazuh manager: $(env_get "$env" WAZUH_MANAGER_ADDR):1515 answers"
      else
        fail "lab -> Wazuh manager: $(env_get "$env" WAZUH_MANAGER_ADDR):1515 unreachable from lab-agent"
      fi
      ;;
    intel) : ;;  # depends on no other node
  esac
}

# ---------------------------------------------------------------- main ---

main() {
  local -a nodes=()
  local n
  if (( ${#ARGS[@]} > 0 )); then
    mapfile -t nodes < <(resolve_nodes "${ARGS[@]}")
  else
    for n in "${ALL_NODES[@]}"; do
      [[ -f "$(node_dir "$n")/.env" && -n $(running_services "$n") ]] && nodes+=("$n")
    done
    (( ${#nodes[@]} > 0 )) || die "no node is running on this machine (scripts/soc.sh up <mode>)"
  fi
  for n in "${nodes[@]}"; do
    [[ -f "$(node_dir "$n")/.env" ]] || { fail "$n: not initialised on this machine (scripts/soc.sh init)"; continue; }
    echo "== $n"
    check_containers "$n"
    # Service checks only when the containers could answer at all.
    if [[ -n $(running_services "$n") ]]; then
      "check_$n"
      (( CROSS )) && check_cross "$n"
    fi
  done
  finish
}

main
