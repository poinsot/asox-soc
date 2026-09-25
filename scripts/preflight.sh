#!/usr/bin/env bash
# Check that this machine is ready to run the SOC (CHECKLIST.md, WSL side).
#
# Usage: scripts/preflight.sh [mode|nodes...]
#   Without arguments, the ports of every node are checked.
# Prints one PASS/FAIL line per check (WARN lines don't fail) and exits
# non-zero if any check fails.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

mapfile -t NODES < <(resolve_nodes "${@:-full}")

# Published host ports per node (PROJECT.md 3.1), as <port>/<proto>.
declare -A NODE_PORTS=(
  [core]="1514/tcp 1515/tcp 514/udp 55000/tcp 5678/tcp 3000/tcp"
  [cases]="9000/tcp 9001/tcp"
  [intel]="9443/tcp"
  [lab]=""
)

echo "== Host"
if [[ $REPO_ROOT == /mnt/* ]]; then
  fail "repo location: $REPO_ROOT is on the Windows filesystem; clone it under ~ inside WSL"
else
  pass "repo location: $REPO_ROOT (Linux filesystem)"
fi

arch=$(uname -m)
if [[ $arch == x86_64 ]]; then pass "architecture: $arch"; else fail "architecture: $arch (only x86_64/amd64 is supported)"; fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  pass "running under WSL2"
else
  warn "not running under WSL2 (plain Linux works but isn't the supported platform, D18)"
fi

echo "== Tools"
for t in git curl jq openssl nc python3 sha256sum tar; do
  if command -v "$t" >/dev/null 2>&1; then pass "tool: $t"; else fail "tool: $t not installed (CHECKLIST.md section 5)"; fi
done

echo "== Docker"
if ! command -v docker >/dev/null 2>&1; then
  fail "docker: CLI not installed (CHECKLIST.md section 4)"
elif ! docker info >/dev/null 2>&1; then
  fail "docker: daemon not reachable without sudo (is it running? is $USER in the docker group?)"
else
  pass "docker: engine $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop'; then
    fail "docker: this is Docker Desktop; the project uses Docker Engine inside WSL (D10)"
  fi
  cv=$(docker compose version --short 2>/dev/null || true)
  cv=${cv#v}
  if [[ -z $cv ]]; then
    fail "docker compose: plugin not installed"
  elif [[ $(printf '%s\n%s\n' 2.20.0 "$cv" | sort -V | head -n1) == 2.20.0 ]]; then
    pass "docker compose: $cv (>= 2.20)"
  else
    fail "docker compose: $cv is older than 2.20"
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ $(systemctl is-enabled docker 2>/dev/null || true) != enabled ]]; then
    warn "docker service is not enabled at boot (sudo systemctl enable docker)"
  fi
  if ! grep -qs 'max-size' /etc/docker/daemon.json; then
    warn "docker log rotation not configured in /etc/docker/daemon.json (CHECKLIST.md section 4)"
  fi
fi

echo "== Kernel and resources"
mmc=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if (( mmc < 262144 )); then
  info "vm.max_map_count is $mmc; trying sudo sysctl -w vm.max_map_count=262144"
  if sudo -n sysctl -qw vm.max_map_count=262144 2>/dev/null || sudo sysctl -qw vm.max_map_count=262144; then
    mmc=$(sysctl -n vm.max_map_count)
  fi
fi
if (( mmc >= 262144 )); then
  pass "vm.max_map_count: $mmc (>= 262144)"
else
  fail "vm.max_map_count: $mmc; set kernelCommandLine in .wslconfig or /etc/sysctl.d (CHECKLIST.md section 3)"
fi

profile=standard
if [[ -f $TOPOLOGY_FILE ]]; then
  if msg=$( (load_topology) 2>&1 ); then
    load_topology
    profile=$TOPO_MEM_PROFILE
    pass "topology.env: DEPLOY_MODE=$TOPO_DEPLOY_MODE MEM_PROFILE=$TOPO_MEM_PROFILE SOC_INSTANCE=$TOPO_SOC_INSTANCE"
  else
    fail "${msg#ERROR }"
  fi
else
  fail "topology.env: missing; cp topology.env.example topology.env and edit it"
fi

mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
swap_kb=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
mem_gib=$(awk -v k="$mem_kb" 'BEGIN {printf "%.1f", k/1048576}')
swap_gib=$(awk -v k="$swap_kb" 'BEGIN {printf "%.1f", k/1048576}')
if [[ $profile == standard ]]; then min_kb=$((9 * 1048576)); min_txt="9 GiB (WSL memory=10GB or more)"
else min_kb=$((5 * 1048576 + 524288)); min_txt="5.5 GiB (WSL memory=6GB)"; fi
if (( mem_kb >= min_kb )); then
  pass "memory: ${mem_gib} GiB RAM, ${swap_gib} GiB swap (profile $profile needs >= $min_txt)"
else
  fail "memory: ${mem_gib} GiB RAM is below $min_txt for profile $profile; use MEM_PROFILE=low or raise .wslconfig memory"
fi
if [[ $profile == low ]] && (( swap_kb < 4 * 1048576 )); then
  warn "swap: ${swap_gib} GiB; 8 GB machines should set swap=8GB in .wslconfig"
fi

free_kb=$(df -Pk "$REPO_ROOT" | awk 'NR==2 {print $4}')
free_gib=$((free_kb / 1048576))
if (( free_gib < 20 )); then
  fail "disk: ${free_gib} GiB free (need >= 20 GiB, 60 GiB recommended)"
elif (( free_gib < 60 )); then
  warn "disk: ${free_gib} GiB free (60 GiB recommended)"
  pass "disk: ${free_gib} GiB free (>= 20 GiB)"
else
  pass "disk: ${free_gib} GiB free"
fi

echo "== Repository"
crlf=$(grep -rlI $'\r' "$REPO_ROOT/scripts" "$REPO_ROOT/nodes" --include='*.sh' --include='*.yml' --include='*.example' 2>/dev/null || true)
if [[ -z $crlf ]]; then
  pass "line endings: no CRLF in scripts or node files"
else
  fail "line endings: CRLF found in: $(tr '\n' ' ' <<<"$crlf")(run: git add --renormalize . && git checkout -- .)"
fi

echo "== Ports (${NODES[*]})"
instance=${TOPO_SOC_INSTANCE:-asox}
listening=$(ss -Htuln 2>/dev/null || true)
containers=""
docker info >/dev/null 2>&1 && containers=$(docker ps --format '{{.Names}} {{.Ports}}')
for node in "${NODES[@]}"; do
  for pp in ${NODE_PORTS[$node]}; do
    port=${pp%/*} proto=${pp#*/}
    if ! awk -v p="$proto" -v port="$port" '$1 == p && $5 ~ (":" port "$") {found=1} END {exit !found}' <<<"$listening"; then
      pass "port $pp ($node): free"
      continue
    fi
    owner=$(awk -v pat=":$port->[0-9]+/$proto" '$0 ~ pat {print $1; exit}' <<<"$containers")
    if [[ -n $owner && $owner == "$instance-"* ]]; then
      pass "port $pp ($node): in use by this instance ($owner)"
    elif [[ -n $owner ]]; then
      fail "port $pp ($node): in use by container $owner (another instance?)"
    else
      fail "port $pp ($node): in use by another process (ss -tulpn | grep :$port)"
    fi
  done
done

finish
