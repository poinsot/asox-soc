#!/usr/bin/env bash
# Memory report of the running containers (PROJECT.md section 8, D40), from
# each container's cgroup: anonymous memory (what limits are sized from),
# page cache ("file", reclaimable), peak, limit, swap and OOM kills, with
# node and overall totals and the WSL VM's own usage.
#
# Usage: scripts/mem-report.sh [--sample SECONDS] [--interval N] [--out FILE] [mode|nodes...]
#   Without nodes: every initialised node with a running container.
#   --sample S   : sample every N seconds (--interval, default 2) for S
#                  seconds and report the anonymous memory peak seen; run it
#                  across start, bootstrap, activity and idle (D40).
#   --out FILE   : also write the report (Markdown) to FILE, e.g. docs/.
# "D40 limit" = anon peak x 1.15 + 64 MiB, rounded up to 50 MiB; a "!" marks
# a container whose mem_limit is below it.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

SAMPLE=0 INTERVAL=2 OUT=""
ARGS=()
while (( $# > 0 )); do
  case $1 in
    --sample) SAMPLE=${2:?--sample needs seconds}; shift ;;
    --interval) INTERVAL=${2:?--interval needs seconds}; shift ;;
    --out) OUT=${2:?--out needs a file}; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done
[[ $SAMPLE =~ ^[0-9]+$ && $INTERVAL =~ ^[1-9][0-9]*$ ]] || die "--sample and --interval take whole seconds"

MIB=$((1024 * 1024))

running_services() { compose "$1" ps --status running --services 2>/dev/null || true; }

cgroup_dir() {
  local d
  for d in "/sys/fs/cgroup/system.slice/docker-$1.scope" "/sys/fs/cgroup/docker/$1"; do
    [[ -f $d/memory.stat ]] && { printf '%s' "$d"; return 0; }
  done
  return 1
}

stat_of() { awk -v k="$2" '$1 == k { print $2 }' "$1/memory.stat"; }
mib() { printf '%d' $(( ($1 + MIB / 2) / MIB )); }
# In MiB. Integer division first on purpose: it rounds up to 50 MiB.
# shellcheck disable=SC2017
d40_limit() { local a=$1; printf '%d' $(( ((a * 115 / 100 + 64 * MIB) + 50 * MIB - 1) / (50 * MIB) * 50 )); }

# ---- containers ----
# Found by their compose labels (project <SOC_INSTANCE>-<node>), so sampling
# follows containers that start or are recreated while it runs.
nodes=()
if (( ${#ARGS[@]} > 0 )); then
  mapfile -t nodes < <(resolve_nodes "${ARGS[@]}")
else
  for n in "${ALL_NODES[@]}"; do
    [[ -f "$(node_dir "$n")/.env" && -n $(running_services "$n") ]] && nodes+=("$n")
  done
fi
(( ${#nodes[@]} > 0 )) || die "no node is running on this machine (scripts/soc.sh up <mode>)"
INSTANCE=$(env_get "$TOPOLOGY_FILE" SOC_INSTANCE)

# Prints "node|service|cgroup dir" for each running container of the nodes.
containers() {
  local id project svc n dir
  while read -r id project svc; do
    for n in "${nodes[@]}"; do
      [[ $project == "$INSTANCE-$n" ]] || continue
      dir=$(cgroup_dir "$id") && printf '%s|%s|%s\n' "$n" "$svc" "$dir"
    done
  done < <(docker ps --no-trunc --format '{{.ID}} {{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.service"}}')
  return 0
}

# Highest anon seen per node|service (across recreations).
declare -A PEAK=()
sample() {
  local n svc dir a
  while IFS='|' read -r n svc dir; do
    a=$(stat_of "$dir" anon 2>/dev/null) || continue   # container just stopped
    [[ -n $a ]] || continue
    (( a > ${PEAK[$n|$svc]:-0} )) && PEAK[$n|$svc]=$a
  done < <(containers)
  return 0
}

sample
if (( SAMPLE > 0 )); then
  printf 'Sampling anonymous memory every %ss for %ss...\n' "$INTERVAL" "$SAMPLE" >&2
  end=$(( SECONDS + SAMPLE ))
  while (( SECONDS < end )); do
    sleep "$INTERVAL"
    sample
  done
fi
all=$(containers)
entries=()
for n in "${nodes[@]}"; do
  mapfile -t -O "${#entries[@]}" entries < <(grep "^$n|" <<<"$all" | sort || true)
done
(( ${#entries[@]} > 0 )) || die "no running containers in: ${nodes[*]}"

# ---- report ----
report() {
  local profile mode e n svc dir anon file peak max swap oom lim d40 mark
  local -A n_lim=() n_anon=() n_peak=()
  local t_lim=0 t_anon=0 t_peak=0 t_oom=0 t_swap=0
  profile=$(env_get "$TOPOLOGY_FILE" MEM_PROFILE)
  mode=$(env_get "$TOPOLOGY_FILE" DEPLOY_MODE)
  printf '# Memory report\n\n'
  printf -- '- Date: %s\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
  # shellcheck disable=SC2016  # Markdown backticks
  printf -- '- Profile: `%s`, deploy mode `%s`, nodes: %s\n' "$profile" "$mode" "${nodes[*]}"
  if (( SAMPLE > 0 )); then
    printf -- '- Anon peak: highest value sampled every %ss over %ss\n' "$INTERVAL" "$SAMPLE"
  else
    printf -- '- Anon peak: current value (no sampling; use --sample for a peak)\n'
  fi
  printf -- '- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)\n\n'
  printf '| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |\n'
  printf '|---|---|--:|--:|--:|--:|--:|--:|--:|--:|\n'
  for e in "${entries[@]}"; do
    IFS='|' read -r n svc dir <<<"$e"
    [[ -f $dir/memory.stat ]] || { printf '| %s | %s | (container gone) |||||||\n' "$n" "$svc"; continue; }
    anon=$(stat_of "$dir" anon); file=$(stat_of "$dir" file)
    peak=$(cat "$dir/memory.peak" 2>/dev/null || echo 0)
    max=$(cat "$dir/memory.max"); swap=$(cat "$dir/memory.swap.current" 2>/dev/null || echo 0)
    oom=$(awk '$1 == "oom_kill" { print $2 }' "$dir/memory.events")
    [[ $max == max ]] && lim=0 || lim=$max
    d40=$(d40_limit "${PEAK[$n|$svc]:-$anon}")
    mark=""; (( lim > 0 && d40 * MIB > lim )) && mark=" !"
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s%s |\n' "$n" "$svc" \
      "$( (( lim > 0 )) && mib "$lim" || echo none)" "$(mib "$anon")" "$(mib "${PEAK[$n|$svc]:-$anon}")" \
      "$(mib "$file")" "$(mib "$peak")" "$(mib "$swap")" "$oom" "$d40" "$mark"
    n_lim[$n]=$(( ${n_lim[$n]:-0} + lim )); n_anon[$n]=$(( ${n_anon[$n]:-0} + anon )); n_peak[$n]=$(( ${n_peak[$n]:-0} + ${PEAK[$n|$svc]:-$anon} ))
    t_lim=$(( t_lim + lim )); t_anon=$(( t_anon + anon )); t_peak=$(( t_peak + ${PEAK[$n|$svc]:-$anon} ))
    t_oom=$(( t_oom + oom )); t_swap=$(( t_swap + swap ))
  done
  printf '\n| Node | Sum of limits | Anon | Sum of anon peaks |\n|---|--:|--:|--:|\n'
  for n in "${nodes[@]}"; do
    printf '| %s | %s | %s | %s |\n' "$n" "$(mib "${n_lim[$n]:-0}")" "$(mib "${n_anon[$n]:-0}")" "$(mib "${n_peak[$n]:-0}")"
  done
  printf '| **all** | **%s** | **%s** | **%s** |\n' "$(mib "$t_lim")" "$(mib "$t_anon")" "$(mib "$t_peak")"
  printf '\nOOM kills: %d. Container swap: %s MiB.\n\n' "$t_oom" "$(mib "$t_swap")"
  # shellcheck disable=SC2016  # Markdown backticks
  printf 'WSL VM (`free -m`, includes WSL, Docker and everything else running):\n\n```\n%s\n```\n' "$(free -m)"
}

if [[ -n $OUT ]]; then
  report | tee "$OUT"
  printf '\nSaved to %s\n' "$OUT" >&2
else
  report
fi
