#!/usr/bin/env bash
# Render nodes/<node>/.env from topology.env and nodes/<node>/.env.example.
#
# For every key in .env.example:
#   - topology-derived keys (instance, URLs, BIND_ADDR, memory profile,
#     paths) are recomputed from topology.env on every run;
#   - __secret__    : a random secret is generated once, then kept;
#   - __bootstrap__ : left empty until bootstrap.sh fills it, then kept;
#   - __from:<node>__ : copied from the same key in nodes/<node>/.env when
#                     <node> runs on this machine (single-host mode, or the
#                     same host in topology.env); otherwise the value already
#                     in .env is kept (pasted by hand in distributed mode),
#                     with a warning while it is empty;
#   - anything else : copied from .env.example (e.g. pinned image tags).
# Keys already in .env but no longer in .env.example are kept, with a warning.
#
# Usage: scripts/render-env.sh            (renders every node)
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { print_usage "$0"; }
[[ ${1:-} == -h || ${1:-} == --help ]] && { usage; exit 0; }

load_topology

# SYSLOG_ALLOWED_IPS (R-06): extra syslog sources for the Wazuh manager,
# rendered into core's WAZUH_SYSLOG_ALLOWED_IPS. Empty is valid (the manager
# then allows only its own Docker networks). Checked before any file is
# written, so an invalid value changes nothing.
check_syslog_allowed_ips() {
  local list=$1 entry o
  local -a entries
  [[ -n $list ]] || return 0
  local hint="comma-separated IPv4 addresses or CIDRs without spaces, e.g. 192.168.1.1,10.0.5.0/24"
  [[ $list != *[[:space:]]* ]] \
    || die "topology.env: SYSLOG_ALLOWED_IPS contains a space ('$list'); use $hint"
  [[ $list != ,* && $list != *, && $list != *,,* ]] \
    || die "topology.env: SYSLOG_ALLOWED_IPS has an empty entry ('$list'); use $hint"
  IFS=, read -ra entries <<< "$list"
  for entry in "${entries[@]}"; do
    [[ $entry =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]] \
      || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry' is not a.b.c.d or a.b.c.d/n; use $hint"
    for o in 1 2 3 4; do
      [[ ${BASH_REMATCH[o]} != 0?* ]] \
        || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry': octet ${BASH_REMATCH[o]}: leading zeros are ambiguous (octal)"
      (( 10#${BASH_REMATCH[o]} <= 255 )) \
        || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry': octet ${BASH_REMATCH[o]} is above 255"
    done
    if [[ -n ${BASH_REMATCH[6]} ]]; then
      (( 10#${BASH_REMATCH[6]} <= 32 )) \
        || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry': prefix /${BASH_REMATCH[6]} is above /32"
      # 0.0.0.0/0, or any /0, matches every address.
      (( 10#${BASH_REMATCH[6]} > 0 )) \
        || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry' accepts every source, which disables the syslog restriction; list the senders' addresses instead"
      # /1 to /7 cover at least 2^25 addresses: more than any syslog sender list needs.
      (( 10#${BASH_REMATCH[6]} >= 8 )) \
        || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry': prefix /${BASH_REMATCH[6]} is too broad (below /8)"
    fi
    # 0.0.0.0/8 is "this network" (RFC 1122): never a sender's address.
    [[ ${BASH_REMATCH[1]} != 0 ]] \
      || die "topology.env: SYSLOG_ALLOWED_IPS entry '$entry': 0.x.x.x is not a source address"
  done
}
check_syslog_allowed_ips "$TOPO_SYSLOG_ALLOWED_IPS"

# Memory profiles (PROJECT.md section 8): heaps and container mem_limit.
# Limits are sized from measured need (D40): anonymous memory peak x 1.15
# + 64 MiB for page cache, rounded up to 50 MiB. Swap is capped at the
# limit in every compose file, so an undersized limit fails visibly.
declare -A PROFILE_STANDARD=(
  [INDEXER_HEAP]=1g      [INDEXER_MEM]=2g
  [WAZUH_MANAGER_MEM]=700m
  [N8N_HEAP]=384        [N8N_MEM]=800m         [N8N_POSTGRES_MEM]=200m
  [GRAFANA_MEM]=256m
  [CASSANDRA_HEAP]=1g    [CASSANDRA_NEWSIZE]=256m [CASSANDRA_MEM]=1600m
  [ES_HEAP]=1g           [ES_MEM]=2400m
  [THEHIVE_HEAP]=1g      [THEHIVE_MEM]=1900m
  [CORTEX_HEAP]=512m     [CORTEX_MEM]=700m
  [CORTEX_ANALYZER_MEM]=268435456
  [MISP_CORE_MEM]=900m   [MISP_NGINX_MEM]=100m
  [MISP_MODULES_MEM]=400m
  [MARIADB_MEM]=550m     [MARIADB_BUFFER_POOL]=256M [REDIS_MEM]=100m
  [LAB_AGENT_MEM]=100m   [SURICATA_MEM]=750m
)
declare -A PROFILE_LOW=(
  [INDEXER_HEAP]=512m    [INDEXER_MEM]=1150m
  [WAZUH_MANAGER_MEM]=700m
  [N8N_HEAP]=320        [N8N_MEM]=800m         [N8N_POSTGRES_MEM]=150m
  [GRAFANA_MEM]=250m
  [CASSANDRA_HEAP]=512m  [CASSANDRA_NEWSIZE]=128m [CASSANDRA_MEM]=1000m
  [ES_HEAP]=512m         [ES_MEM]=1450m
  [THEHIVE_HEAP]=512m    [THEHIVE_MEM]=1300m
  [CORTEX_HEAP]=256m     [CORTEX_MEM]=550m
  [CORTEX_ANALYZER_MEM]=268435456
  [MISP_CORE_MEM]=900m   [MISP_NGINX_MEM]=100m
  [MISP_MODULES_MEM]=400m
  [MARIADB_MEM]=400m     [MARIADB_BUFFER_POOL]=128M [REDIS_MEM]=100m
  [LAB_AGENT_MEM]=100m   [SURICATA_MEM]=750m
)

# Host of a node in distributed mode. The lab agent has no host of its own:
# it is treated as running on the core machine.
node_host() {
  case $1 in
    core|lab) printf '%s' "$TOPO_CORE_HOST" ;;
    cases) printf '%s' "$TOPO_CASES_HOST" ;;
    intel) printf '%s' "$TOPO_INTEL_HOST" ;;
  esac
}

# Address of a service in <target> node as seen from <consumer> node:
# the container alias inside the node or in single-host mode (soc-net),
# otherwise the target host's IP with the published port.
addr() {
  local consumer=$1 target=$2 alias_url=$3 host_url_tmpl=$4
  if [[ $consumer == "$target" || $TOPO_DEPLOY_MODE == single ]]; then
    printf '%s' "$alias_url"
  else
    printf '%s' "${host_url_tmpl//HOST/$(node_host "$target")}"
  fi
}

# Print the derived value of <key> for <node>; return 1 if not derived.
derive() {
  local node=$1 key=$2
  case $key in
    SOC_INSTANCE)       printf '%s' "$TOPO_SOC_INSTANCE" ;;
    DEPLOY_MODE)        printf '%s' "$TOPO_DEPLOY_MODE" ;;
    MEM_PROFILE)        printf '%s' "$TOPO_MEM_PROFILE" ;;
    BIND_ADDR)          [[ $TOPO_DEPLOY_MODE == single ]] && printf '127.0.0.1' || printf '0.0.0.0' ;;
    WAZUH_INDEXER_URL)  printf 'https://wazuh.indexer:9200' ;;  # internal to core, never published; name in its certificate
    WAZUH_API_URL)      addr "$node" core  https://wazuh-manager:55000 https://HOST:55000 ;;
    WAZUH_MANAGER_ADDR) addr "$node" core  wazuh-manager               HOST ;;
    N8N_WEBHOOK_URL)    addr "$node" core  http://n8n:5678             http://HOST:5678 ;;
    THEHIVE_URL)        addr "$node" cases http://thehive:9000         http://HOST:9000 ;;
    CORTEX_URL)         addr "$node" cases http://cortex:9001          http://HOST:9001 ;;
    MISP_URL)           addr "$node" intel https://misp-nginx:8443     https://HOST:9443 ;;
    # MISP's own base URL, as users reach it on the published port.
    MISP_BASE_URL)      [[ $TOPO_DEPLOY_MODE == single ]] && printf 'https://localhost:9443' || printf 'https://%s:9443' "$TOPO_INTEL_HOST" ;;
    CORTEX_JOBS_HOST_DIR) printf '%s' "$REPO_ROOT/nodes/cases/cortex/jobs" ;;
    # Cortex runs as the owner of the job directory, with access to the
    # host's Docker socket (docs/decisions.md A50).
    CORTEX_UID)         id -u ;;
    CORTEX_GID)         id -g ;;
    DOCKER_GID)         stat -c %g /var/run/docker.sock 2>/dev/null || getent group docker | cut -d: -f3 ;;
    # Analyzer containers reach MISP by alias on soc-net in single-host mode,
    # or through its published port from the default bridge (A49).
    CORTEX_ANALYZER_NETWORK) [[ $TOPO_DEPLOY_MODE == single ]] && printf '%s' "$SOC_NET" || printf 'bridge' ;;
    # n8n calls TheHive only when it has a key for it (R-18). Reads the value
    # already rendered in this run (render_node's "rendered"), so the key
    # must come before THEHIVE_ENABLED in .env.example.
    THEHIVE_ENABLED)    [[ -n ${rendered[THEHIVE_N8N_API_KEY]:-} ]] && printf 'true' || printf 'false' ;;
    # R-06: checked by check_syslog_allowed_ips; empty unless topology.env sets it.
    WAZUH_SYSLOG_ALLOWED_IPS) printf '%s' "$TOPO_SYSLOG_ALLOWED_IPS" ;;
    *)
      local v
      if [[ $TOPO_MEM_PROFILE == standard ]]; then v=${PROFILE_STANDARD[$key]:-}; else v=${PROFILE_LOW[$key]:-}; fi
      [[ -n $v ]] || return 1
      printf '%s' "$v"
      ;;
  esac
}

# Value of <key> for <node> taken from nodes/<src>/.env, else the current
# value. The source may be rendered before or after <node> in this run: the
# copied values (secrets, bootstrap keys) are kept across renders anyway.
# The source is only read when <src> runs on this machine: in single-host
# mode, or in distributed mode when topology.env gives both nodes the same
# host. Otherwise nodes/<src>/.env here is just a rendering of a node this
# machine doesn't run (with its own, unused secrets), and the value pasted
# by hand is kept.
from_node() {
  local node=$1 key=$2 src=$3 current=$4 v=""
  is_node "$src" || die "$node: .env.example: unknown node in __from:${src}__ for $key"
  if [[ $TOPO_DEPLOY_MODE == single || $(node_host "$node") == "$(node_host "$src")" ]] \
      && [[ -f "$(node_dir "$src")/.env" ]]; then
    v=$(env_get "$(node_dir "$src")/.env" "$key")
  fi
  [[ -n $v ]] || v=$current
  # In single-host mode an empty value is filled by a later render (after
  # the source node's bootstrap); only distributed mode needs a manual copy.
  if [[ -z $v && $TOPO_DEPLOY_MODE == distributed ]]; then
    warn "$node: $key is empty; if $node runs on this machine, paste it from nodes/$src/.env on the $src machine" >&2
  fi
  printf '%s' "$v"
}

gen_secret() {
  # 32 chars: upper, lower, digit and a dash, which satisfies the Wazuh
  # password policy and needs no quoting in .env, YAML or URLs.
  local s
  while :; do
    s=$(openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 31)
    [[ $s =~ [A-Z] && $s =~ [a-z] && $s =~ [0-9] ]] && break
  done
  printf '%s-%s' "${s:0:16}" "${s:16}"
}

render_node() {
  local node=$1
  local dir example target
  dir=$(node_dir "$node")
  example="$dir/.env.example"
  target="$dir/.env"
  [[ -f $example ]] || { skip "$node: no .env.example"; return 0; }

  local -A old=()
  local line key val derived
  if [[ -f $target ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
      old[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
    done < "$target"
  fi

  local tmp
  tmp=$(mktemp "$dir/.env.XXXXXX")
  chmod 600 "$tmp"
  local -A seen=() rendered=()
  local in_header=1 generated=0
  {
    printf '# GENERATED by scripts/render-env.sh from topology.env and .env.example.\n'
    printf '# Contains secrets: never commit. Re-run render-env.sh instead of editing\n'
    printf '# topology values here; secrets and bootstrap keys are kept across runs.\n\n'
    while IFS= read -r line || [[ -n $line ]]; do
      # Drop the template's explanatory header (everything before the first blank line).
      if (( in_header )); then [[ -z $line ]] && in_header=0; continue; fi
      if [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
        key=${BASH_REMATCH[1]}
        val=${BASH_REMATCH[2]}
        seen[$key]=1
        if derived=$(derive "$node" "$key"); then
          val=$derived
        elif [[ $val == __secret__ ]]; then
          if [[ -n ${old[$key]:-} ]]; then val=${old[$key]}; else val=$(gen_secret); generated=$((generated + 1)); fi
        elif [[ $val == __bootstrap__ ]]; then
          val=${old[$key]:-}
        elif [[ $val =~ ^__from:([a-z]+)__$ ]]; then
          val=$(from_node "$node" "$key" "${BASH_REMATCH[1]}" "${old[$key]:-}")
        fi
        rendered[$key]=$val
        printf '%s=%s\n' "$key" "$val"
      else
        printf '%s\n' "$line"
      fi
    done < "$example"

    local extra=()
    for key in "${!old[@]}"; do [[ -n ${seen[$key]:-} ]] || extra+=("$key"); done
    if (( ${#extra[@]} > 0 )); then
      printf '\n# --- Kept from the previous .env (not in .env.example) ---\n'
      while IFS= read -r key; do
        printf '%s=%s\n' "$key" "${old[$key]}"
        warn "$node: key $key is not in .env.example; kept" >&2
      done < <(printf '%s\n' "${extra[@]}" | sort)
    fi
  } > "$tmp"
  mv "$tmp" "$target"
  local note=""
  (( generated > 0 )) && note=", $generated new secret(s)"
  pass "rendered nodes/$node/.env ($TOPO_DEPLOY_MODE, $TOPO_MEM_PROFILE$note)"
  # A key left over from an earlier cases init keeps TheHive enabled on a
  # machine that now runs core only (A83). It must be cleared in both files:
  # render copies it from cases, and keeps core's value when cases' is empty.
  if [[ ${rendered[THEHIVE_ENABLED]:-} == true ]]; then
    info "$node: THEHIVE_ENABLED=true, set because THEHIVE_N8N_API_KEY is non-empty; if this machine no longer runs cases, clear that key in nodes/core/.env and nodes/cases/.env, re-render and run scripts/bootstrap.sh core"
  fi
}

for node in "${ALL_NODES[@]}"; do
  render_node "$node"
done

mkdir -p "$REPO_ROOT/nodes/cases/cortex/jobs"
