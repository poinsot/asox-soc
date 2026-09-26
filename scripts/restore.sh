#!/usr/bin/env bash
# Restore one node from a backup made by scripts/backup.sh (PROJECT.md 9.2).
#
# Usage: scripts/restore.sh <node> <backup-dir> [--force] [--yes]
#   --force  restore even if the backup's pinned image tags differ from the
#            ones pinned now (only onto the same versions is supported)
#   --yes    don't ask for confirmation
# Steps: verify the checksums; compare the pinned image tags; stop the node;
# restore its .env and certificates if the backup has them (otherwise keep
# the current ones, or render new ones, with a warning); re-render every
# .env for this machine's topology.env; replace the node's volumes with the
# archived ones; start the node and run healthcheck.sh on it.
# The node gets this machine's SOC_INSTANCE, so a backup can move between
# machines and instances.
# shellcheck disable=SC2016
# (commands run inside containers expand their own variables: '$1')
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/backup.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/backup.sh"

usage() { print_usage "$0"; }

NODE="" SRC="" FORCE=0 YES=0
while (( $# > 0 )); do
  case $1 in
    --force) FORCE=1 ;;
    --yes) YES=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *)
      if [[ -z $NODE ]]; then NODE=$1
      elif [[ -z $SRC ]]; then SRC=$1
      else usage >&2; exit 2; fi
      ;;
  esac
  shift
done
[[ -n $NODE && -n $SRC ]] || { usage >&2; exit 2; }
is_node "$NODE" || die "unknown node: $NODE (nodes: ${ALL_NODES[*]})"
[[ -f $SRC/$MANIFEST ]] || die "$SRC/$MANIFEST not found: not a backup folder"
SRC=$(cd "$SRC" && pwd)
M="$SRC/$MANIFEST"
DIR=$(node_dir "$NODE")
load_topology

# ------------------------------------------------------------ 1. checks ---
[[ $(manifest_get "$M" node) == "$NODE" ]] \
  || die "this is a backup of node '$(manifest_get "$M" node)', not '$NODE'"

SUMS=$(manifest_section "$M" SHA-256)
[[ -n $SUMS ]] || die "$MANIFEST has no checksums"
if out=$(cd "$SRC" && sha256sum --check --strict <<<"$SUMS" 2>&1); then
  pass "checksums of $(wc -l <<<"$SUMS") file(s) match"
else
  printf '%s\n' "$out" | grep -v ': OK$' >&2
  die "checksum mismatch: the backup is damaged or incomplete"
fi

# The backup's pinned versions against the ones pinned now (.env.example).
if diffs=$(diff <(manifest_section "$M" Images) <(pinned_versions "$DIR/.env.example")); then
  pass "pinned image tags match the backup's"
else
  printf '%s\n' "$diffs" | sed -n 's/^< /  backup: /p; s/^> /  now:    /p' >&2
  if (( FORCE )); then
    warn "pinned image tags differ from the backup's; restoring anyway (--force)"
  else
    die "pinned image tags differ from the backup's (above); restore onto the same versions, or pass --force"
  fi
fi

HAS_SECRETS=0
[[ $(manifest_get "$M" secrets) == yes && -f $SRC/$SECRETS_ENV ]] && HAS_SECRETS=1
mapfile -t VOLS < <(manifest_section "$M" Volumes)

echo "Restoring $NODE from $SRC ($(manifest_get "$M" created), host $(manifest_get "$M" host))."
echo "This replaces ALL data of $NODE on this machine (instance $TOPO_SOC_INSTANCE):"
echo "  volumes: $(printf '%s\n' "${VOLS[@]}" | cut -d' ' -f1 | paste -sd' ')"
if (( HAS_SECRETS )); then
  echo "  and nodes/$NODE/.env$(node_has_certs "$NODE" && [[ -f $SRC/$SECRETS_CERTS ]] && printf ' and nodes/%s/certs' "$NODE")"
fi
if (( ! YES )); then
  read -r -p "Type 'restore' to continue: " reply
  [[ $reply == restore ]] || die "aborted"
fi

# --------------------------------------------------------------- 2. stop ---
if [[ -f $DIR/.env ]]; then
  compose "$NODE" down --remove-orphans >/dev/null 2>&1
else
  # No .env (e.g. after soc.sh reset): remove leftover containers by label.
  mapfile -t left < <(docker ps -aq --filter "label=com.docker.compose.project=$TOPO_SOC_INSTANCE-$NODE")
  (( ${#left[@]} == 0 )) || docker rm -f "${left[@]}" >/dev/null
fi
pass "$NODE: stopped"

# ------------------------------------------------------------ 3. secrets ---
if (( HAS_SECRETS )); then
  install -m 600 "$SRC/$SECRETS_ENV" "$DIR/.env"
  pass "$NODE: .env restored from the backup"
  if node_has_certs "$NODE" && [[ -f $SRC/$SECRETS_CERTS ]]; then
    backup_run -v "$DIR/certs:/c" -v "$SRC/secrets:/in:ro" -- \
      sh -c 'find /c -mindepth 1 ! -name .gitkeep -delete && tar -C /c -xzpf /in/certs.tar.gz --numeric-owner --no-overwrite-dir'
    pass "$NODE: certificates restored to nodes/$NODE/certs"
  fi
elif [[ -f $DIR/.env ]]; then
  warn "$NODE: the backup has no secrets; keeping the current nodes/$NODE/.env. API keys and passwords stored in the restored data may not match it (e.g. n8n's TheHive and Cortex credentials): re-run scripts/bootstrap.sh for this node and the nodes using its keys"
else
  warn "$NODE: the backup has no secrets and nodes/$NODE/.env doesn't exist: rendering new secrets, which won't match the passwords and API keys stored in the restored data. Use a backup made with --with-secrets if the node doesn't come up"
fi

# ------------------------------------------------------------- 4. render ---
# Topology values (URLs, paths, BIND_ADDR, memory profile) for this machine;
# secrets and API keys already in .env are kept.
"$REPO_ROOT/scripts/render-env.sh" >/dev/null
pass "rendered every .env for this machine's topology.env ($TOPO_DEPLOY_MODE, $TOPO_MEM_PROFILE)"
if node_has_certs "$NODE" && (( ! HAS_SECRETS )) && [[ -z $(find "$DIR/certs" -mindepth 1 ! -name .gitkeep -print -quit) ]]; then
  "$REPO_ROOT/scripts/gen-certs.sh" "$NODE"
fi

# ------------------------------------------------------------ 5. volumes ---
[[ $TOPO_DEPLOY_MODE == single ]] && { docker network inspect "$SOC_NET" >/dev/null 2>&1 || docker network create "$SOC_NET" >/dev/null; }
# Compose creates the (empty) volumes with its own labels, and the
# containers, without starting them.
compose "$NODE" --progress quiet create
declare -A NAME_OF=()
while read -r key name; do NAME_OF[$key]=$name; done < <(node_volumes "$NODE")
for v in "${VOLS[@]}"; do
  read -r key _ <<<"$v"
  name=${NAME_OF[$key]:-}
  [[ -n $name ]] || die "$NODE: volume $key from the backup is no longer defined in the compose files"
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    # Only for volumes of optional profiles (e.g. n8n's postgres).
    docker volume create --label "com.docker.compose.project=$TOPO_SOC_INSTANCE-$NODE" \
      --label "com.docker.compose.volume=$key" "$name" >/dev/null
  fi
  backup_run -v "$name:/v" -v "$SRC/volumes:/in:ro" -- \
    sh -c 'find /v -mindepth 1 -delete && tar -C /v -xzpf "/in/$1.tar.gz" --numeric-owner' _ "$key"
  pass "$NODE: volume $key restored"
done

# ------------------------------------------------------------- 6. start ---
info "starting $NODE"
compose "$NODE" up -d --wait --wait-timeout "${SOC_UP_TIMEOUT:-900}" >/dev/null
pass "$NODE: up"

# Values other nodes on this machine copy from this one (__from:$NODE__), or
# this node copies from others, may have changed.
case $NODE in
  intel) info "if cases uses this MISP from another backup or machine: scripts/render-env.sh && scripts/bootstrap.sh cases" ;;
  cases) info "if core's n8n credentials or TheHive's webhook no longer work (C3, C4, C6): scripts/render-env.sh && scripts/bootstrap.sh core && scripts/bootstrap.sh cases" ;;
  core)  info "if the webhook token or enrollment password changed: scripts/render-env.sh && scripts/bootstrap.sh cases, and scripts/soc.sh reset lab && scripts/soc.sh init core for the lab agent" ;;
esac

"$REPO_ROOT/scripts/healthcheck.sh" "$NODE"
