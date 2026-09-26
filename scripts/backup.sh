#!/usr/bin/env bash
# Back up one node's data (PROJECT.md 9.2): every named volume of the node,
# archived while the node is stopped, plus a MANIFEST.txt (node, date,
# pinned image tags, volumes, SHA-256 checksums).
#
# Usage: scripts/backup.sh <node> [--out <dir>] [--with-secrets]
#   <node>          core, cases, intel or lab (a whole node, never a service)
#   --out <dir>     parent folder (default: backups/ in the repo); the backup
#                   goes to <dir>/<node>-<YYYYmmdd-HHMMSS>/
#   --with-secrets  also include the node's .env (secrets and API keys) and,
#                   for core and intel, its certificates. Treat the backup as
#                   a credential: store it privately, never commit it.
# The node is stopped while its volumes are archived, then started again if
# it was running. Restore with scripts/restore.sh <node> <backup-dir>.
# shellcheck disable=SC2016
# (commands run inside containers expand their own variables: '$1')
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/backup.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/backup.sh"

usage() { print_usage "$0"; }

NODE="" OUT_PARENT="$REPO_ROOT/backups" WITH_SECRETS=0
while (( $# > 0 )); do
  case $1 in
    --out) OUT_PARENT=${2:?--out needs a directory}; shift ;;
    --with-secrets) WITH_SECRETS=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) [[ -z $NODE ]] || { usage >&2; exit 2; }; NODE=$1 ;;
  esac
  shift
done
[[ -n $NODE ]] || { usage >&2; exit 2; }
is_node "$NODE" || die "unknown node: $NODE (nodes: ${ALL_NODES[*]}; a backup is always a whole node)"
DIR=$(node_dir "$NODE")
[[ -f $DIR/.env ]] || die "nodes/$NODE/.env not found: $NODE is not initialised on this machine"

mkdir -p "$OUT_PARENT"
OUT="$(cd "$OUT_PARENT" && pwd)/$NODE-$(date +%Y%m%d-%H%M%S)"
[[ ! -e $OUT ]] || die "$OUT already exists"
mkdir -p "$OUT/volumes"
chmod 700 "$OUT"

# Volumes that exist on this machine (e.g. n8n's optional postgres volume
# only once the pg profile has been used).
declare -a VOLS=()
while read -r key name; do
  if docker volume inspect "$name" >/dev/null 2>&1; then VOLS+=("$key $name")
  else skip "$NODE: volume $key not created on this machine"; fi
done < <(node_volumes "$NODE")
(( ${#VOLS[@]} > 0 )) || die "$NODE: no volumes to back up"

RUNNING=$(compose "$NODE" ps --status running --services 2>/dev/null || true)
# Databases flush on SIGTERM; give them time instead of the 10 s default.
if [[ -n $RUNNING ]]; then
  info "stopping $NODE"
  compose "$NODE" stop --timeout 120 >/dev/null 2>&1
  pass "$NODE: stopped"
fi
restart() {
  if [[ -n $RUNNING ]]; then
    info "starting $NODE"
    if compose "$NODE" up -d --wait --wait-timeout "${SOC_UP_TIMEOUT:-900}" >/dev/null 2>&1; then
      pass "$NODE: started again"
    else
      fail "$NODE: did not become healthy again (scripts/soc.sh status)"
    fi
  fi
}
# Start the node again even if archiving fails.
trap restart EXIT

UID_GID="$(id -u):$(id -g)"
for v in "${VOLS[@]}"; do
  read -r key name <<<"$v"
  backup_run -v "$name:/v:ro" -v "$OUT/volumes:/out" -- \
    sh -c 'tar -C /v -czf "/out/$1.tar.gz" --warning=no-file-ignored . && chown "$2" "/out/$1.tar.gz"' _ "$key" "$UID_GID"
  pass "$NODE: volume $key archived ($(du -h "$OUT/volumes/$key.tar.gz" | cut -f1))"
done

if (( WITH_SECRETS )); then
  mkdir -p "$OUT/secrets"
  chmod 700 "$OUT/secrets"
  install -m 600 "$DIR/.env" "$OUT/$SECRETS_ENV"
  pass "$NODE: .env included (secrets and API keys)"
  if node_has_certs "$NODE"; then
    # Some certificate files belong to container users (MISP's nginx), so
    # they are archived from a container, keeping owners and modes.
    backup_run -v "$DIR/certs:/c:ro" -v "$OUT/secrets:/out" -- \
      sh -c 'tar -C /c -czf /out/certs.tar.gz --exclude=./.gitkeep . && chown "$1" /out/certs.tar.gz && chmod 600 /out/certs.tar.gz' _ "$UID_GID"
    pass "$NODE: certificates included (nodes/$NODE/certs)"
  fi
fi

SUM_DIRS=(volumes)
(( WITH_SECRETS )) && SUM_DIRS+=(secrets)
{
  printf '# ASOX SOC backup (scripts/backup.sh). Restore: scripts/restore.sh %s <this folder>\n' "$NODE"
  printf 'node: %s\n' "$NODE"
  printf 'instance: %s\n' "$(env_get "$DIR/.env" SOC_INSTANCE)"
  printf 'created: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'host: %s\n' "$(hostname)"
  printf 'deploy_mode: %s\n' "$(env_get "$DIR/.env" DEPLOY_MODE)"
  printf 'mem_profile: %s\n' "$(env_get "$DIR/.env" MEM_PROFILE)"
  printf 'secrets: %s\n' "$( (( WITH_SECRETS )) && echo yes || echo no)"
  printf '\n## Images\n'
  pinned_versions "$DIR/.env"
  printf '\n## Volumes\n'
  printf '%s\n' "${VOLS[@]}"
  printf '\n## SHA-256\n'
  (cd "$OUT" && find "${SUM_DIRS[@]}" -type f | sort | xargs sha256sum)
} > "$OUT/$MANIFEST"

trap - EXIT
restart
(( FAILURES == 0 )) || finish
pass "backup of $NODE written to $OUT ($(du -sh "$OUT" | cut -f1))"
(( WITH_SECRETS )) && warn "the backup contains credentials: keep it private and never commit it"
exit 0
