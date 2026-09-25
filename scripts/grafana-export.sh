#!/usr/bin/env bash
# Save dashboards edited in the Grafana UI back into the repo, as the JSON
# files Grafana provisions at startup (PROJECT.md 11.2).
#
# Usage: scripts/grafana-export.sh [UID...]
#   Without UIDs, every dashboard is exported. A dashboard whose UID is
#   already in a file in nodes/core/grafana/provisioning/dashboards/ overwrites
#   that file; a new one gets <title>.json. Review with git diff, then commit.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

ENV_FILE="$(node_dir core)/.env"
[[ -f $ENV_FILE ]] || die "nodes/core/.env not found; run scripts/soc.sh init core"
DASH_DIR="$(node_dir core)/grafana/provisioning/dashboards"
# Published on the core host; 127.0.0.1 works with either BIND_ADDR.
GRAFANA_URL=${GRAFANA_URL:-http://127.0.0.1:3000}
AUTH="$(env_get "$ENV_FILE" GRAFANA_ADMIN_USER):$(env_get "$ENV_FILE" GRAFANA_ADMIN_PASSWORD)"

api() { curl -sf -u "$AUTH" "$GRAFANA_URL$1"; }

api /api/health >/dev/null || die "Grafana is not reachable at $GRAFANA_URL (is core running?)"

if (( $# > 0 )); then
  uids=("$@")
else
  mapfile -t uids < <(api "/api/search?type=dash-db&limit=5000" | jq -r '.[].uid')
fi
(( ${#uids[@]} > 0 )) || die "no dashboards found"

# File that already holds a dashboard UID, if any.
file_for_uid() {
  local f
  for f in "$DASH_DIR"/*.json; do
    [[ -f $f ]] || continue
    [[ $(jq -r '.uid // empty' "$f" 2>/dev/null) == "$1" ]] && { printf '%s' "$f"; return 0; }
  done
  return 0
}

for uid in "${uids[@]}"; do
  if ! json=$(api "/api/dashboards/uid/$uid"); then
    fail "dashboard $uid: not found"
    continue
  fi
  title=$(jq -r '.dashboard.title' <<<"$json")
  target=$(file_for_uid "$uid")
  if [[ -z $target ]]; then
    slug=$(tr '[:upper:]' '[:lower:]' <<<"$title" | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')
    target="$DASH_DIR/${slug:-$uid}.json"
    [[ -e $target ]] && target="$DASH_DIR/${slug}-${uid}.json"
  fi
  # The numeric id is per Grafana database; provisioning matches on uid.
  jq '.dashboard | del(.id)' <<<"$json" > "$target.tmp" && mv "$target.tmp" "$target"
  pass "exported \"$title\" ($uid) -> ${target#"$REPO_ROOT"/}"
done

finish
