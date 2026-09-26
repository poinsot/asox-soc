#!/usr/bin/env bash
# Save n8n workflows from the n8n database into nodes/core/n8n/workflows/
# (PROJECT.md 11.2). Exported files contain credential references (ID and
# name) only, never credential data.
#
# Usage: scripts/n8n-export.sh [WORKFLOW_ID...]
#   Without IDs, every non-archived workflow is exported. A workflow whose ID
#   is already in a file overwrites that file; a new one gets <name>.json.
#   Volatile fields (timestamps, version IDs, sharing, pinned data) are
#   dropped so git diffs show real changes only. Review with git diff.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { print_usage "$0"; exit 0; }
[[ -f "$(node_dir core)/.env" ]] || die "nodes/core/.env not found; run scripts/soc.sh init core"

all=$(n8n_cli -- export:workflow --all 2>/dev/null) || die "n8n export failed (is the core node initialised?)"
jq -e 'type == "array"' >/dev/null <<<"$all" || die "unexpected n8n export output"
if (( $# > 0 )); then
  all=$(jq -c --args '[.[] | select(.id as $id | $ARGS.positional | index($id))]' "$@" <<<"$all")
  for id in "$@"; do
    jq -e --arg id "$id" 'any(.[]; .id == $id)' >/dev/null <<<"$all" || fail "workflow $id: not found"
  done
fi

file_for_id() {
  local f
  for f in "$N8N_WORKFLOW_DIR"/*.json; do
    [[ -f $f ]] || continue
    [[ $(jq -r '.id // empty' "$f" 2>/dev/null) == "$1" ]] && { printf '%s' "$f"; return 0; }
  done
  return 0
}

while IFS= read -r wf; do
  id=$(jq -r '.id' <<<"$wf"); name=$(jq -r '.name' <<<"$wf")
  target=$(file_for_id "$id")
  if [[ -z $target ]]; then
    slug=$(tr '[:upper:]' '[:lower:]' <<<"$name" | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')
    target="$N8N_WORKFLOW_DIR/${slug:-$id}.json"
    [[ -e $target ]] && target="$N8N_WORKFLOW_DIR/${slug}-${id}.json"
  fi
  jq '{id, name, description, active, nodes, connections, settings, staticData, meta, nodeGroups,
       tags: [(.tags // [])[] | {name}], pinData: {}}
      | with_entries(select(.value != null))' <<<"$wf" > "$target.tmp"
  mv "$target.tmp" "$target"
  pass "exported \"$name\" ($id) -> ${target#"$REPO_ROOT"/}"
done < <(jq -c '.[] | select(.isArchived != true)' <<<"$all")

finish
