#!/usr/bin/env bash
# Load the configuration saved by thehive-export.sh (JSON files in
# nodes/cases/thehive/entities/) into this machine's TheHive.
# Each object is matched by name: created if missing, updated if different,
# left alone if identical. Nothing is ever deleted from TheHive, so running
# it twice is safe and never creates duplicates. Custom fields go first,
# since case templates refer to them.
#
# Usage: nodes/cases/thehive/scripts/thehive-import.sh [--dry-run] [KIND...]
#   KIND       custom-fields, observable-types, case-templates (default: all)
#   --dry-run  only print what would be created or updated
# Run it on the machine hosting cases, while cases is up.
set -euo pipefail
# shellcheck source=nodes/cases/thehive/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=0
args=()
for a in "$@"; do
  case $a in
    -h|--help) print_usage "$0"; exit 0 ;;
    -n|--dry-run) DRY_RUN=1 ;;
    *) args+=("$a") ;;
  esac
done

th_parse_kinds ${args[@]+"${args[@]}"}
th_require_ready
if th_needs_org; then th_org_key; fi

# ---- Create / update, per kind ----
# Each function gets: the wanted object (normalised JSON), its name, and for
# updates the object's TheHive id and its current (normalised) form.

create_custom-fields() {
  th_expect "custom-fields: create $2" "$(thehive_admin POST /api/v1/customField "$1")" 200 201
}
update_custom-fields() {
  local body
  if [[ $(jq -r .type <<<"$1") != $(jq -r .type <<<"$4") ]]; then
    warn "custom-fields: $2: type can't be changed ($(jq -r .type <<<"$4") in TheHive, $(jq -r .type <<<"$1") in the file); updating the rest"
  fi
  # Unset lists are cleared, so removing options in the file removes them.
  body=$(jq -c '{options: []} + . | del(.name, .type)' <<<"$1")
  th_expect "custom-fields: update $2" "$(thehive_admin PATCH "/api/v1/customField/$3" "$body")" 200 204
}

create_observable-types() {
  th_expect "observable-types: create $2" "$(thehive_admin POST /api/v1/observable/type "$1")" 200 201
}
update_observable-types() {
  # TheHive has no update for observable types (only name and isAttachment).
  warn "observable-types: $2: isAttachment differs; TheHive can't update it: delete the type in the UI (Entities management) and import again"
  return 1
}

# Template custom fields are sent as {name, value, order}.
JQ_TEMPLATE_BODY='(.customFields // []) |= map({name, value: (.value // null), order: (.order // 0)})'

create_case-templates() {
  th_expect "case-templates: create $2" \
    "$(thehive_org POST /api/v1/caseTemplate "$(jq -c "$JQ_TEMPLATE_BODY" <<<"$1")")" 200 201
}
update_case-templates() {
  local body r
  # Unset lists are cleared, so removing tags/tasks/fields in the file removes them.
  body=$(jq -c '{tags: [], tasks: [], customFields: []} + . | del(.name) | '"$JQ_TEMPLATE_BODY" <<<"$1")
  r=$(thehive_org PATCH "/api/v1/caseTemplate/$3" "$body")
  if [[ $(http_code "$r") =~ ^20[04]$ ]]; then return 0; fi
  # Fallback: recreate it. Cases already created from the template keep their
  # own copy of its tasks and fields, so they are not affected.
  warn "case-templates: $2: update refused (HTTP $(http_code "$r")); recreating the template instead"
  th_expect "case-templates: delete $2" "$(thehive_org DELETE "/api/v1/caseTemplate/$3")" 200 204 || return 1
  create_case-templates "$1" "$2"
}

# ---- Main loop ----

for kind in "${KINDS[@]}"; do
  file="$ENTITIES_DIR/$kind.json"
  rel=${file#"$REPO_ROOT"/}
  if [[ ! -f $file ]]; then
    skip "$kind: $rel doesn't exist (nothing exported yet)"
    continue
  fi
  if ! jq -e 'type == "array"' "$file" >/dev/null 2>&1 || ! want=$(th_normalize "$kind" < "$file"); then
    fail "$kind: $rel is not a valid JSON list"
    continue
  fi
  if ! raw=$(th_list "$kind"); then
    fail "$kind: TheHive didn't return the current list (see the error above)"
    continue
  fi
  cur=$(th_normalize "$kind" <<<"$raw")

  created=0 updated=0 same=0 failed=0
  n=$(jq length <<<"$want")
  for (( i = 0; i < n; i++ )); do
    item=$(jq -c ".[$i]" <<<"$want")
    name=$(jq -r '.name // empty' <<<"$item")
    if [[ -z $name ]]; then
      fail "$kind: entry $((i + 1)) in $rel has no name"
      failed=$((failed + 1))
      continue
    fi
    have=$(jq -c --arg n "$name" 'first(.[] | select(.name == $n)) // empty' <<<"$cur")
    if [[ -z $have ]]; then
      if (( DRY_RUN )); then
        info "$kind: would create $name"
      elif ! "create_$kind" "$item" "$name"; then
        failed=$((failed + 1)); continue
      fi
      created=$((created + 1))
    elif [[ $(jq -S . <<<"$have") == "$(jq -S . <<<"$item")" ]]; then
      same=$((same + 1))
    else
      id=$(jq -r --arg n "$name" 'first(.[] | select(.name == $n) | ._id) // empty' <<<"$raw")
      if (( DRY_RUN )); then
        info "$kind: would update $name"
      elif ! "update_$kind" "$item" "$name" "$id" "$have"; then
        failed=$((failed + 1)); continue
      fi
      updated=$((updated + 1))
    fi
  done

  extra=$(jq -r --argjson w "$want" '[.[].name] - [$w[].name] | join(", ")' <<<"$cur")
  [[ -n $extra ]] && info "$kind: only in TheHive, not in $rel (left as is): $extra"
  verb=""; (( DRY_RUN )) && verb="would be "
  summary="$kind: ${verb}created $created, ${verb}updated $updated, unchanged $same"
  if (( failed > 0 )); then
    warn "$summary, failed $failed"
  else
    pass "$summary"
  fi
done

finish
