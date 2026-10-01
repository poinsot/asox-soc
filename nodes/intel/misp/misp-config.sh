#!/usr/bin/env bash
# MISP warninglists and feeds as code (owner: Cortex + MISP). Run it on the
# machine that hosts the intel node, once scripts/soc.sh init has
# bootstrapped it.
#
# Usage: nodes/intel/misp/misp-config.sh <apply|fetch|export>
#   apply : update MISP's warninglists from the image and enable every list
#           with at most misp-config.json's warninglists.maxEntries entries
#           and disable larger ones (they exhaust misp-core's memory
#           limit); load MISP's default feed
#           list, then enable and cache the feeds marked "enabled": true
#           (queueing a first fetch) and disable those marked false. Feeds
#           not listed are left alone. Idempotent.
#   fetch : queue a new fetch of every enabled feed (there is no schedule
#           yet: see BACKLOG.md).
#   export: write the enabled state of MISP's feeds back into misp-config.json,
#           after changing them in the UI.
# One PASS/FAIL line per check; exit code 1 on failure.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../scripts/lib/common.sh"
# shellcheck source=scripts/lib/cases.sh
source "$REPO_ROOT/scripts/lib/cases.sh"
# shellcheck source=scripts/lib/misp.sh
source "$REPO_ROOT/scripts/lib/misp.sh"

CONFIG_FILE="$REPO_ROOT/nodes/intel/misp/misp-config.json"
# MISP returns flags as booleans or as "0"/"1" depending on the endpoint.
JQ_ON='def on: . == true or . == 1 or . == "1";'

usage() { print_usage "$0"; }

# misp_ok WHAT RESPONSE: true on HTTP 200, else a FAIL line.
misp_ok() {
  [[ $(http_code "$2") == 200 ]] && return 0
  fail "$1: HTTP $(http_code "$2") $(http_body "$2" | head -c 200)"
  return 1
}

apply_warninglists() {
  local r max ids batch total on wrong
  max=$(jq -r '.warninglists.maxEntries // empty' "$CONFIG_FILE")
  if [[ -z $max ]]; then
    skip "warninglists: no maxEntries in misp-config.json, left as they are"
    return
  fi
  r=$(misp_admin POST /warninglists/update)
  misp_ok "warninglists: update from the image" "$r" || return
  r=$(misp_admin GET /warninglists)
  misp_ok "warninglists: list" "$r" || return
  # Lists above maxEntries are disabled, including the 1M-entry list MISP
  # enables by default: with it, every warninglist check got php-fpm
  # OOM-killed within misp-core's memory limit. Toggled in small batches: one
  # request enabling every list at once was OOM-killed too (BACKLOG.md).
  local want
  for want in true false; do
    ids=$(http_body "$r" | jq -c --argjson m "$max" --argjson w "$want" "$JQ_ON"' [.Warninglists[]?.Warninglist
      | select(((.warninglist_entry_count | tonumber) <= $m) == $w and (.enabled | on) != $w) | .id]')
    while IFS= read -r batch; do
      misp_ok "warninglists: set enabled=$want on $batch" \
        "$(misp_admin POST /warninglists/toggleEnable "$(jq -nc --argjson i "$batch" --argjson e "$want" '{id: $i, enabled: $e}')")" || return
    done < <(jq -c '_nwise(10)' <<<"$ids")
  done
  r=$(misp_admin GET /warninglists)
  misp_ok "warninglists: list" "$r" || return
  total=$(http_body "$r" | jq '[.Warninglists[]?] | length')
  on=$(http_body "$r" | jq --argjson m "$max" "$JQ_ON"' [.Warninglists[]?.Warninglist | select(.enabled | on)] | length')
  wrong=$(http_body "$r" | jq --argjson m "$max" "$JQ_ON"' [.Warninglists[]?.Warninglist
    | select((.enabled | on) != ((.warninglist_entry_count | tonumber) <= $m))] | length')
  if [[ $wrong == 0 ]]; then pass "warninglists: $on of $total enabled (every list with <= $max entries)"
  else fail "warninglists: $wrong list(s) not in the wanted state (<= $max entries enabled, larger disabled)"; fi
  # Checked with the Read Only key that Cortex's MISP analyzer uses: 8.8.8.8
  # is on the public DNS resolver lists.
  r=$(misp_as "$(intel_env MISP_CORTEX_API_KEY)" POST /warninglists/checkValue '["8.8.8.8"]')
  hit=$(http_body "$r" | jq -r '.["8.8.8.8"][0].name // empty' 2>/dev/null || true)
  if [[ -n $hit ]]; then pass "warninglists: 8.8.8.8 -> \"$hit\" ($(intel_env MISP_CORTEX_USER))"
  else fail "warninglists: 8.8.8.8 matched no list (HTTP $(http_code "$r"))"; fi
}

# MISP's feed list (after loading the default feeds once).
FEEDS=""
load_feeds() {
  local r
  r=$(misp_admin GET /feeds/index)
  misp_ok "feeds: list" "$r" || return 1
  FEEDS=$(http_body "$r")
}

apply_feeds() {
  local r name want id state
  r=$(misp_admin POST /feeds/loadDefaultFeeds)
  misp_ok "feeds: load MISP's default feed list" "$r" || return
  load_feeds || return
  while IFS=$'\t' read -r name want; do
    id=$(jq -r --arg n "$name" '[.[] | .Feed | select(.name == $n) | .id] | first // empty' <<<"$FEEDS")
    [[ -n $id ]] || { fail "feed \"$name\": not in MISP's feed list"; continue; }
    state=$(jq -r --arg i "$id" "$JQ_ON"' .[] | .Feed | select(.id == $i)
      | if (.enabled | on) and (.caching_enabled | on) then "on" elif (.enabled | on) then "partial" else "off" end' <<<"$FEEDS")
    if [[ $want == true ]]; then
      if [[ $state == on ]]; then pass "feed \"$name\" (id $id): enabled"; continue; fi
      r=$(misp_admin POST "/feeds/edit/$id" '{"Feed": {"enabled": true, "caching_enabled": true}}')
      misp_ok "feed \"$name\": enable" "$r" || continue
      r=$(misp_admin POST "/feeds/fetchFromFeed/$id")
      misp_ok "feed \"$name\": fetch" "$r" || continue
      pass "feed \"$name\" (id $id): enabled, first fetch queued (MISP: Administration > Jobs)"
    else
      if [[ $state == off ]]; then pass "feed \"$name\" (id $id): disabled"; continue; fi
      r=$(misp_admin POST "/feeds/edit/$id" '{"Feed": {"enabled": false, "caching_enabled": false}}')
      misp_ok "feed \"$name\": disable" "$r" && pass "feed \"$name\" (id $id): disabled"
    fi
  done < <(jq -r '.feeds[] | [.name, (.enabled | tostring)] | @tsv' "$CONFIG_FILE")
}

cmd_apply() {
  apply_warninglists
  apply_feeds
}

cmd_fetch() {
  local id name r n=0
  load_feeds || return
  while IFS=$'\t' read -r id name; do
    r=$(misp_admin POST "/feeds/fetchFromFeed/$id")
    misp_ok "feed \"$name\": fetch" "$r" && pass "feed \"$name\" (id $id): fetch queued" && n=$((n + 1))
  done < <(jq -r "$JQ_ON"' .[] | .Feed | select(.enabled | on) | [.id, .name] | @tsv' <<<"$FEEDS")
  (( n > 0 )) || skip "no feed is enabled"
}

cmd_export() {
  local new tmp
  load_feeds || return
  # The feed list is too large for a jq argument: it comes on stdin.
  new=$(jq --slurpfile c "$CONFIG_FILE" "$JQ_ON"'
    [.[] | .Feed | select(.enabled | on) | .name] as $on
    | $c[0] | .feeds |= (map(.enabled = (.name as $n | $on | index($n) != null))
                         + [($on - map(.name))[] | {name: ., enabled: true}])' <<<"$FEEDS")
  tmp=$(mktemp "$(dirname "$CONFIG_FILE")/.misp-config.XXXXXX")
  printf '%s\n' "$new" >"$tmp"
  mv "$tmp" "$CONFIG_FILE"
  pass "exported the state of $(jq '.feeds | length' "$CONFIG_FILE") feed(s) to nodes/intel/misp/misp-config.json"
  info "review with: git diff nodes/intel/misp/misp-config.json"
}

case ${1:-} in
  apply|fetch|export) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
[[ -f "$(node_dir intel)/.env" ]] || die "nodes/intel/.env not found: run scripts/soc.sh init cases-intel (or intel) first"
[[ -n $(intel_env MISP_ADMIN_KEY) ]] || die "MISP_ADMIN_KEY is empty in nodes/intel/.env (run scripts/bootstrap.sh intel)"
jq empty "$CONFIG_FILE" || die "nodes/intel/misp/misp-config.json is not valid JSON"
"cmd_$1"
finish
