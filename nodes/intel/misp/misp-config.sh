#!/usr/bin/env bash
# MISP warninglists, feeds and service users as code (owner: Cortex + MISP).
# scripts/bootstrap.sh intel runs "apply" (R-22); run it by hand only after
# changing misp-config.json, on the machine that hosts the intel node.
#
# Usage: nodes/intel/misp/misp-config.sh <apply|fetch|export>
#   apply : update MISP's warninglists from the image and enable every list
#           with at most misp-config.json's warninglists.maxEntries entries
#           and disable larger ones (they exhaust misp-core's memory
#           limit); load MISP's default feed
#           list, then enable and cache the feeds marked "enabled": true
#           (queueing a first fetch) and disable those marked false. Feeds
#           not listed are left alone. Check that the seed event's test IOC
#           is on no warninglist (X-36) and delete older seed events. Create
#           the Read Only users of misp-config.json's n8n.user (contract
#           C10) and wazuh.user (C14), each with its own API key, stored as
#           MISP_N8N_API_KEY and MISP_WAZUH_API_KEY in nodes/intel/.env.
#           Idempotent.
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
  local r max ids batch total on wrong hit
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

# The seed event (C7) is created by bootstrap.sh from seed/seed-event.json.
# Its test IOC must be on no warninglist, or C10 tags the lab's only IOC as
# common (X-36). Seed events from before the IOC changed (other info, same
# asox:seed tag) are deleted, so every instance has the same single seed.
apply_seed() {
  local info ioc r seeds id old hit
  info=$(jq -r '.Event.info' "$MISP_SEED_FILE")
  ioc=$(jq -r '.Event.Attribute[0].value' "$MISP_SEED_FILE")
  r=$(misp_as "$(intel_env MISP_CORTEX_API_KEY)" POST /warninglists/checkValue "$(jq -nc --arg v "$ioc" '[$v]')")
  misp_ok "seed: checkValue $ioc" "$r" || return
  hit=$(http_body "$r" | jq -r --arg v "$ioc" '[objects | .[$v][]?.name] | join("\", \"")')
  if [[ -z $hit ]]; then pass "seed: test IOC $ioc is on no warninglist"
  else fail "seed: test IOC $ioc is on warninglist(s) \"$hit\" (X-36): pick another IOC in seed/seed-event.json"; fi
  r=$(misp_admin POST /events/restSearch '{"returnFormat": "json", "tags": ["asox:seed"], "metadata": true}')
  misp_ok "seed: list seed events" "$r" || return
  seeds=$(http_body "$r")
  if ! jq -e --arg i "$info" '[.response[]?.Event | select(.info == $i)] | length > 0' <<<"$seeds" >/dev/null; then
    skip "seed: \"$info\" not in MISP yet (scripts/bootstrap.sh intel creates it); older seed events kept"
    return
  fi
  while IFS=$'\t' read -r id old; do
    misp_ok "seed: delete old seed event $id" "$(misp_admin POST "/events/delete/$id")" \
      && pass "seed: old seed event $id (\"$old\") deleted"
  done < <(jq -r --arg i "$info" '.response[]?.Event | select(.info != $i) | [.id, .info] | @tsv' <<<"$seeds")
}

# ensure_ro_user LABEL EMAIL ENV_KEY COMMENT HINT: a Read Only user with its
# own API key, stored as ENV_KEY in nodes/intel/.env. Same steps as
# bootstrap.sh's user for Cortex (C7). Sets RO_KEY to the working key.
RO_KEY=""
ensure_ro_user() {
  local label=$1 email=$2 env_key=$3 comment=$4 hint=$5 r org_id role_id user_id key
  RO_KEY=""
  org_id=$(http_body "$(misp_admin GET /users/view/me)" | jq -r '.User.org_id')
  role_id=$(http_body "$(misp_admin GET /roles)" | jq -r '[.[] | (.Role // .) | select(.name == "Read Only") | .id] | first // empty')
  [[ -n $role_id ]] || { fail "$label: role \"Read Only\" not found"; return 1; }
  user_id=$(http_body "$(misp_admin GET /admin/users)" | jq -r --arg e "$email" '[.[] | select(.User.email == $e) | .User.id] | first // empty')
  if [[ -z $user_id ]]; then
    r=$(misp_admin POST /admin/users/add "$(jq -nc --arg e "$email" --arg o "$org_id" --arg r "$role_id" \
      '{email: $e, org_id: $o, role_id: $r, change_pw: false, notify: false, termsaccepted: true}')")
    misp_ok "$label: create $email" "$r" || return 1
    user_id=$(http_body "$r" | jq -r '.User.id')
  else
    r=$(misp_admin POST "/admin/users/edit/$user_id" "$(jq -nc --arg r "$role_id" --arg o "$org_id" '{role_id: $r, org_id: $o, disabled: false}')")
    misp_ok "$label: update $email" "$r" || return 1
  fi
  key=$(intel_env "$env_key")
  if [[ $(misp_key_email "$key") != "$email" ]]; then
    r=$(misp_admin POST "/auth_keys/add/$user_id" "$(jq -nc --arg c "$comment" '{comment: $c}')")
    key=$(http_body "$r" | jq -r '.AuthKey.authkey_raw // empty')
    if [[ -z $key || $(misp_key_email "$key") != "$email" ]]; then
      fail "$label: could not create a working API key for $email (HTTP $(http_code "$r"))"
      return 1
    fi
    env_set "$(node_dir intel)/.env" "$env_key" "$key"
    info "new $env_key in nodes/intel/.env: $hint"
  fi
  pass "$label: $email (Read Only), API key works"
  RO_KEY=$key
}

# ro_write_refused LABEL KEY: a write with KEY must get HTTP 403.
ro_write_refused() {
  local r
  r=$(misp_as "$2" POST /events/add '{"Event": {"info": "Read Only write check: must be refused", "distribution": 0}}')
  if [[ $(http_code "$r") == 403 ]]; then pass "$1: a write (POST /events/add) is refused"
  else fail "$1: POST /events/add answered HTTP $(http_code "$r"), expected 403"; fi
}

# C10: the Read Only user n8n calls POST /warninglists/checkValue with.
apply_n8n_user() {
  local label="n8n user (C10)" email r hit
  email=$(jq -r '.n8n.user // empty' "$CONFIG_FILE")
  if [[ -z $email ]]; then
    skip "$label: no n8n.user in misp-config.json"
    return
  fi
  ensure_ro_user "$label" "$email" MISP_N8N_API_KEY \
    "n8n warninglist check (C10), created by misp-config.sh" \
    "n8n's MISP credential needs it (R-13)" || return
  # C10's check: the key can read warninglists and nothing else.
  r=$(misp_as "$RO_KEY" POST /warninglists/checkValue '["8.8.8.8"]')
  hit=$(http_body "$r" | jq -r '.["8.8.8.8"][0].name // empty' 2>/dev/null || true)
  if [[ -n $hit ]]; then pass "$label: checkValue 8.8.8.8 -> \"$hit\""
  else fail "$label: checkValue matched no list for 8.8.8.8 (HTTP $(http_code "$r"))"; fi
  ro_write_refused "$label" "$RO_KEY"
}

# C14: the attributes Wazuh's misp-sync exports into its CDB lists
# (C14-reply-wazuh.md): published events, to_ids, these types, and nothing
# that is on an enabled warninglist.
C14_FILTER='{"returnFormat": "json", "type": ["ip-src", "ip-dst", "domain", "hostname", "md5", "sha1", "sha256"], "to_ids": 1, "published": 1, "enforceWarninglist": 1}'

# C14: the Read Only user Wazuh's misp-sync calls POST /attributes/restSearch
# with.
apply_wazuh_user() {
  local label="wazuh user (C14)" email ioc r n
  email=$(jq -r '.wazuh.user // empty' "$CONFIG_FILE")
  if [[ -z $email ]]; then
    skip "$label: no wazuh.user in misp-config.json"
    return
  fi
  ensure_ro_user "$label" "$email" MISP_WAZUH_API_KEY \
    "Wazuh CDB list sync (C14), created by misp-config.sh" \
    "core needs it as WAZUH_MISP_API_KEY (R-08): scripts/render-env.sh on the core machine" || return
  # C14's check: C14's filter returns the seed IOC (it must stay to_ids).
  ioc=$(jq -r '.Event.Attribute[0].value' "$MISP_SEED_FILE")
  r=$(misp_as "$RO_KEY" POST /attributes/restSearch "$(jq -c --arg v "$ioc" '. + {value: $v}' <<<"$C14_FILTER")")
  n=$(http_body "$r" | jq '[.response.Attribute[]?] | length' 2>/dev/null || echo 0)
  if (( n > 0 )); then pass "$label: C14's filter returns the seed IOC $ioc ($n attribute(s))"
  else fail "$label: C14's filter doesn't return the seed IOC $ioc (HTTP $(http_code "$r")); is it to_ids and published?"; fi
  ro_write_refused "$label" "$RO_KEY"
}

cmd_apply() {
  apply_warninglists
  apply_feeds
  apply_seed
  apply_n8n_user
  apply_wazuh_user
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
