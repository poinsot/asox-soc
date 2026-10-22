#!/usr/bin/env bash
# Replay test of pb-ssh-bruteforce (owner: n8n, N8N-4.2; first of N8N-0.6's
# per-playbook tests). Builds copies of the real 5763, 5712, 40112 and 100200
# fixtures in a temporary directory, each with a fresh alert id, the time now
# as timestamp and, per case, a source address in 198.51.100.200-250 that no
# TheHive alert carries yet; replays them through fixtures/replay.sh one after
# the other (each alert written back before the next is sent); then reads
# TheHive with n8n's key (the platform admin sees no SOC alerts) and the
# asox-metrics documents as n8n-indexer. One PASS/FAIL line per check.
#
# Cases:
#   a  5763, then 5712 from the same address: two ssh-bruteforce alerts, both
#      tagged ssh-campaign:<ip>; the second writeback lists the first
#   b  5763, then 40112: the 5763 alert raised 3 -> 4, tagged
#      ssh:login-after-bruteforce, exactly one escalation comment, its
#      asox-metrics severity 4; the 40112 writeback lists it
#   c  b's 40112 again with the same id: duplicate at intake (one queue row),
#      nothing new written, still one escalation comment
#   d  40112, then 5763 (the parallel-slot order): the 5763 escalates itself
#   e  5763 from an address with no history: no related alert, no escalation
#   f  100200: still pb-generic, caseTemplate suspicious-login
#   g  the parallel-slot race (N8N-4.2 follow-up): a 5763 whose TheHive alert
#      is raised to 4 with n8n's key (C4 drops the event, as it drops a
#      40112's raise) as soon as it appears, before its writeback: the run
#      writes its document with 3, then re-reads TheHive and re-syncs it to 4.
#      The re-read follows the writeback comment, so a raise that returns
#      while the comment is still missing came before the re-read; when the
#      writeback wins instead, the case is tried again (3 tries, then SKIP)
#
# Everything it created (TheHive alerts, asox-metrics documents) is deleted at
# the end, also on failure or interruption; the ids are listed. Needs core
# and cases running (intel optional: enrichment only), the workflows imported
# (scripts/n8n-import.sh). No secrets are printed: keys and passwords are read
# from nodes/core/.env into variables and handed to curl through stdin or a
# file descriptor.
#
# Usage: nodes/core/n8n/fixtures/tests/pb-ssh-bruteforce.sh [options]
#   --only CASES   run only these cases, e.g. a,e (default: a,b,c,d,e,f,g; c needs b)
#   --timeout S    seconds to wait for each alert's writeback (default 120)
#   -h, --help     show this help
# Exit code 1 if any check failed, 2 on usage errors.
# shellcheck disable=SC2016
# (jq programs in single quotes: their $names are jq variables, not shell)
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$(cd "$TEST_DIR/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$FIXTURES_DIR/../../../../scripts/lib/common.sh"
# shellcheck source=scripts/lib/cases.sh
source "$REPO_ROOT/scripts/lib/cases.sh"
# shellcheck source=scripts/lib/wazuh.sh
source "$REPO_ROOT/scripts/lib/wazuh.sh"

usage() { print_usage "$0"; }
usage_error() { printf 'ERROR %s\n' "$*" >&2; usage >&2; exit 2; }

CASES="a,b,c,d,e,f,g" TIMEOUT=120
while (( $# > 0 )); do
  case $1 in
    --only) CASES=${2:?--only needs a list, e.g. a,e}; shift ;;
    --timeout) TIMEOUT=${2:?--timeout needs seconds}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[[ $CASES =~ ^[a-g](,[a-g])*$ ]] || usage_error "--only takes letters a-g separated by commas"
[[ $TIMEOUT =~ ^[1-9][0-9]*$ ]] || usage_error "--timeout must be a positive number of seconds"
[[ ,$CASES, == *,c,* && ,$CASES, != *,b,* ]] && usage_error "case c replays case b's 40112: add b"

load_topology
[[ $TOPO_DEPLOY_MODE == distributed ]] && THEHIVE_API=http://$TOPO_CASES_HOST:9000
N8N_CONTAINER="$TOPO_SOC_INSTANCE-core-n8n-1"
PB=pb-ssh-bruteforce
N8N_USER=n8n@asox.local
WB_MARKER='[asox-n8n writeback]'
ESC_MARKER='[asox-n8n escalation]'
CAMPAIGN=ssh-campaign:
ESCALATED=ssh:login-after-bruteforce
F5763="$FIXTURES_DIR/wazuh/5763-sshd-bruteforce.json"
F5712="$FIXTURES_DIR/wazuh/5712-sshd-bruteforce-invalid-users.json"
F40112="$FIXTURES_DIR/wazuh/40112-login-after-bruteforce.json"
F100200="$FIXTURES_DIR/wazuh/100200-ssh-root-login.json"

TH_KEY=$(core_env THEHIVE_N8N_API_KEY)
[[ -n $TH_KEY ]] || die "THEHIVE_N8N_API_KEY is empty in nodes/core/.env (no cases node?)"
IDX_PASSWORD=$(core_env N8N_INDEXER_PASSWORD)
[[ -n $IDX_PASSWORD ]] || die "N8N_INDEXER_PASSWORD is empty in nodes/core/.env"
WORK=$(mktemp -d)
CREATED=()      # Wazuh alert ids of the copies sent (sourceRef = document id)
USED_IPS=()

# th METHOD PATH [JSON]: TheHive as n8n (key through a file descriptor, so it
# never appears in the process list). Prints the body, then the HTTP status on
# a last line.
th() {
  local -a args=(-s --max-time 15 -w '\n%{http_code}' -X "$1" "$THEHIVE_API$2")
  [[ -n ${3:-} ]] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  curl "${args[@]}" -H @<(printf 'Authorization: Bearer %s\n' "$TH_KEY") || printf '\n000'
}
# th_query JSON: the answer's array (empty on any error).
th_query() {
  local r
  r=$(th POST /api/v1/query "$1")
  [[ $(http_code "$r") == 200 ]] && http_body "$r" | jq -c 'if type == "array" then . else [] end' 2>/dev/null || echo '[]'
}
alerts_by_ref() { th_query "$(jq -nc --arg r "$1" '{query: [{_name: "listAlert"}, {_name: "filter", _field: "sourceRef", _value: $r}]}')"; }
alert_list() { th_query "$(jq -nc --arg a "$1" --arg l "$2" '{query: [{_name: "getAlert", idOrName: $a}, {_name: $l}, {_name: "page", from: 0, to: 500}]}')"; }
# Alerts with an ip observable equal to <ip>, any time (the pre-existing-alert rule).
alerts_with_ip() {
  th_query "$(jq -nc --arg ip "$1" '{query: [{_name: "listObservable"},
    {_name: "filter", _and: [{_field: "dataType", _value: "ip"}, {_field: "data", _value: $ip}]},
    {_name: "alert"}, {_name: "page", from: 0, to: 10}]}')"
}
# metrics_doc <id>: the asox-metrics document's _source, or empty.
metrics_doc() {
  local r
  r=$(indexer_as n8n-indexer "$IDX_PASSWORD" GET "/$ASOX_METRICS_INDEX/_doc/$1")
  if [[ $(http_code "$r") == 200 ]]; then http_body "$r" | jq -c '._source'; fi
}
# Comments by n8n whose first line is <line>, as a JSON array.
comments_starting() {
  alert_list "$1" comments | jq -c --arg u "$N8N_USER" --arg p "$2" \
    '[.[] | select(.createdBy == $u and ((.message // "") | split("\n")[0]) == $p)]'
}
writeback_text() { comments_starting "$1" "$WB_MARKER wazuh-alert-id=$2" | jq -r '.[0].message // ""'; }
# Rows of the alert queue (n8n Data Table) with this alert id: read-only.
queue_rows() {
  docker exec "$N8N_CONTAINER" node -e '
    const s = require("/usr/local/lib/node_modules/n8n/node_modules/sqlite3");
    const d = new s.Database("/home/node/.n8n/database.sqlite", s.OPEN_READONLY);
    d.get("SELECT id FROM data_table WHERE name = ?", ["asox_alert_queue"], (e, t) => {
      if (e || !t) { console.log("?"); return; }
      d.get(`SELECT count(*) AS n FROM data_table_user_${t.id} WHERE alert_id = ?`, [process.argv[1]], (e2, r) => console.log(e2 ? "?" : r.n));
    });' "$1" 2>/dev/null || echo '?'
}

# A source address in 198.51.100.200-250 that no TheHive alert carries and
# this run hasn't used, in PICKED. These helpers run in this shell, not in
# $(...), so CREATED and USED_IPS keep what they add.
PICKED="" COPY=""
pick_ip() {
  local n ip
  for n in $(shuf -i 200-250); do
    ip=198.51.100.$n
    [[ " ${USED_IPS[*]} " == *" $ip "* ]] && continue
    if [[ $(alerts_with_ip "$ip" | jq 'length') == 0 ]]; then
      USED_IPS+=("$ip"); PICKED=$ip; return 0
    fi
  done
  die "no unused address left in 198.51.100.200-250"
}
# copy FIXTURE IP: a copy with a fresh id, the time now and data.srcip IP (the
# old address replaced in the log line and description too), in COPY.
copy_fixture() {
  local f=$1 ip=$2 id out old
  id="$(date +%s).$$$(printf '%05d' "$RANDOM")"
  out="$WORK/$id.json"
  old=$(jq -r '.data.srcip' "$f")
  jq --arg id "$id" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)" --arg ip "$ip" --arg old "$old" '
    def swap: if type == "string" then split($old) | join($ip) else . end;
    .id = $id | .timestamp = $ts | .data.srcip = $ip
    | .full_log |= swap | .rule.description |= swap
    | if has("previous_output") then .previous_output |= swap else . end' "$f" > "$out"
  CREATED+=("$id")
  COPY=$out
}
# send FILE: replay it; waits for its TheHive alert and writeback. Sets
# TH_ID (empty on timeout) and WB (the writeback text).
send() {
  local file=$1 id deadline
  id=$(jq -r '.id' "$file")
  TH_ID="" WB=""
  if ! "$FIXTURES_DIR/replay.sh" --file "$file" >/dev/null; then
    fail "replay of $(jq -r '.rule.id' "$file") alert $id: replay.sh failed"; return 0
  fi
  deadline=$(( SECONDS + TIMEOUT ))
  while (( SECONDS < deadline )); do
    TH_ID=$(alerts_by_ref "$id" | jq -r 'if length == 1 then .[0]._id else empty end')
    if [[ -n $TH_ID ]]; then
      WB=$(writeback_text "$TH_ID" "$id")
      [[ -n $WB ]] && return 0
    fi
    sleep 3
  done
  fail "alert $id (rule $(jq -r '.rule.id' "$file")): no TheHive alert with one writeback within ${TIMEOUT}s"
  TH_ID=""
}
alert_json() { th_query "$(jq -nc --arg a "$1" '{query: [{_name: "getAlert", idOrName: $a}]}')" | jq -c '.[0] // {}'; }
check() { local name=$1; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
# jqt JSON FILTER [jq options]: the filter holds for JSON.
jqt() { local j=$1 f=$2; shift 2; jq -e "$@" "$f" >/dev/null <<<"$j"; }
has_tag() { jqt "$1" '(.tags // []) | index($t) != null' --arg t "$2"; }
field_is() { jqt "$1" '.[$f] == $v' --arg f "$2" --argjson v "$3"; }
# wb_has TEXT STRING...: every string is in the text.
wb_has() { local t=$1 s; shift; for s in "$@"; do grep -qF -- "$s" <<<"$t" || return 1; done; }
wb_lacks() { ! grep -qF -- "$2" <<<"$1"; }
# wb_line TEXT A B: a line containing A also contains B.
wb_line() { grep -F -- "$2" <<<"$1" | grep -qF -- "$3"; }
n_escalation_comments() { comments_starting "$1" "$ESC_MARKER wazuh-alert-id=$2" | jq 'length'; }

cleanup() {
  local id th_id r deleted=()
  for id in "${CREATED[@]}"; do
    for th_id in $(alerts_by_ref "$id" | jq -r '.[]._id'); do
      r=$(th DELETE "/api/v1/alert/$th_id")
      if [[ $(http_code "$r") == 204 ]]; then deleted+=("TheHive alert $th_id ($id)")
      else warn "cleanup: deleting TheHive alert $th_id returned HTTP $(http_code "$r"); delete it by hand"; fi
    done
    r=$(indexer_as n8n-indexer "$IDX_PASSWORD" DELETE "/$ASOX_METRICS_INDEX/_doc/$id")
    [[ $(http_code "$r") == 200 ]] && deleted+=("$ASOX_METRICS_INDEX document $id")
  done
  local d
  for d in "${deleted[@]}"; do info "cleanup: deleted $d"; done
  (( ${#deleted[@]} > 0 )) || info "cleanup: nothing to delete"
  rm -rf "$WORK"
}
trap cleanup EXIT

run_case() { [[ ,$CASES, == *,$1,* ]]; }
echo "== $PB replay test (cases $CASES)"

if run_case a; then
  pick_ip; ip=$PICKED; info "a: address $ip"
  copy_fixture "$F5763" "$ip"; f1=$COPY; id1=$(jq -r .id "$f1")
  send "$f1"; th1=$TH_ID
  copy_fixture "$F5712" "$ip"; send "$COPY"; th2=$TH_ID wb2=$WB
  if [[ -n $th1 && -n $th2 ]]; then
    a1=$(alert_json "$th1") a2=$(alert_json "$th2")
    check "a: 5763 alert $th1 is ssh-bruteforce, tagged $CAMPAIGN$ip" \
      jqt "$a1" '.caseTemplate == "ssh-bruteforce" and ((.tags // []) | index($t) != null)' --arg t "$CAMPAIGN$ip"
    check "a: 5712 alert $th2 is ssh-bruteforce, tagged $CAMPAIGN$ip" \
      jqt "$a2" '.caseTemplate == "ssh-bruteforce" and ((.tags // []) | index($t) != null)' --arg t "$CAMPAIGN$ip"
    check "a: second writeback ran $PB and lists the first ($id1)" wb_has "$wb2" "playbook **$PB**" \
      "Related (same source within 1 h): 1 alert(s) from $ip" "Wazuh $id1: rule 5763"
    check "a: no escalation" wb_lacks "$wb2" "Escalat"
  fi
fi

if run_case b; then
  pick_ip; ip=$PICKED; info "b: address $ip"
  copy_fixture "$F5763" "$ip"; f3=$COPY; id3=$(jq -r .id "$f3")
  send "$f3"; th3=$TH_ID
  copy_fixture "$F40112" "$ip"; f4=$COPY; id4=$(jq -r .id "$f4")
  send "$f4"; th4=$TH_ID wb4=$WB
  if [[ -n $th3 && -n $th4 ]]; then
    a3=$(alert_json "$th3") a4=$(alert_json "$th4")
    check "b: 5763 alert $th3 raised to severity 4" field_is "$a3" severity 4
    check "b: 5763 alert tagged $ESCALATED" has_tag "$a3" "$ESCALATED"
    check "b: exactly one escalation comment on the 5763 alert" test "$(n_escalation_comments "$th3" "$id4")" = 1
    check "b: 5763 asox-metrics severity 4" field_is "$(metrics_doc "$id3")" severity 4
    check "b: 40112 alert $th4 is suspicious-login, severity 4, tagged $CAMPAIGN$ip" \
      jqt "$a4" '.caseTemplate == "suspicious-login" and .severity == 4 and ((.tags // []) | index($t) != null)' --arg t "$CAMPAIGN$ip"
    check "b: 40112 writeback lists the escalated 5763 with 3 → 4" wb_line "$wb4" "Escalated: TheHive $th3 (Wazuh $id3, rule 5763" "severity 3 → 4"
    check "b: 40112 asox-metrics: playbook $PB, severity 4" jqt "$(metrics_doc "$id4")" '.playbook == $p and .severity == 4' --arg p "$PB"
  fi
fi

if run_case c && [[ -n ${th3:-} && -n ${th4:-} ]]; then
  if "$FIXTURES_DIR/replay.sh" --file "$f4" >/dev/null; then
    # A delivery that got through would be processed within a few seconds:
    # watch for 20 s that nothing new appears.
    deadline=$(( SECONDS + 20 ))
    while (( SECONDS < deadline )); do sleep 4; done
    check "c: duplicate at intake (one queue row for $id4)" test "$(queue_rows "$id4")" = 1
    check "c: still one TheHive alert for $id4" test "$(alerts_by_ref "$id4" | jq 'length')" = 1
    check "c: still one writeback on $th4" test "$(comments_starting "$th4" "$WB_MARKER wazuh-alert-id=$id4" | jq 'length')" = 1
    check "c: still one escalation comment on $th3" test "$(n_escalation_comments "$th3" "$id4")" = 1
  else
    fail "c: replay of $id4 failed"
  fi
fi

if run_case d; then
  pick_ip; ip=$PICKED; info "d: address $ip"
  copy_fixture "$F40112" "$ip"; f5=$COPY; id5=$(jq -r .id "$f5")
  send "$f5"; th5=$TH_ID wb5=$WB
  copy_fixture "$F5763" "$ip"; f6=$COPY; id6=$(jq -r .id "$f6")
  send "$f6"; th6=$TH_ID wb6=$WB
  if [[ -n $th5 && -n $th6 ]]; then
    a6=$(alert_json "$th6")
    check "d: the 40112 found nothing to escalate yet" wb_has "$wb5" "no related ssh-bruteforce alert to escalate"
    check "d: 5763 alert $th6 escalated itself: severity 4, tagged $ESCALATED and $CAMPAIGN$ip" \
      jqt "$a6" '.severity == 4 and ((.tags // []) | index($e) != null and index($c) != null)' --arg e "$ESCALATED" --arg c "$CAMPAIGN$ip"
    check "d: one escalation comment naming the 40112 ($id5)" test "$(n_escalation_comments "$th6" "$id5")" = 1
    check "d: writeback says so" wb_line "$wb6" "Escalated this alert ($ESCALATED): rule 40112 alert $id5" "severity 3 → 4"
    check "d: 5763 asox-metrics severity 4" field_is "$(metrics_doc "$id6")" severity 4
  fi
fi

if run_case e; then
  pick_ip; ip=$PICKED; info "e: address $ip"
  copy_fixture "$F5763" "$ip"; send "$COPY"; th7=$TH_ID wb7=$WB
  if [[ -n $th7 ]]; then
    a7=$(alert_json "$th7")
    check "e: no related alert" wb_has "$wb7" "Related (same source within 1 h): 0 alert(s) from $ip"
    check "e: no escalation: severity 3, no $ESCALATED tag" jqt "$a7" '.severity == 3 and ((.tags // []) | index($e) == null)' --arg e "$ESCALATED"
    check "e: tagged $CAMPAIGN$ip" has_tag "$a7" "$CAMPAIGN$ip"
    check "e: response recommended, nothing changed" wb_has "$wb7" "Recommended: block $ip (response actions, C9, Phase 2); nothing was changed."
  fi
fi

if run_case f; then
  pick_ip; ip=$PICKED; info "f: address $ip"
  copy_fixture "$F100200" "$ip"; send "$COPY"; th8=$TH_ID wb8=$WB
  if [[ -n $th8 ]]; then
    a8=$(alert_json "$th8")
    check "f: 100200 still runs pb-generic (route suspicious-login)" wb_has "$wb8" "playbook **pb-generic**" \
      "Route: suspicious-login (rule 100200): playbook pb-generic, case template suspicious-login."
    check "f: caseTemplate suspicious-login" field_is "$a8" caseTemplate '"suspicious-login"'
    check "f: no $CAMPAIGN tag" jqt "$a8" '[(.tags // [])[] | select(startswith($p))] | length == 0' --arg p "$CAMPAIGN"
  fi
fi

if run_case g; then
  hit="" stopped=""
  for try in 1 2 3; do
    pick_ip; ip=$PICKED; info "g: address $ip (try $try)"
    copy_fixture "$F5763" "$ip"; f9=$COPY; id9=$(jq -r .id "$f9")
    if ! "$FIXTURES_DIR/replay.sh" --file "$f9" >/dev/null; then fail "g: replay of $id9 failed"; stopped=yes; break; fi
    th9="" deadline=$(( SECONDS + TIMEOUT ))
    while [[ -z $th9 ]] && (( SECONDS < deadline )); do
      th9=$(alerts_by_ref "$id9" | jq -r 'if length == 1 then .[0]._id else empty end')
      [[ -n $th9 ]] || sleep 0.2
    done
    [[ -n $th9 ]] || { fail "g: no TheHive alert for $id9 within ${TIMEOUT}s"; stopped=yes; break; }
    r=$(th PATCH "/api/v1/alert/$th9" '{"severity":4}')
    [[ $(http_code "$r") == 204 ]] || { fail "g: raising $th9 returned HTTP $(http_code "$r")"; stopped=yes; break; }
    if [[ -z $(writeback_text "$th9" "$id9") ]]; then hit=yes; break; fi
    info "g: the writeback of $th9 came before the raise: try again"
  done
  if [[ $hit == yes ]]; then
    wb9="" deadline=$(( SECONDS + TIMEOUT ))
    while [[ -z $wb9 ]] && (( SECONDS < deadline )); do
      wb9=$(writeback_text "$th9" "$id9"); [[ -n $wb9 ]] || sleep 1
    done
    # The re-sync runs right after the writeback: poll the document briefly.
    doc9="" deadline=$(( SECONDS + 30 ))
    while (( SECONDS < deadline )); do
      doc9=$(metrics_doc "$id9"); [[ -n $doc9 ]] || doc9='{}'
      jqt "$doc9" '.severity == 4' && break
      sleep 1
    done
    check "g: the run didn't see the raise (writeback: created with severity 3)" wb_line "$wb9" "TheHive alert created:" "severity 3,"
    check "g: TheHive alert $th9 at severity 4" field_is "$(alert_json "$th9")" severity 4
    check "g: asox-metrics document $id9 re-synced to severity 4" field_is "$doc9" severity 4
  elif [[ -z $stopped ]]; then
    skip "g: the writeback won the race 3 times: re-sync not exercised"
  fi
fi

finish
