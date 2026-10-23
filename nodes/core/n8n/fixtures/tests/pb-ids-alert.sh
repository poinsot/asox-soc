#!/usr/bin/env bash
# Replay test of pb-ids-alert (owner: n8n, N8N-4.4; N8N-0.6's per-playbook
# tests). Builds copies of the real Suricata fixtures (101001 ids-test, 101010
# ids-scan) in a temporary directory, each with a fresh alert id, the time now
# as timestamp, its own addresses and a signature_id nobody uses (99xxxxxx,
# outside Suricata's and ET's ranges), changed in data.*, data.flow.*, the EVE
# line (full_log) and the rule description; replays them through
# fixtures/replay.sh one after the other (each alert written back before the
# next is sent); then reads TheHive with n8n's key (the platform admin sees no
# SOC alerts) and the asox-metrics documents as n8n-indexer. One PASS/FAIL
# line per check.
#
# Cases:
#   a  101001 from the lab host (172.22.0.2) to a fresh documentation address:
#      route ids-network-alert, playbook pb-ids-alert, the IDS section, the
#      remote party is the destination, no asox:verdict tag, severity 3, one
#      writeback, the document's playbook
#   b  two copies to the same fresh address (different signature_ids): the
#      second's "Related IDS alerts (1 h)" lists the first (same remote);
#      nothing written on the first
#   c  two copies to two fresh addresses with the same signature_id: the
#      second lists the first, counted as the same signature
#   d  101010 (nmap scan between two lab hosts): ids-network-alert,
#      pb-ids-alert, the remote party is the scanner (both internal: the
#      source)
#   e  a's alert again with the same id: duplicate at intake (one queue row),
#      nothing new written
#   f  101001 to the MISP seed IOC 101.99.75.184 (X-36): MISP_2_1 says
#      suspicious, the alert is tagged asox:verdict=suspicious, severity
#      unchanged
# Without analyzer keys only MISP_2_1 runs, so a live remote address reaches
# suspicious at most; the malicious path (severity raised to 4) is covered by
# the harness, not here.
#
# Everything it created (TheHive alerts, asox-metrics documents) is deleted at
# the end, also on failure or interruption; the ids are listed. Needs core,
# cases and intel running (MISP for case f), the workflows imported
# (scripts/n8n-import.sh). Reads the alert queue's row count read-only (docker
# exec). No secrets are printed: keys and passwords are read from
# nodes/core/.env into variables and handed to curl through a file descriptor.
#
# Usage: nodes/core/n8n/fixtures/tests/pb-ids-alert.sh [options]
#   --only CASES   run only these cases, e.g. a,d (default: a,b,c,d,e,f; e needs a)
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

CASES="a,b,c,d,e,f" TIMEOUT=120
while (( $# > 0 )); do
  case $1 in
    --only) CASES=${2:?--only needs a list, e.g. a,d}; shift ;;
    --timeout) TIMEOUT=${2:?--timeout needs seconds}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[[ $CASES =~ ^[a-f](,[a-f])*$ ]] || usage_error "--only takes letters a-f separated by commas"
[[ $TIMEOUT =~ ^[1-9][0-9]*$ ]] || usage_error "--timeout must be a positive number of seconds"
[[ ,$CASES, == *,e,* && ,$CASES, != *,a,* ]] && usage_error "case e replays case a's alert: add a"

load_topology
[[ $TOPO_DEPLOY_MODE == distributed ]] && THEHIVE_API=http://$TOPO_CASES_HOST:9000
N8N_CONTAINER="$TOPO_SOC_INSTANCE-core-n8n-1"
PB=pb-ids-alert
ROUTE=ids-network-alert
N8N_USER=n8n@asox.local
WB_MARKER='[asox-n8n writeback]'
VERDICT=asox:verdict=
SEED_IOC=101.99.75.184
LAB_HOST=172.22.0.2
F101001="$FIXTURES_DIR/wazuh/101001-suricata-id-check-root.json"
F101010="$FIXTURES_DIR/wazuh/101010-suricata-nmap-syn-scan.json"

TH_KEY=$(core_env THEHIVE_N8N_API_KEY)
[[ -n $TH_KEY ]] || die "THEHIVE_N8N_API_KEY is empty in nodes/core/.env (no cases node?)"
IDX_PASSWORD=$(core_env N8N_INDEXER_PASSWORD)
[[ -n $IDX_PASSWORD ]] || die "N8N_INDEXER_PASSWORD is empty in nodes/core/.env"
WORK=$(mktemp -d)
CREATED=()      # Wazuh alert ids of the copies sent (sourceRef = document id)
USED_IPS=()
USED_SIDS=()

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
alert_json() { th_query "$(jq -nc --arg a "$1" '{query: [{_name: "getAlert", idOrName: $a}]}')" | jq -c '.[0] // {}'; }
alerts_with_ip() {
  th_query "$(jq -nc --arg ip "$1" '{query: [{_name: "listObservable"},
    {_name: "filter", _and: [{_field: "dataType", _value: "ip"}, {_field: "data", _value: $ip}]},
    {_name: "alert"}, {_name: "page", from: 0, to: 10}]}')"
}
# Suricata alerts (tag suricata) whose description mentions <term>, any time.
ids_alerts_mentioning() {
  th_query "$(jq -nc --arg t "*$1*" '{query: [{_name: "listAlert"},
    {_name: "filter", _and: [{_in: {_field: "tags", _values: ["suricata"]}}, {_like: {_field: "description", _value: $t}}]},
    {_name: "page", from: 0, to: 10}]}')"
}
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

# pick_ip: a documentation address (198.51.100.200-250) no TheHive alert
# carries, as an observable or in a Suricata alert's description; in PICKED.
pick_ip() {
  local n ip
  for n in $(shuf -i 200-250); do
    ip=198.51.100.$n
    [[ " ${USED_IPS[*]} " == *" $ip "* ]] && continue
    if [[ $(alerts_with_ip "$ip" | jq 'length') == 0 && $(ids_alerts_mentioning "$ip" | jq 'length') == 0 ]]; then
      USED_IPS+=("$ip"); PICKED=$ip; return 0
    fi
  done
  die "no unused address left in 198.51.100.200-250"
}
# pick_sid: a signature_id 99000000-99999999 no Suricata alert mentions; in PICKED.
pick_sid() {
  local sid
  for _ in 1 2 3 4 5; do
    sid=99$(shuf -i 100000-999999 -n 1)
    [[ " ${USED_SIDS[*]} " == *" $sid "* ]] && continue
    if [[ $(ids_alerts_mentioning "$sid" | jq 'length') == 0 ]]; then
      USED_SIDS+=("$sid"); PICKED=$sid; return 0
    fi
  done
  die "no unused signature_id found in 5 tries"
}
# copy_fixture FIXTURE SRC DST SID: a copy with a fresh id, the time now, the
# source and destination addresses SRC / DST and the signature_id SID (in
# data.*, data.flow.*, the EVE line and the rule description). In COPY (runs
# in this shell, so CREATED keeps the id).
COPY=""
copy_fixture() {
  local f=$1 src=$2 dst=$3 sid=$4 id out
  id="$(date +%s).$$$(printf '%05d' "$RANDOM")"
  out="$WORK/$id.json"
  jq --arg id "$id" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+0000)" --arg src "$src" --arg dst "$dst" --arg sid "$sid" '
    .data.src_ip as $os | .data.dest_ip as $od
    | def swap: if type == "string" then split($os) | join("\u0000") | split($od) | join($dst) | split("\u0000") | join($src) else . end;
    .id = $id | .timestamp = $ts
    | .data.src_ip = $src | .data.dest_ip = $dst | .data.flow.src_ip = $src | .data.flow.dest_ip = $dst
    | .data.alert.signature_id = $sid
    | .full_log |= (fromjson | .src_ip = $src | .dest_ip = $dst | .flow.src_ip = $src | .flow.dest_ip = $dst
        | .alert.signature_id = ($sid | tonumber) | tojson)
    | .rule.description |= swap' "$f" > "$out"
  CREATED+=("$id")
  COPY=$out
}
# send FILE: replay it; waits for its TheHive alert and writeback. Sets TH_ID
# (empty on timeout) and WB (the writeback text).
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
check() { local name=$1; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
jqt() { local j=$1 f=$2; shift 2; jq -e "$@" "$f" >/dev/null <<<"$j"; }
has_tag() { jqt "$1" '(.tags // []) | index($t) != null' --arg t "$2"; }
field_is() { jqt "$1" '.[$f] == $v' --arg f "$2" --argjson v "$3"; }
wb_has() { local t=$1 s; shift; for s in "$@"; do grep -qF -- "$s" <<<"$t" || return 1; done; }
wb_lacks() { ! grep -qF -- "$2" <<<"$1"; }
wb_line() { grep -F -- "$2" <<<"$1" | grep -qF -- "$3"; }

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
  pick_ip; ipa=$PICKED; pick_sid; sida=$PICKED
  copy_fixture "$F101001" "$LAB_HOST" "$ipa" "$sida"; fa=$COPY; ida=$(jq -r .id "$fa")
  send "$fa"; tha=$TH_ID wba=$WB
  if [[ -n $tha ]]; then
    a=$(alert_json "$tha")
    check "a: alert $tha is $ROUTE, ran $PB" jqt "$a" '.caseTemplate == $r' --arg r "$ROUTE"
    check "a: writeback names the route and $PB" wb_has "$wba" "playbook **$PB**" "Route: $ROUTE (" \
      "): playbook $PB, case template $ROUTE."
    check "a: IDS section (signature, signature_id $sida, category, severity, flow, sensor)" wb_has "$wba" \
      "IDS alert (N8N-4.4): GPL ATTACK_RESPONSE id check returned root (signature_id $sida), category Potentially Bad Traffic, Suricata severity 2, TCP $LAB_HOST:48362 → $ipa:80, sensor lab-agent."
    check "a: remote party $ipa, the destination" wb_has "$wba" "Remote party: $ipa (destination; the source is internal): "
    check "a: nothing changed, recommendation" wb_has "$wba" "Nothing changed on the alert (the remote address isn't suspicious or malicious)." \
      "Recommended: review the remote address; blocking needs response on the attacked host (C9 scope: SSH playbook only); nothing was changed."
    check "a: no $VERDICT tag on the alert, severity 3" jqt "$a" '.severity == 3 and ([(.tags // [])[] | select(startswith($p))] | length == 0)' --arg p "$VERDICT"
    check "a: exactly one writeback" test "$(comments_starting "$tha" "$WB_MARKER wazuh-alert-id=$ida" | jq 'length')" = 1
    check "a: asox-metrics playbook $PB, severity 3" jqt "$(metrics_doc "$ida")" '.playbook == $p and .severity == 3' --arg p "$PB"
  fi
fi

if run_case b; then
  pick_ip; ipb=$PICKED; pick_sid; sidb1=$PICKED; pick_sid; sidb2=$PICKED
  copy_fixture "$F101001" "$LAB_HOST" "$ipb" "$sidb1"; idb1=$(jq -r .id "$COPY"); send "$COPY"; thb1=$TH_ID
  copy_fixture "$F101001" "$LAB_HOST" "$ipb" "$sidb2"; send "$COPY"; thb2=$TH_ID wbb2=$WB
  if [[ -n $thb1 && -n $thb2 ]]; then
    check "b: second writeback lists the first ($thb1) by remote" wb_line "$wbb2" "TheHive $thb1 (Wazuh $idb1)" "remote $ipb, host lab-agent at "
    check "b: listed as same remote, not same signature" wb_line "$wbb2" "TheHive $thb1 (Wazuh $idb1)" "(same remote)"
    check "b: header 1 alert, 1 with the remote address, 0 with the signature" wb_has "$wbb2" \
      "Related IDS alerts (1 h): 1 alert(s) (1 with the remote address $ipb, 0 with the same signature_id $sidb2)."
    check "b: the first alert got no comment from the second" test "$(alert_list "$thb1" comments | jq 'length')" = 1
  fi
fi

if run_case c; then
  pick_ip; ipc1=$PICKED; pick_ip; ipc2=$PICKED; pick_sid; sidc=$PICKED
  copy_fixture "$F101001" "$LAB_HOST" "$ipc1" "$sidc"; idc1=$(jq -r .id "$COPY"); send "$COPY"; thc1=$TH_ID
  copy_fixture "$F101001" "$LAB_HOST" "$ipc2" "$sidc"; send "$COPY"; thc2=$TH_ID wbc2=$WB
  if [[ -n $thc1 && -n $thc2 ]]; then
    check "c: second writeback lists the first ($thc1, remote $ipc1) by signature" \
      wb_line "$wbc2" "TheHive $thc1 (Wazuh $idc1): GPL ATTACK_RESPONSE id check returned root ($sidc), remote $ipc1" "(same signature)"
    check "c: header 1 alert, 0 with the remote address, 1 with the signature" wb_has "$wbc2" \
      "Related IDS alerts (1 h): 1 alert(s) (0 with the remote address $ipc2, 1 with the same signature_id $sidc)."
  fi
fi

if run_case d; then
  pick_sid; sidd=$PICKED
  scanner=$(jq -r '.data.src_ip' "$F101010")
  copy_fixture "$F101010" "$scanner" "$LAB_HOST" "$sidd"; send "$COPY"; thd=$TH_ID wbd=$WB
  if [[ -n $thd ]]; then
    check "d: 101010 alert $thd is $ROUTE (not network-scan), ran $PB" wb_has "$wbd" "Route: $ROUTE (" "): playbook $PB, case template $ROUTE."
    check "d: caseTemplate $ROUTE" field_is "$(alert_json "$thd")" caseTemplate "\"$ROUTE\""
    check "d: remote party the scanner $scanner (both internal: the source)" \
      wb_has "$wbd" "Remote party: $scanner (source; both internal (a LAN attack)): "
  fi
fi

if run_case e && [[ -n ${tha:-} ]]; then
  before=$(alert_json "$tha" | jq -c '{tags, severity}')
  if "$FIXTURES_DIR/replay.sh" --file "$fa" >/dev/null; then
    # A delivery that got through would be processed within a few seconds:
    # watch for 20 s that nothing new appears.
    deadline=$(( SECONDS + 20 ))
    while (( SECONDS < deadline )); do sleep 4; done
    check "e: duplicate at intake (one queue row for $ida)" test "$(queue_rows "$ida")" = 1
    check "e: still one TheHive alert for $ida" test "$(alerts_by_ref "$ida" | jq 'length')" = 1
    check "e: still one comment on $tha" test "$(alert_list "$tha" comments | jq 'length')" = 1
    check "e: tags and severity unchanged" test "$(alert_json "$tha" | jq -c '{tags, severity}')" = "$before"
  else
    fail "e: replay of $ida failed"
  fi
fi

if run_case f; then
  n=$(ids_alerts_mentioning "$SEED_IOC" | jq 'length')
  info "f: seed IOC $SEED_IOC ($n existing Suricata alert(s) mention it)"
  pick_sid; sidf=$PICKED
  copy_fixture "$F101001" "$LAB_HOST" "$SEED_IOC" "$sidf"; idf=$(jq -r .id "$COPY"); send "$COPY"; thf=$TH_ID wbf=$WB
  if [[ -n $thf ]]; then
    f=$(alert_json "$thf")
    check "f: MISP_2_1 suspicious on $SEED_IOC" wb_line "$wbf" "Enriched: ip $SEED_IOC: verdict suspicious" "MISP_2_1: suspicious"
    check "f: remote party $SEED_IOC, verdict suspicious" wb_has "$wbf" "Remote party: $SEED_IOC (destination; the source is internal): verdict suspicious."
    check "f: alert $thf tagged ${VERDICT}suspicious" has_tag "$f" "${VERDICT}suspicious"
    check "f: severity unchanged (3)" jqt "$f" '.severity == 3'
    check "f: no severity line" wb_lacks "$wbf" "Severity "
    check "f: writeback says so" wb_has "$wbf" "Tagged this alert ${VERDICT}suspicious."
    check "f: asox-metrics severity 3" field_is "$(metrics_doc "$idf")" severity 3
  fi
fi

finish
