#!/usr/bin/env bash
# Rule test runner (owner: Wazuh). Copies the repo's rules/ and decoders/ into
# the running manager, checks that the ruleset loads cleanly, then sends each
# test case through wazuh-logtest and compares the result with what the case
# expects. One PASS/FAIL line per check; exit 1 if any check fails.
#
# Usage: nodes/core/wazuh/tests/run.sh [--no-sync] [FILTER]
#   --no-sync  test what the manager already has (don't copy the repo files)
#   FILTER     only run cases whose file or name contains this text
#
# The copy changes nothing until the manager restarts: wazuh-logtest loads the
# rules from disk for each session, the running analysis engine does not.
# Case files are tests/cases/*.cases; their format is in tests/README.md.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(cd "$WAZUH_DIR/../../.." && pwd)"
OSSEC=/var/ossec

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

sync=1 filter=""
while (( $# > 0 )); do
  case $1 in
    --no-sync) sync=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) filter=$1 ;;
  esac
  shift
done

instance=$(sed -n 's/^SOC_INSTANCE=//p' "$REPO_DIR/topology.env" 2>/dev/null | tail -1)
MANAGER="${instance:-asox}-core-wazuh-manager-1"
if [[ $(docker inspect -f '{{.State.Running}}' "$MANAGER" 2>/dev/null) != true ]]; then
  echo "ERROR manager container $MANAGER is not running (scripts/soc.sh up core)" >&2
  exit 2
fi

fails=0 passes=0
pass() { echo "PASS  $*"; passes=$((passes + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

# 1. Copy the repo's rule and decoder files into the manager.
if (( sync )); then
  for kind in rules decoders; do
    for f in "$WAZUH_DIR/$kind"/*.xml; do
      [[ -e $f ]] || continue
      docker exec -i "$MANAGER" sh -c "cat > $OSSEC/etc/$kind/${f##*/} && chown wazuh:wazuh $OSSEC/etc/$kind/${f##*/} && chmod 660 $OSSEC/etc/$kind/${f##*/}" < "$f"
    done
    # A file in the manager but not in the repo was removed or renamed:
    # it still loads until it's deleted by hand (README, "Removing or renaming a file").
    for f in $(docker exec "$MANAGER" sh -c "ls $OSSEC/etc/$kind/ 2>/dev/null"); do
      [[ $f == local_decoder.xml || -e $WAZUH_DIR/$kind/$f ]] || echo "WARN  $kind/$f is in the manager but not in the repo (still loaded; see README to remove it)"
    done
  done
fi

# 2. The ruleset must load without errors, and without rules dropped because
#    a parent wasn't found (7617, 7619: a child loaded before its parent's file).
check=$(docker exec "$MANAGER" "$OSSEC/bin/wazuh-analysisd" -t 2>&1) || true
problems=$(grep -E 'ERROR|CRITICAL|\(76(17|19)\)' <<<"$check" || true)
if [[ -z $problems ]]; then
  pass "ruleset loads (wazuh-analysisd -t)"
else
  fail "ruleset loads (wazuh-analysisd -t):"
  while IFS= read -r p; do echo "        $p"; done <<<"$problems"
fi

# 3. Run each case in its own logtest session. A case passes when some event
#    of the session produced the expected rule (frequency rules fire on an
#    event in the middle, then stay quiet for their "ignore" time).
#    Result lines from the parser: "<rule id>|<level>|<groups>|<decoder>|<alert yes/no>".
parse() {
  awk '
    function flush() { if (started) print rule "|" level "|" groups "|" dec "|" alert }
    /\*\*Phase 1:/ { flush(); started=1; rule=""; level=""; groups=""; dec=""; alert="no" }
    /^\tname: /    { dec=$2;   gsub(/\047/, "", dec) }
    /^\tid: /      { rule=$2;  gsub(/\047/, "", rule) }
    /^\tlevel: /   { level=$2; gsub(/\047/, "", level) }
    /^\tgroups: /  { sub(/^\tgroups: /, ""); gsub(/[\047\[\] ]/, ""); groups=$0 }
    /\*\*Alert to be generated/ { alert="yes" }
    END { flush() }'
}

check() {  # file, name, one expect line, logtest results
  local file=$1 name=$2 expect=$3 results=$4 want_rule="" want_level="" want_groups="" want_dec="" not_rule="" kv
  for kv in $expect; do
    case $kv in
      rule=*) want_rule=${kv#rule=} ;;
      not=*) not_rule=${kv#not=} ;;
      level=*) want_level=${kv#level=} ;;
      groups=*) want_groups=${kv#groups=} ;;
      decoder=*) want_dec=${kv#decoder=} ;;
      *) fail "$file: $name: unknown expect key '$kv'"; return ;;
    esac
  done
  if [[ -n $not_rule ]]; then
    if cut -d'|' -f1 <<<"$results" | grep -qx "$not_rule"; then
      fail "$file: $name: rule $not_rule must not fire, but it did"
    else
      pass "$file: $name (rule $not_rule did not fire)"
    fi
    [[ -n $want_rule ]] || return 0
  fi
  [[ -n $want_rule ]] || { fail "$file: $name: expect needs rule=<id>, rule=none or not=<id>"; return; }

  if [[ $want_rule == none ]]; then
    if grep -q '|yes$' <<<"$results"; then
      fail "$file: $name: expected no alert, got rule $(grep '|yes$' <<<"$results" | head -1 | cut -d'|' -f1)"
    else
      pass "$file: $name (no alert)"
    fi
    return
  fi

  local r l g d hit="" g_ok
  while IFS='|' read -r r l g d _; do
    [[ "|$want_rule|" == *"|$r|"* ]] || continue
    [[ -z $want_level || $l == "$want_level" ]] || { hit="rule $r at level $l, expected level $want_level"; continue; }
    [[ -z $want_dec || $d == "$want_dec" ]] || { hit="rule $r with decoder '$d', expected '$want_dec'"; continue; }
    g_ok=1
    for want in ${want_groups//,/ }; do [[ ",$g," == *",$want,"* ]] || g_ok=0; done
    (( g_ok )) || { hit="rule $r with groups $g, expected $want_groups"; continue; }
    pass "$file: $name (rule $r, level $l)"
    return
  done <<<"$results"
  if [[ -z $hit ]]; then
    hit="got $(cut -d'|' -f1,2 <<<"$results" | sed 's/^|$/none/; s/|/@/' | sort -u | paste -sd, -) (rule@level)"
  fi
  fail "$file: $name: expected rule $want_rule; $hit"
}

run_case() {  # file, name, expect lines, log lines
  local file=$1 name=$2 expects=$3 lines=$4 results e
  [[ -z $filter || $file == *"$filter"* || $name == *"$filter"* ]] || return 0
  [[ -n $expects ]] || { fail "$file: $name: no expect line"; return; }
  [[ -n $lines ]] || { fail "$file: $name: no log, repeat or scenario line"; return; }
  results=$(printf '%s\n' "$lines" | docker exec -i "$MANAGER" "$OSSEC/bin/wazuh-logtest" 2>&1 | parse)
  while IFS= read -r e; do check "$file" "$name" "$e" "$results"; done <<<"$expects"
}

shopt -s nullglob
files=("$TESTS_DIR"/cases/*.cases)
(( ${#files[@]} )) || { echo "ERROR no case files in $TESTS_DIR/cases/" >&2; exit 2; }
for cf in "${files[@]}"; do
  file=${cf##*/} name="" expect="" lines=""
  while IFS= read -r line || [[ -n $line ]]; do
    case $line in
      ''|'#'*) continue ;;
      case\ *)
        [[ -z $name ]] || run_case "$file" "$name" "$expect" "$lines"
        name=${line#case } expect="" lines="" ;;
      expect\ *) expect+="${expect:+$'\n'}${line#expect }" ;;
      log\ *) lines+="${lines:+$'\n'}${line#log }" ;;
      scenario\ *)
        # The lines nodes/lab/trigger.sh writes for that scenario, so cases
        # and scenarios can't drift apart.
        lines+="${lines:+$'\n'}$("$REPO_DIR/nodes/lab/trigger.sh" --scenario "${line#scenario }" --print --id runner)" ;;
      repeat\ *)
        read -r _ n rest <<<"$line"
        for (( i = 0; i < n; i++ )); do lines+="${lines:+$'\n'}$rest"; done ;;
      *) fail "$file: unknown line: $line" ;;
    esac
  done < "$cf"
  [[ -z $name ]] || run_case "$file" "$name" "$expect" "$lines"
done

echo
echo "$passes passed, $fails failed"
(( fails == 0 ))
