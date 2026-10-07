#!/usr/bin/env bash
# False-positive report for Wazuh tuning (BACKLOG.md T4.4, X-11).
# Lists the cases closed as False positive and the alerts closed as Ignored or
# False positive, grouped by the Wazuh rule that raised them (custom field
# `wazuh-rule-id`, or the `rule:<id>` tag), with counts, titles and the
# analysts' reasons (case / alert summary). The Wazuh owner uses it to tune
# noisy rules (W2.4). Test objects (tag or source "asox-test") are left out.
#
# Usage: nodes/cases/thehive/scripts/thehive-fp-report.sh [--days N] [--out FILE]
#   --days N    only objects updated in the last N days (default 30; 0 = all)
#   --out FILE  write the Markdown report to FILE instead of standard output
# Read-only: it changes nothing in TheHive. It reads as an org-admin of SOC
# through a temporary API key, revoked on exit (as thehive-export.sh does).
set -euo pipefail
# shellcheck source=nodes/cases/thehive/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DAYS=30 OUT=""
while (( $# > 0 )); do
  case $1 in
    -h|--help) print_usage "$0"; exit 0 ;;
    --days) [[ ${2:-} =~ ^[0-9]+$ ]] || die "--days needs a number"; DAYS=$2; shift ;;
    --out) [[ -n ${2:-} ]] || die "--out needs a file name"; OUT=$2; shift ;;
    *) die "unknown argument: $1 (options: --days N --out FILE)" ;;
  esac
  shift
done

th_require_ready
th_org_key

since=0
(( DAYS == 0 )) || since=$(( ($(date +%s) - DAYS * 86400) * 1000 ))

# TheHive statuses that mean "not a real incident". Cases: FalsePositive
# (TRIAGE.md, "Closing"). Alerts: Ignored (TRIAGE.md, "False positive") and
# FalsePositive, if the alert was closed with that status.
# query KIND NAME STATUS...: list KIND (listCase / listAlert) with one of the
# statuses, updated since $since, as a JSON array.
query() {
  local kind=$1 name=$2 q r; shift 2
  q=$(jq -nc --arg k "$kind" --argjson since "$since" --args '{query: [
        {_name: $k},
        {_name: "filter", _and: [
          {_in: {_field: "status", _values: $ARGS.positional}},
          {_gte: {_field: "_updatedAt", _value: $since}}
        ]},
        {_name: "sort", _fields: [{_updatedAt: "desc"}]},
        {_name: "page", from: 0, to: 1000}
      ]}' "$@")
  r=$(thehive_org POST "/api/v1/query?name=$name" "$q")
  th_expect "list $kind" "$r" 200 || return 1
  http_body "$r"
}

cases=$(query listCase fpCases FalsePositive) || die "could not read the cases"
alerts=$(query listAlert fpAlerts Ignored FalsePositive) || die "could not read the alerts"

# One row per object: {rule, level, kind, number, title, status, reason, date}.
# shellcheck disable=SC2016  # jq code
JQ_ROWS='
  def cf($n): [ (.customFields // [])[] | select(.name == $n) | .value ] | first;
  def rule: (cf("wazuh-rule-id")
             // ([ (.tags // [])[] | select(startswith("rule:")) | ltrimstr("rule:") ] | first)
             // "unknown") | tostring;
  def test: ((.tags // []) | index("asox-test")) or .source == "asox-test";
  [ .[] | select(test | not) | {
      rule: rule,
      level: (cf("wazuh-rule-level") // "?"),
      kind: $kind,
      number: (if $kind == "case" then "#\(.number)" else ._id end),
      title: (.title // "" | gsub("\\|"; "/")),
      status: .status,
      reason: ((.summary // "") | gsub("\\s+"; " ") | gsub("\\|"; "/") | .[0:160]),
      date: ((._updatedAt // ._createdAt // 0) / 1000 | strftime("%Y-%m-%d"))
  } ]'
case_rows=$(jq --arg kind case "$JQ_ROWS" <<<"$cases")
alert_rows=$(jq --arg kind alert "$JQ_ROWS" <<<"$alerts")
rows=$(jq -n --argjson c "$case_rows" --argjson a "$alert_rows" '$c + $a')

period=$([[ $DAYS == 0 ]] && echo "all time" || echo "last $DAYS days")
# shellcheck disable=SC2016  # jq code
report=$(jq -r --arg period "$period" --arg now "$(date '+%Y-%m-%d %H:%M')" '
  group_by(.rule) | sort_by(-length, .[0].rule) as $groups
  | "# False positives by Wazuh rule",
    "",
    "Generated \($now) by `thehive-fp-report.sh` (\($period)). Cases closed as *False positive*; alerts closed as *Ignored* or *False positive*; test objects left out.",
    "",
    (if ($groups | length) == 0 then "No false positives in this period." else
      "| Wazuh rule | Level | Total | Cases | Alerts | Last seen |",
      "|---|---|---|---|---|---|",
      ($groups[] | "| \(.[0].rule) | \(.[0].level) | \(length) | \(map(select(.kind == "case")) | length) | \(map(select(.kind == "alert")) | length) | \(map(.date) | max) |"),
      "",
      "Rules with 3 or more false positives should be reviewed by the Wazuh owner (TRIAGE.md).",
      ($groups[] |
        "",
        "## Rule \(.[0].rule)\(if length >= 3 then " (review)" else "" end)",
        "",
        "| Date | Object | Status | Title | Reason |",
        "|---|---|---|---|---|",
        (sort_by(.date) | reverse | .[] |
          "| \(.date) | \(.kind) \(.number) | \(.status) | \(.title) | \(if .reason == "" then "(no summary)" else .reason end) |"))
    end)' <<<"$rows")

if [[ -n $OUT ]]; then
  printf '%s\n' "$report" >"$OUT"
  pass "report written to $OUT ($(jq 'length' <<<"$rows") object(s), $(jq 'group_by(.rule) | length' <<<"$rows") rule(s))"
else
  printf '%s\n' "$report"
fi
