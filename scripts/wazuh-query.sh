#!/usr/bin/env bash
# Query Wazuh alerts in the indexer from the command line (the Wazuh
# dashboard is not deployed). The indexer is internal to core, so the query
# runs inside the wazuh-indexer container, as the read-only grafana-ro user.
#
# Usage: scripts/wazuh-query.sh [options]
#   -n, --size N         number of alerts to show (default 10, newest first)
#   -s, --since DUR      time window: <number><s|m|h|d> (default 24h)
#   -r, --rule ID        only this rule ID
#   -l, --min-level N    only alerts with rule.level >= N
#   -a, --agent NAME     only this agent name
#   -m, --match TEXT     full-text match on the original log (full_log)
#   -i, --id ID          only the alert with this ID
#   -j, --json           print the raw alert documents as JSON
# Exit code: 0 if alerts were found, 1 if none matched, 2 on error.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }
err() { printf 'ERROR %s\n' "$*" >&2; exit 2; }

SIZE=10 SINCE=24h RULE="" MIN_LEVEL="" AGENT="" MATCH="" ALERT_ID="" JSON=0
while (( $# > 0 )); do
  case $1 in
    -n|--size)      SIZE=${2:?}; shift ;;
    -s|--since)     SINCE=${2:?}; shift ;;
    -r|--rule)      RULE=${2:?}; shift ;;
    -l|--min-level) MIN_LEVEL=${2:?}; shift ;;
    -a|--agent)     AGENT=${2:?}; shift ;;
    -m|--match)     MATCH=${2:?}; shift ;;
    -i|--id)        ALERT_ID=${2:?}; shift ;;
    -j|--json)      JSON=1 ;;
    -h|--help)      usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
[[ $SIZE =~ ^[0-9]+$ ]] || err "--size must be a number"
[[ $SINCE =~ ^[0-9]+[smhd]$ ]] || err "--since must look like 15m, 2h or 7d"
[[ -z $MIN_LEVEL || $MIN_LEVEL =~ ^[0-9]+$ ]] || err "--min-level must be a number"

ENV_FILE="$(node_dir core)/.env"
[[ -f $ENV_FILE ]] || err "nodes/core/.env not found; run scripts/soc.sh init core"
USER_NAME=$(env_get "$ENV_FILE" GRAFANA_INDEXER_USER)
USER_PW=$(env_get "$ENV_FILE" GRAFANA_INDEXER_PASSWORD)
URL=$(env_get "$ENV_FILE" WAZUH_INDEXER_URL)

query=$(jq -nc \
  --argjson size "$SIZE" --arg since "now-$SINCE" --arg rule "$RULE" \
  --arg level "$MIN_LEVEL" --arg agent "$AGENT" --arg match "$MATCH" --arg id "$ALERT_ID" '
  {
    size: $size,
    sort: [{timestamp: {order: "desc"}}],
    query: {bool: {filter: (
      [{range: {timestamp: {gte: $since}}}]
      + (if $rule  != "" then [{term: {"rule.id": $rule}}] else [] end)
      + (if $level != "" then [{range: {"rule.level": {gte: ($level | tonumber)}}}] else [] end)
      + (if $agent != "" then [{term: {"agent.name": $agent}}] else [] end)
      + (if $id    != "" then [{term: {"id": $id}}] else [] end)
      + (if $match != "" then [{match_phrase: {full_log: $match}}] else [] end)
    )}}
  }')

if ! resp=$(printf '%s' "$query" | compose core exec -T wazuh-indexer curl -s \
    --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -u "$USER_NAME:$USER_PW" -H 'Content-Type: application/json' \
    "$URL/wazuh-alerts-*/_search" --data-binary @- 2>&1); then
  err "query failed (is the core node running?): $resp"
fi
jq -e '.hits' >/dev/null 2>&1 <<<"$resp" || err "indexer error: $(jq -c '.error // .' <<<"$resp" 2>/dev/null || printf '%s' "$resp")"

total=$(jq -r '.hits.hits | length' <<<"$resp")
if (( total == 0 )); then
  echo "No alerts found (window: last $SINCE)." >&2
  exit 1
fi

if (( JSON )); then
  jq '[.hits.hits[]._source]' <<<"$resp"
else
  jq -r '.hits.hits[]._source
    | [.timestamp, "lvl \(.rule.level)", "rule \(.rule.id)", "agent \(.agent.name)", "id \(.id)", .rule.description]
    | @tsv' <<<"$resp" | if command -v column >/dev/null; then column -t -s $'\t'; else cat; fi
fi
