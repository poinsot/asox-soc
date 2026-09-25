#!/usr/bin/env bash
# Produce a test alert (owner: Wazuh): writes a line with the marker
# ASOX_TEST_EVENT to the lab agent's monitored test log. The manager's test
# rule 100100 (level 10) turns it into an alert, which is indexed and, above
# WAZUH_ALERT_MIN_LEVEL, forwarded to n8n (C1).
#
# Usage: nodes/lab/trigger.sh [--id ID]
#   --id ID   event ID to embed (default: a new unique one)
# Prints the event ID on stdout, so scripts can capture it, e.g.
#   id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_LOG=/var/log/asox-lab/test.log

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; }

id=""
while (( $# > 0 )); do
  case $1 in
    --id) id=${2:?--id needs a value}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
[[ -n $id ]] || id="trig-$(date +%s)-$RANDOM"
[[ $id =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "ERROR --id may only contain letters, digits and . _ : -" >&2; exit 2; }

[[ -f $DIR/.env ]] || { echo "ERROR nodes/lab/.env not found; run scripts/soc.sh init core" >&2; exit 1; }

line="$(date '+%b %e %H:%M:%S') $(sed -n 's/^LAB_AGENT_NAME=//p' "$DIR/.env") asox-test: ASOX_TEST_EVENT id=$id"
if ! printf '%s\n' "$line" | docker compose --project-directory "$DIR" --env-file "$DIR/.env" \
    -f "$DIR/docker-compose.yml" exec -T lab-agent sh -c "cat >> $TEST_LOG"; then
  echo "ERROR could not write to the lab agent (is the lab node running? scripts/soc.sh up core)" >&2
  exit 1
fi
echo "Test event sent: ASOX_TEST_EVENT id=$id" >&2
printf '%s\n' "$id"
