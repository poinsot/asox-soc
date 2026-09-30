#!/usr/bin/env bash
# Replay payload fixtures to n8n's webhooks, as Wazuh (C1) and TheHive (C4)
# would send them (owner: n8n, N8N-0.6). The target is chosen from the
# payload: a Wazuh alert (has .rule) goes to /webhook/wazuh-alert with
# X-ASOX-Token, a TheHive event (has .objectType) to /webhook/thehive-event
# with Authorization: Bearer. The token is read from nodes/core/.env and never
# printed.
#
# Usage: nodes/core/n8n/fixtures/replay.sh [options]
#   -f, --file FILE    replay this fixture (repeatable)
#   -a, --all          replay every fixture under fixtures/wazuh and fixtures/thehive
#   -o, --only KIND    with --all: only wazuh or only thehive fixtures
#   -t, --times N      POST each fixture N times (idempotency test, N8N-3.3; default 1)
#   -n, --no-token     send without the token: every POST must get HTTP 403 (N8N-1.6)
#   -h, --help         show this help
# One PASS/FAIL line per POST with the HTTP code (expected: 200, or 403 with
# --no-token). Exit code 1 if any POST failed, 2 on usage errors.
# n8n is reached on its published port (N8N_URL, default http://127.0.0.1:5678,
# from scripts/lib/n8n.sh): N8N_WEBHOOK_URL in nodes/core/.env is the address
# inside the Docker network, which the host can't resolve in single-host mode.
# Once playbooks are attached, a replay runs them for real: replay TheHive
# events only against test objects.
set -euo pipefail

FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$FIXTURES_DIR/../../../../scripts/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$REPO_ROOT/scripts/lib/n8n.sh"

usage() { print_usage "$0"; }
usage_error() { printf 'ERROR %s\n' "$*" >&2; usage >&2; exit 2; }

files=() ALL=0 ONLY="" TIMES=1 NO_TOKEN=0
while (( $# > 0 )); do
  case $1 in
    -f|--file)     files+=("${2:?--file needs a path}"); shift ;;
    -a|--all)      ALL=1 ;;
    -o|--only)     ONLY=${2:?--only needs wazuh or thehive}; shift ;;
    -t|--times)    TIMES=${2:?--times needs a number}; shift ;;
    -n|--no-token) NO_TOKEN=1 ;;
    -h|--help)     usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[[ $TIMES =~ ^[1-9][0-9]*$ ]] || usage_error "--times must be a positive number"
[[ -z $ONLY || $ONLY == wazuh || $ONLY == thehive ]] || usage_error "--only must be wazuh or thehive"
[[ -z $ONLY || $ALL == 1 ]] || usage_error "--only goes with --all"
if (( ALL )); then
  for kind in wazuh thehive; do
    [[ -z $ONLY || $ONLY == "$kind" ]] || continue
    for f in "$FIXTURES_DIR/$kind"/*.json; do [[ -e $f ]] && files+=("$f"); done
  done
fi
(( ${#files[@]} > 0 )) || usage_error "give --file FILE or --all"

TOKEN=""
if (( ! NO_TOKEN )); then
  TOKEN=$(n8n_env N8N_WEBHOOK_TOKEN)
  [[ -n $TOKEN ]] || die "N8N_WEBHOOK_TOKEN not found in nodes/core/.env; run scripts/soc.sh init core"
fi

# post FILE PATH HEADER-NAME HEADER-PREFIX: prints the HTTP status. The auth
# header is passed to curl through a file descriptor, so the token never
# appears in the process list.
post() {
  local file=$1 path=$2 name=$3 prefix=$4
  local -a args=(-s -o /dev/null -w '%{http_code}' -X POST "$N8N_URL/webhook/$path"
                 -H 'Content-Type: application/json' --data-binary "@$file")
  if (( NO_TOKEN )); then
    curl "${args[@]}" || printf '000'
  else
    curl "${args[@]}" -H @<(printf '%s: %s%s\n' "$name" "$prefix" "$TOKEN") || printf '000'
  fi
}

expected=200 note=""
(( NO_TOKEN )) && expected=403 note=", no token"
for file in "${files[@]}"; do
  label=$(realpath --relative-to="$FIXTURES_DIR" "$file")
  if ! kind=$(jq -er 'if (.rule | type) == "object" then "wazuh"
                       elif (.objectType | type) == "string" then "thehive"
                       else error("unknown") end' "$file" 2>/dev/null); then
    fail "$label: not a Wazuh alert or TheHive event (or not JSON)"
    continue
  fi
  if [[ $kind == wazuh ]]; then
    path=wazuh-alert name=X-ASOX-Token prefix="" ref="alert $(jq -r '.id' "$file")"
  else
    path=thehive-event name=Authorization prefix="Bearer " ref="$(jq -r '"\(.action) \(.objectType) \(.objectId)"' "$file")"
  fi
  for (( i = 1; i <= TIMES; i++ )); do
    code=$(post "$file" "$path" "$name" "$prefix")
    msg="$label -> /webhook/$path ($ref, $i/$TIMES$note): HTTP $code"
    if [[ $code == "$expected" ]]; then pass "$msg"; else fail "$msg (expected $expected)"; fi
  done
done
finish
