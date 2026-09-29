# shellcheck shell=bash
# Shared helpers for thehive-export.sh and thehive-import.sh (owner: TheHive).
# Source it; don't run it.
#
# What is exported ("kinds"), and who can read / write it in TheHive 5.7:
#   custom-fields     platform-wide   -> platform admin (admin@thehive.local)
#   observable-types  platform-wide   -> platform admin
#   case-templates    SOC organisation -> an org-admin of SOC: the Service
#                     account THEHIVE_BOOTSTRAP_USER, through a temporary API
#                     key that is revoked when the script exits (as
#                     scripts/bootstrap.sh does; docs/decisions.md D42).
# Nothing here reads or prints a password or key into a file.
# shellcheck disable=SC2034  # globals are used by the scripts that source this

TH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$TH_DIR/../../../scripts/lib/common.sh"
# shellcheck source=scripts/lib/cases.sh
source "$REPO_ROOT/scripts/lib/cases.sh"

ENTITIES_DIR=${THEHIVE_ENTITIES_DIR:-$TH_DIR/entities}
# Import order matters: case templates refer to custom fields by name.
ALL_KINDS=(custom-fields observable-types case-templates)
KINDS=()

# Fill KINDS from the arguments (default: all), always in ALL_KINDS order.
th_parse_kinds() {
  local k want=" $* "
  for k in "$@"; do
    [[ " ${ALL_KINDS[*]} " == *" $k "* ]] || die "unknown kind: $k (kinds: ${ALL_KINDS[*]})"
  done
  KINDS=()
  for k in "${ALL_KINDS[@]}"; do
    if (( $# == 0 )) || [[ $want == *" $k "* ]]; then KINDS+=("$k"); fi
  done
}

# Stop early with a clear message if cases isn't configured or running.
th_require_ready() {
  local r
  [[ -f "$(node_dir cases)/.env" ]] || die "nodes/cases/.env not found; run scripts/soc.sh init cases"
  r=$(thehive_admin GET /api/v1/user/current)
  [[ $(http_code "$r") == 200 ]] \
    || die "TheHive doesn't accept the admin login at $THEHIVE_API (HTTP $(http_code "$r")); is cases up? (scripts/soc.sh up cases)"
}

# ---- Organisation access (case templates) ----

ORG_KEY="" ORG_LOGIN=""

th_needs_org() { [[ " ${KINDS[*]} " == *" case-templates "* ]]; }

# Create a temporary API key for the bootstrap Service account; it is revoked
# on exit, whatever happens.
th_org_key() {
  local r
  ORG_LOGIN=$(cases_env THEHIVE_BOOTSTRAP_USER)
  [[ -n $ORG_LOGIN ]] || die "THEHIVE_BOOTSTRAP_USER is missing from nodes/cases/.env"
  r=$(thehive_admin POST "/api/v1/user/$ORG_LOGIN/key/renew")
  [[ $(http_code "$r") == 200 ]] \
    || die "could not create a temporary API key for $ORG_LOGIN (HTTP $(http_code "$r")); run scripts/bootstrap.sh cases"
  ORG_KEY=$(http_body "$r")
  trap th_revoke_key EXIT
}

th_revoke_key() {
  if [[ -n $ORG_KEY ]]; then
    thehive_admin DELETE "/api/v1/user/$ORG_LOGIN/key" >/dev/null || true
    ORG_KEY=""
  fi
  return 0
}

# thehive_org METHOD PATH [JSON]: as an org-admin of SOC.
thehive_org() { thehive_key "$ORG_KEY" "$@"; }

# ---- Reading and normalising ----

# Print TheHive's current objects of <kind> as a raw JSON array; on error,
# print "HTTP <code> ..." on stderr and return 1.
th_list() {
  local r
  case $1 in
    custom-fields)    r=$(thehive_admin GET /api/v1/customField) ;;
    observable-types) r=$(thehive_admin POST '/api/v1/query?name=observableTypes' '{"query":[{"_name":"listObservableType"}]}') ;;
    case-templates)   r=$(thehive_org POST '/api/v1/query?name=caseTemplates' '{"query":[{"_name":"listCaseTemplate"}]}') ;;
  esac
  if [[ $(http_code "$r") != 200 ]]; then
    printf 'HTTP %s %s\n' "$(http_code "$r")" "$(http_body "$r" | head -c 200)" >&2
    return 1
  fi
  http_body "$r"
}

# jq filters that turn TheHive's output (or a hand-edited file) into the
# stored form: no IDs, dates or authors; empty values dropped; lists sorted,
# so the same configuration always gives the same file.
# shellcheck disable=SC2016  # jq code, not shell
JQ_CLEAN='def clean: with_entries(select(.value != null and .value != "" and .value != []));'

# shellcheck disable=SC2016
JQ_NORMALIZE_CUSTOM_FIELDS="$JQ_CLEAN"'
  [ .[] | {name, displayName, group, description, type,
           mandatory: (.mandatory // false), options} | clean ]
  | sort_by(.name)'

JQ_NORMALIZE_OBSERVABLE_TYPES='
  [ .[] | {name, isAttachment: (.isAttachment // false)} ] | sort_by(.name)'

# Case template custom fields come as a list of {name, value, order} (or, in
# hand-written files, as an object {name: value}).
# shellcheck disable=SC2016
JQ_NORMALIZE_CASE_TEMPLATES="$JQ_CLEAN"'
  def fields:
    if type == "object" then [ to_entries[] | {name: .key, value: .value} ]
    else [ .[] | {name, value, order} ] end;
  [ .[] | {
      name, displayName, titlePrefix, description, severity, tlp, pap,
      flag: (.flag // false), summary,
      tags: ((.tags // []) | sort),
      tasks: ([ (.tasks // [])[]
                | {title, group, description, order, mandatory: (.mandatory // false)}
                | clean ] | sort_by(.order // 0, .title)),
      customFields: ((.customFields // []) | fields | map(clean)
                     | sort_by(.order // 0, .name))
    } | clean ]
  | sort_by(.name)'

# th_normalize KIND < raw-json-array
th_normalize() {
  case $1 in
    custom-fields)    jq "$JQ_NORMALIZE_CUSTOM_FIELDS" ;;
    observable-types) jq "$JQ_NORMALIZE_OBSERVABLE_TYPES" ;;
    case-templates)   jq "$JQ_NORMALIZE_CASE_TEMPLATES" ;;
  esac
}

# th_expect LABEL RESPONSE CODE...: true if the HTTP status is one of CODEs,
# otherwise a FAIL line with the start of the body.
th_expect() {
  local what=$1 r=$2 code c; shift 2
  code=$(http_code "$r")
  for c in "$@"; do [[ $code == "$c" ]] && return 0; done
  fail "$what: HTTP $code $(http_body "$r" | head -c 200)"
  return 1
}
