#!/usr/bin/env bash
# Cortex analyzers as code (owner: Cortex + MISP). Run it on the machine that
# hosts the cases node, once scripts/soc.sh init has bootstrapped it.
#
# Usage: nodes/cases/cortex/analyzers/analyzers.sh <apply|export|test>
#   apply : enable (or update) every analyzer of analyzers.json in Cortex's
#           SOC organisation, as its org admin, with the API keys from
#           analyzer-keys.env; disable the ones marked "enabled": false;
#           pre-pull their images. An analyzer whose key is blank is
#           skipped. Idempotent.
#   export: write the analyzers enabled in Cortex back into analyzers.json,
#           after changing them in the UI. Keys stay ${VAR} placeholders.
#   test  : run each enabled analyzer of analyzers.json on its test
#           observable as the n8n API user (the account of C6), forcing a
#           new job, and print its verdict.
# The MISP analyzer (C7) is managed by scripts/bootstrap.sh cases, not here.
# One PASS/FAIL line per check; exit code 1 on failure.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../../scripts/lib/common.sh"
# shellcheck source=scripts/lib/cases.sh
source "$REPO_ROOT/scripts/lib/cases.sh"

HERE="$REPO_ROOT/nodes/cases/cortex/analyzers"
ANALYZERS_FILE="$HERE/analyzers.json"
KEYS_FILE=${ANALYZER_KEYS_FILE:-$HERE/analyzer-keys.env}
TEST_TIMEOUT=${TEST_TIMEOUT:-180}
# A configuration value that is only "${VAR}" is read from KEYS_FILE.
PLACEHOLDER='^\$\{[A-Z0-9_]+\}$'
# Analyzers left to bootstrap.sh (C7).
RESERVED='^MISP_[0-9]+_[0-9]+$'

usage() { print_usage "$0"; }

# Cortex's analyzer catalog and the analyzers enabled in the SOC organisation.
load_cortex_state() {
  local r
  r=$(cortex_orgadmin GET '/api/analyzerdefinition?range=all')
  [[ $(http_code "$r") == 200 ]] || die "Cortex at $CORTEX_API: catalog request failed (HTTP $(http_code "$r")); is the cases node running and bootstrapped?"
  DEFS=$(http_body "$r")
  (( $(jq length <<<"$DEFS") > 0 )) || die "Cortex's analyzer catalog is empty: it needs internet access to catalogs.download.strangebee.com"
  r=$(cortex_orgadmin GET '/api/analyzer?range=all')
  [[ $(http_code "$r") == 200 ]] || die "Cortex: listing enabled analyzers failed (HTTP $(http_code "$r"))"
  ENABLED=$(http_body "$r")
}

# Highest catalog version of the analyzer matching <regex> (empty if none).
latest_def() {
  jq -r --arg re "$1" '[.[] | select(.id | test($re))]
    | sort_by(.id | [scan("[0-9]+") | tonumber]) | last | .id // empty' <<<"$DEFS"
}

# ID in Cortex of the enabled analyzer matching <regex> (empty if none).
enabled_id() {
  jq -r --arg re "$1" '[.[] | select(.workerDefinitionId | test($re)) | .id] | first // empty' <<<"$ENABLED"
}

# resolve_config CONFIG_JSON: prints it with each "${VAR}" replaced by VAR's
# value from KEYS_FILE. Returns 1 (printing the blank names) if any is blank.
resolve_config() {
  local cfg=$1 vals='{}' v val
  local -a missing=()
  while IFS= read -r v; do
    [[ -n $v ]] || continue
    val=$(env_get "$KEYS_FILE" "$v")
    [[ -n $val ]] || missing+=("$v")
    vals=$(jq -c --arg k "$v" --arg v "$val" '. + {($k): $v}' <<<"$vals")
  done < <(jq -r --arg p "$PLACEHOLDER" '[.. | strings | select(test($p)) | .[2:-1]] | unique[]' <<<"$cfg")
  if (( ${#missing[@]} > 0 )); then
    printf '%s' "${missing[*]}"
    return 1
  fi
  jq -c --argjson vals "$vals" --arg p "$PLACEHOLDER" \
    'walk(if type == "string" and test($p) then $vals[.[2:-1]] else . end)' <<<"$cfg"
}

apply_one() {
  local entry=$1 re def id cfg missing body r image unknown verb
  re=$(jq -r '.match' <<<"$entry")
  def=$(latest_def "$re")
  id=$(enabled_id "$re")
  if [[ $(jq -r '.enabled' <<<"$entry") != true ]]; then
    if [[ -z $id ]]; then pass "$re: disabled (not enabled in Cortex)"; return; fi
    r=$(cortex_orgadmin DELETE "/api/analyzer/$id")
    if [[ $(http_code "$r") =~ ^20 ]]; then pass "$re: disabled in Cortex"
    else fail "$re: disabling failed (HTTP $(http_code "$r"))"; fi
    return
  fi
  [[ -n $def ]] || { fail "$re: no analyzer in Cortex's catalog matches"; return; }
  if ! cfg=$(resolve_config "$(jq -c '.configuration' <<<"$entry")"); then
    missing=$cfg
    skip "$def: $missing blank in $(basename "$KEYS_FILE")${id:+ (left as it is in Cortex)}"
    return
  fi
  # Catch typos in configuration names against the catalog.
  unknown=$(jq -r --arg d "$def" --argjson c "$cfg" \
    '(.[] | select(.id == $d) | [.configurationItems[]?.name]) as $ok
     | [$c | keys[] | select(. as $k | $ok | index($k) | not)] | join(", ")' <<<"$DEFS")
  [[ -z $unknown ]] || warn "$def: configuration not in the catalog definition: $unknown"
  body=$(jq -nc --arg n "$def" --argjson d "$(jq -c '.defaults' "$ANALYZERS_FILE")" --argjson e "$entry" --argjson c "$cfg" '
    {name: $n, configuration: ($d.configuration + $c),
     jobCache: ($e.jobCache // $d.jobCache), jobTimeout: ($e.jobTimeout // $d.jobTimeout)}
    + (if $e.rate then {rate: $e.rate, rateUnit: $e.rateUnit} else {} end)')
  if [[ -z $id ]]; then
    r=$(cortex_orgadmin POST "/api/organization/analyzer/$def" "$body")
    [[ $(http_code "$r") == 201 ]] || { fail "$def: enabling failed (HTTP $(http_code "$r")) $(http_body "$r" | head -c 200)"; return; }
  else
    r=$(cortex_orgadmin PATCH "/api/analyzer/$id" "$(jq -c 'del(.name)' <<<"$body")")
    [[ $(http_code "$r") == 200 ]] || { fail "$def: updating failed (HTTP $(http_code "$r")) $(http_body "$r" | head -c 200)"; return; }
  fi
  # Pre-pull the image, so the first job doesn't wait for the download.
  verb=enabled
  [[ -z $id ]] || verb=updated
  image=$(jq -r --arg d "$def" '.[] | select(.id == $d) | .dockerImage // empty' <<<"$DEFS")
  if [[ -n $image ]] && docker pull -q "$image" >/dev/null 2>&1; then
    pass "$def: $verb (image $image)"
  else
    fail "$def: $verb, but its image (${image:-unknown}) could not be pulled"
  fi
}

cmd_apply() {
  local entry
  [[ -f $KEYS_FILE ]] || warn "$(basename "$KEYS_FILE") not found: analyzers that need an API key are skipped (copy analyzer-keys.env.example)"
  load_cortex_state
  while IFS= read -r entry; do
    apply_one "$entry"
  done < <(jq -c '.analyzers[]' "$ANALYZERS_FILE")
}

cmd_export() {
  local cur new tmp
  load_cortex_state
  # One object per enabled analyzer, configuration parsed if Cortex sends it
  # as a string.
  cur=$(jq -c --arg r "$RESERVED" '[.[] | select(.workerDefinitionId | test($r) | not)
    | {def: .workerDefinitionId, rate, rateUnit, jobCache, jobTimeout,
       cfg: (.configuration | if type == "string" then fromjson else . end // {})}]' <<<"$ENABLED")
  new=$(jq --argjson cur "$cur" '
    def isph: type == "string" and test("^\\$\\{[A-Z0-9_]+\\}$");
    def family: sub("_[0-9]+_[0-9]+$"; "");
    .defaults as $d
    | reduce $cur[] as $a (.;
        ([.analyzers | to_entries[] | select(.value.match as $m | $a.def | test($m)) | .key] | first) as $i
        | (if $i == null
           then {match: ("^" + ($a.def | family) + "_[0-9]+_[0-9]+$"), enabled: true, configuration: {}}
           else .analyzers[$i] end) as $old
        # Values equal to the shared defaults are not repeated per analyzer.
        | ($a.cfg | with_entries(select(.value != null
            and (.key as $k | ($d.configuration | has($k)) and $d.configuration[$k] == .value | not)))) as $c
        | (($old.configuration | keys_unsorted) + (($c | keys_unsorted) - ($old.configuration | keys_unsorted))) as $ks
        | (reduce $ks[] as $k ({};
            if ($old.configuration[$k] | isph) then . + {($k): $old.configuration[$k]}
            elif ($c | has($k)) then
              if ($k | test("key|token|password|secret"; "i")) and ($c[$k] | type == "string")
              then . + {($k): ("${" + ($a.def | family | ascii_upcase) + "_" + ($k | ascii_upcase) + "}")}
              else . + {($k): $c[$k]} end
            else . end)) as $conf
        | ({match: $old.match, enabled: true, configuration: $conf}
           + (if $a.rate then {rate: $a.rate, rateUnit: $a.rateUnit} else {} end)
           + (if ($a.jobCache // $d.jobCache) != $d.jobCache then {jobCache: $a.jobCache} else {} end)
           + (if ($a.jobTimeout // $d.jobTimeout) != $d.jobTimeout then {jobTimeout: $a.jobTimeout} else {} end)
           + (if $old.test then {test: $old.test} else {} end)) as $e
        | if $i == null then .analyzers += [$e] else .analyzers[$i] = $e end)' "$ANALYZERS_FILE")
  tmp=$(mktemp "$HERE/.analyzers.XXXXXX")
  printf '%s\n' "$new" >"$tmp"
  mv "$tmp" "$ANALYZERS_FILE"
  pass "exported $(jq length <<<"$cur") enabled analyzer(s) (MISP_2_1 excluded) to nodes/cases/cortex/analyzers/analyzers.json"
  # Entries the file wants enabled that Cortex doesn't have (e.g. no key yet).
  jq -r --argjson cur "$cur" '.analyzers[] | select(.enabled) | .match as $m
    | select([$cur[].def | test($m)] | any | not) | $m' "$ANALYZERS_FILE" \
    | while IFS= read -r m; do warn "$m: enabled in analyzers.json but not in Cortex (missing key? run apply)"; done
  jq -r '[.analyzers[] | select(.test | not) | .match] | .[]' "$ANALYZERS_FILE" \
    | while IFS= read -r m; do warn "$m: no test observable: add \"test\": {\"dataType\": ..., \"data\": ...} for the test command"; done
  jq -r --arg p "$PLACEHOLDER" '[.analyzers[].configuration[] | strings | select(test($p)) | .[2:-1]] | unique[]' "$ANALYZERS_FILE" \
    | while IFS= read -r v; do
        grep -q "^$v=" "$HERE/analyzer-keys.env.example" \
          || warn "$v: new key placeholder: add it to analyzer-keys.env.example (blank) and to your analyzer-keys.env"
      done
  info "review with: git diff nodes/cases/cortex/analyzers/analyzers.json"
}

cmd_test() {
  local key entry re id dt data r jid status
  key=$(cases_env CORTEX_N8N_API_KEY)
  [[ -n $key ]] || die "CORTEX_N8N_API_KEY is empty in nodes/cases/.env (run scripts/bootstrap.sh cases)"
  r=$(cortex_key "$key" GET '/api/analyzer?range=all')
  [[ $(http_code "$r") == 200 ]] || die "Cortex refused the n8n API key (HTTP $(http_code "$r"))"
  ENABLED=$(http_body "$r")
  while IFS= read -r entry; do
    re=$(jq -r '.match' <<<"$entry")
    [[ $(jq -r '.test // empty' <<<"$entry") ]] || { skip "$re: no test observable"; continue; }
    id=$(enabled_id "$re")
    [[ -n $id ]] || { skip "$re: not enabled in Cortex (missing key? run apply)"; continue; }
    dt=$(jq -r '.test.dataType' <<<"$entry")
    data=$(jq -r '.test.data' <<<"$entry")
    r=$(cortex_key "$key" POST "/api/analyzer/$id/run" \
      "$(jq -nc --arg d "$data" --arg t "$dt" '{data: $d, dataType: $t, tlp: 2, pap: 2, force: true}')")
    jid=$(http_body "$r" | jq -r '.id // empty')
    [[ -n $jid ]] || { fail "$re: Cortex refused the job on $data (HTTP $(http_code "$r"))"; continue; }
    r=$(cortex_key "$key" GET "/api/job/$jid/waitreport?atMost=${TEST_TIMEOUT}seconds")
    status=$(http_body "$r" | jq -r '.status // "unknown"')
    if [[ $status == Success ]]; then
      pass "$(jq -r '.analyzerName // .analyzerDefinitionId // empty' <<<"$(http_body "$r")") on $dt $data: $(http_body "$r" \
        | jq -r '[.report.summary.taxonomies[]? | "\(.namespace):\(.predicate)=\(.value) [\(.level)]"] | join(", ") | if . == "" then "no taxonomies" else . end')"
    else
      # The error's last line is the analyzer's own message.
      fail "$re on $dt $data: job $jid $status: $(http_body "$r" \
        | jq -r '.errorMessage // "" | split("\n") | map(select(length > 0)) | last // ""' | cut -c1-200)"
    fi
  done < <(jq -c '.analyzers[] | select(.enabled)' "$ANALYZERS_FILE")
}

case ${1:-} in
  apply|export|test) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
[[ -f "$(node_dir cases)/.env" ]] || die "nodes/cases/.env not found: run scripts/soc.sh init cases (or cases-intel) first"
jq empty "$ANALYZERS_FILE" || die "nodes/cases/cortex/analyzers/analyzers.json is not valid JSON"
"cmd_$1"
finish
