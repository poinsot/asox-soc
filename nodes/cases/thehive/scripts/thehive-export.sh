#!/usr/bin/env bash
# Save TheHive's UI configuration into the repo (PROJECT.md 11.2): custom
# fields, observable types and the SOC organisation's case templates, one
# JSON file per kind in nodes/cases/thehive/entities/.
# IDs, dates and authors are left out and every list is sorted by name, so
# the files are the same on every machine and git diff shows only real
# changes. Load them into a TheHive with thehive-import.sh.
#
# Usage: nodes/cases/thehive/scripts/thehive-export.sh [KIND...]
#   KIND  custom-fields, observable-types, case-templates (default: all)
# Run it on the machine hosting cases, while cases is up. Then review with
# git diff and commit.
set -euo pipefail
# shellcheck source=nodes/cases/thehive/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { print_usage "$0"; exit 0; }

th_parse_kinds "$@"
th_require_ready
if th_needs_org; then th_org_key; fi
mkdir -p "$ENTITIES_DIR"

for kind in "${KINDS[@]}"; do
  file="$ENTITIES_DIR/$kind.json"
  if ! raw=$(th_list "$kind"); then
    fail "$kind: TheHive didn't return the list (see the error above)"
    continue
  fi
  if ! out=$(th_normalize "$kind" <<<"$raw"); then
    fail "$kind: unexpected answer from TheHive: ${raw:0:200}"
    continue
  fi
  printf '%s\n' "$out" > "$file.tmp" && mv "$file.tmp" "$file"
  pass "$kind: $(jq length <<<"$out") exported -> ${file#"$REPO_ROOT"/}"
done

finish
