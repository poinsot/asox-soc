#!/usr/bin/env bash
# Load workflows from nodes/core/n8n/workflows/ into n8n (PROJECT.md 11.2),
# e.g. after pulling a teammate's changes.
#
# Usage: scripts/n8n-import.sh [FILE|DIR...]
#   Without arguments, every *.json in nodes/core/n8n/workflows/ is imported;
#   a directory argument stands for every *.json in it.
#   Workflows with the same ID are OVERWRITTEN (export your own UI changes
#   first with scripts/n8n-export.sh). Workflows whose file says
#   "active": true are activated on the running n8n, sub-workflows before the
#   workflows that call them whatever the file order; one that still can't be
#   activated gets a FAIL line with its name and n8n's reason (exit code 1).
#   Credentials are not imported: they are created by scripts/bootstrap.sh.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { print_usage "$0"; exit 0; }
[[ -f "$(node_dir core)/.env" ]] || die "nodes/core/.env not found; run scripts/soc.sh init core"

files=()
if (( $# == 0 )); then set -- "$N8N_WORKFLOW_DIR"; fi
for arg in "$@"; do
  if [[ -d $arg ]]; then
    dir_files=("$arg"/*.json)
    [[ -f ${dir_files[0]} ]] || die "no *.json files in $arg"
    files+=("${dir_files[@]}")
  else
    files+=("$arg")
  fi
done
for f in "${files[@]}"; do
  [[ -f $f ]] || die "no such file: $f"
  jq -e '.id and .name and .nodes' >/dev/null "$f" 2>&1 || die "$f is not an n8n workflow export"
done
n8n_api_ok || die "n8n API not reachable with N8N_API_KEY at $N8N_URL (is core running? run scripts/bootstrap.sh core)"
n8n_import_workflows "${files[@]}"
finish
