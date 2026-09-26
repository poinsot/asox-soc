#!/usr/bin/env bash
# Load workflows from nodes/core/n8n/workflows/ into n8n (PROJECT.md 11.2),
# e.g. after pulling a teammate's changes.
#
# Usage: scripts/n8n-import.sh [FILE...]
#   Without files, every *.json in nodes/core/n8n/workflows/ is imported.
#   Workflows with the same ID are OVERWRITTEN (export your own UI changes
#   first with scripts/n8n-export.sh). Workflows whose file says
#   "active": true are activated on the running n8n.
#   Credentials are not imported: they are created by scripts/bootstrap.sh.
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=scripts/lib/n8n.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/n8n.sh"

[[ ${1:-} == -h || ${1:-} == --help ]] && { print_usage "$0"; exit 0; }
[[ -f "$(node_dir core)/.env" ]] || die "nodes/core/.env not found; run scripts/soc.sh init core"

if (( $# > 0 )); then files=("$@"); else files=("$N8N_WORKFLOW_DIR"/*.json); fi
for f in "${files[@]}"; do
  [[ -f $f ]] || die "no such file: $f"
  jq -e '.id and .name and .nodes' >/dev/null "$f" 2>&1 || die "$f is not an n8n workflow export"
done
n8n_api_ok || die "n8n API not reachable with N8N_API_KEY at $N8N_URL (is core running? run scripts/bootstrap.sh core)"
n8n_import_workflows "${files[@]}"
finish
