#!/usr/bin/env bash
# Tests of scripts/lint-workflows.sh for its listed exceptions (owner: n8n,
# N8N-0.7). Static: copies a workflow into a temporary directory, changes it
# and lints the copy; no containers, no n8n.
#
# Usage: nodes/core/n8n/scripts/lint-workflows-test.sh [-h|--help]
# Checks:
#   - an ID on the 16-character exception list (asoxLibThTagObs) passes
#     silently
#   - another 15-character ID still gets the rule a WARN, and a WARN alone
#     doesn't fail the lint (exit 0)
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$TEST_DIR/../../../../scripts/lib/common.sh"

case ${1:-} in
  -h|--help) print_usage "$0"; exit 0 ;;
  "") ;;
  *) printf 'ERROR unknown option: %s\n' "$1" >&2; print_usage "$0" >&2; exit 2 ;;
esac

LINT="$TEST_DIR/lint-workflows.sh"
WORKFLOW_DIR="$REPO_ROOT/nodes/core/n8n/workflows"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The listed exception: no a/id finding, the file passes.
out=$("$LINT" --file "$WORKFLOW_DIR/lib-thehive-tag-observable.json") || true
if grep -q '^PASS  lint .*lib-thehive-tag-observable.json$' <<<"$out" && ! grep -q '\[a/id\]' <<<"$out"; then
  pass "lint-test: listed ID asoxLibThTagObs passes silently"
else
  fail "lint-test: listed ID asoxLibThTagObs is flagged: $(grep -m1 -v '^PASS' <<<"$out")"
fi

# Negative test: a 15-character ID that isn't listed still WARNs.
python3 - "$WORKFLOW_DIR/lib-config.json" "$tmp/lib-config.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
data["id"] = "asoxLibConfig01"  # 15 characters, not on the exception list
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
PY
rc=0
out=$("$LINT" --file "$tmp/lib-config.json") || rc=$?
if grep -q '^WARN  lint .*lib-config.json \[a/id\]: ID "asoxLibConfig01"' <<<"$out" && (( rc == 0 )); then
  pass "lint-test: unlisted 15-character ID asoxLibConfig01 still WARNs (exit 0)"
else
  fail "lint-test: unlisted 15-character ID asoxLibConfig01: exit $rc, no a/id WARN"
fi

finish
