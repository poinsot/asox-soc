#!/usr/bin/env bash
# Run the Jev offline core's unit tests (node:test) in a pinned Node image.
# The image has the same Node version as the n8n image (n8nio/n8n:2.40.7
# ships Node 26.7.0), so the code is tested on the runtime that will run it
# in n8n Code nodes. Nothing else is needed: no stack, no network, no API key.
# The folder is mounted read-only and the container has no network.
#
# Usage: nodes/core/n8n/jev/run-tests.sh [-h|--help] [test file...]
#   test file   path relative to this folder (default: every tests/*.test.js)
# One PASS/FAIL line; exit code 1 if a test failed, 2 on usage errors.
set -euo pipefail

JEV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$JEV_DIR/../../../../scripts/lib/common.sh"

NODE_IMAGE=node:26.7.0-alpine

usage() { print_usage "$0"; }

files=()
while (( $# > 0 )); do
  case $1 in
    -h|--help) usage; exit 0 ;;
    -*) printf 'ERROR unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    *) files+=("$1"); shift ;;
  esac
done
(( ${#files[@]} > 0 )) || files=('tests/*.test.js')

if docker run --rm --network none -v "$JEV_DIR:/jev:ro" -w /jev "$NODE_IMAGE" \
    node --test "${files[@]}"; then
  pass "jev unit tests ($NODE_IMAGE)"
else
  fail "jev unit tests ($NODE_IMAGE)"
fi
finish
