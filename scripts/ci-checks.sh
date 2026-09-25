#!/usr/bin/env bash
# Lightweight repo checks (PROJECT.md 11.5), identical locally and in GitHub
# Actions. Tools run from pinned Docker images, so only Docker and git are
# needed. Checks run on a snapshot of the files git would commit (tracked +
# untracked, minus .gitignore), so local secrets and generated files are
# never scanned or used.
#
# Usage: scripts/ci-checks.sh [compose|shellcheck|json|xml|secrets|all]...
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

SHELLCHECK_IMAGE=koalaman/shellcheck:v0.11.0
GITLEAKS_IMAGE=zricethezav/gitleaks:v8.30.1
PYTHON_IMAGE=python:3.14.7-slim

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; }

SNAP=""
cleanup() { [[ -n $SNAP && -d $SNAP ]] && rm -rf "$SNAP"; return 0; }
trap cleanup EXIT

snapshot() {
  [[ -n $SNAP ]] && return 0
  SNAP=$(mktemp -d)
  (cd "$REPO_ROOT" && git ls-files -co --exclude-standard -z | xargs -0 -r tar -cf - --) | tar -xf - -C "$SNAP"
}

# List snapshot files matching a find expression, relative to the snapshot.
snap_files() {
  (cd "$SNAP" && find . -type f "$@" -printf '%P\n' | sort)
}

check_compose() {
  echo "== compose config (with .env.example values)"
  local node dir
  for node in "${ALL_NODES[@]}"; do
    dir="$SNAP/nodes/$node"
    [[ -f $dir/docker-compose.yml ]] || { fail "compose $node: nodes/$node/docker-compose.yml missing"; continue; }
    [[ -f $dir/.env.example ]] || { fail "compose $node: nodes/$node/.env.example missing"; continue; }
    cp "$dir/.env.example" "$dir/.env"
    local mode out
    for mode in single distributed; do
      local -a files=(-f "$dir/docker-compose.yml")
      [[ $mode == single ]] && files+=(-f "$dir/soc-net.yml")
      if out=$(docker compose --project-directory "$dir" --env-file "$dir/.env" "${files[@]}" --profile '*' config --quiet 2>&1); then
        pass "compose $node ($mode)"
      else
        fail "compose $node ($mode): $out"
      fi
    done
    rm -f "$dir/.env"
  done
}

check_shellcheck() {
  echo "== shellcheck"
  local -a files
  mapfile -t files < <(snap_files -name '*.sh')
  if (( ${#files[@]} == 0 )); then pass "shellcheck: no shell scripts"; return; fi
  local f out
  for f in "${files[@]}"; do
    if out=$(docker run --rm -v "$SNAP:/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" -x "$f" 2>&1); then
      pass "shellcheck $f"
    else
      fail "shellcheck $f"
      printf '%s\n' "$out"
    fi
  done
}

# Run a Python validator over files inside the pinned Python image.
# The validator prints PASS/FAIL lines itself.
py_validate() {
  local code=$1; shift
  local out rc=0
  out=$(docker run --rm -v "$SNAP:/mnt:ro" -w /mnt "$PYTHON_IMAGE" python3 -c "$code" "$@" 2>&1) || rc=$?
  printf '%s\n' "$out"
  FAILURES=$((FAILURES + $(grep -c '^FAIL' <<<"$out" || true)))
  (( rc == 0 )) || [[ $out == *FAIL* ]] || fail "validator crashed (exit $rc)"
}

check_json() {
  echo "== JSON (n8n workflows, Grafana dashboards)"
  local -a files
  mapfile -t files < <(snap_files -name '*.json' \( -path './nodes/core/n8n/*' -o -path './nodes/core/grafana/*' \))
  if (( ${#files[@]} == 0 )); then pass "json: no files yet"; return; fi
  py_validate '
import json, sys
for f in sys.argv[1:]:
    try:
        json.load(open(f, encoding="utf-8"))
        print("PASS  json " + f)
    except Exception as e:
        print("FAIL  json %s: %s" % (f, e))
' "${files[@]}"
}

check_xml() {
  echo "== XML (Wazuh rules and decoders)"
  local -a files
  mapfile -t files < <(snap_files -name '*.xml' \( -path './nodes/core/wazuh/rules/*' -o -path './nodes/core/wazuh/decoders/*' \))
  if (( ${#files[@]} == 0 )); then pass "xml: no files yet"; return; fi
  # Wazuh rule/decoder files have several top-level elements, so wrap them.
  py_validate '
import sys, xml.etree.ElementTree as ET
for f in sys.argv[1:]:
    try:
        ET.fromstring("<root>" + open(f, encoding="utf-8").read() + "</root>")
        print("PASS  xml " + f)
    except Exception as e:
        print("FAIL  xml %s: %s" % (f, e))
' "${files[@]}"
}

check_secrets() {
  echo "== secret scan (gitleaks)"
  local out
  if out=$(docker run --rm -v "$SNAP:/scan:ro" "$GITLEAKS_IMAGE" dir /scan --no-banner --redact 2>&1); then
    pass "gitleaks: working tree"
  else
    fail "gitleaks: working tree"
    printf '%s\n' "$out"
  fi
  if git -C "$REPO_ROOT" rev-parse --verify -q HEAD >/dev/null; then
    if out=$(docker run --rm -v "$REPO_ROOT:/repo:ro" -e GIT_CONFIG_COUNT=1 \
        -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
        "$GITLEAKS_IMAGE" git /repo --no-banner --redact 2>&1); then
      pass "gitleaks: git history"
    else
      fail "gitleaks: git history"
      printf '%s\n' "$out"
    fi
  else
    skip "gitleaks: git history (no commits yet)"
  fi
}

main() {
  local -a checks=("$@")
  (( ${#checks[@]} > 0 )) || checks=(all)
  [[ ${checks[0]} == -h || ${checks[0]} == --help ]] && { usage; exit 0; }
  [[ ${checks[*]} == all ]] && checks=(compose shellcheck json xml secrets)
  snapshot
  local c
  for c in "${checks[@]}"; do
    case $c in
      compose|shellcheck|json|xml|secrets) "check_$c" ;;
      *) die "unknown check: $c" ;;
    esac
  done
  finish
}

main "$@"
