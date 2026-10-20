#!/usr/bin/env bash
# C1 retry check (owner: Wazuh, X-10): runs tests/c1_retry_test.py inside the
# running manager, with Wazuh's bundled Python, against the repo's
# integrations/custom-n8n.py and a stub HTTP server. No n8n involved.
# Usage: nodes/core/wazuh/tests/c1-retry.sh
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(cd "$WAZUH_DIR/../../.." && pwd)"
instance=$(sed -n 's/^SOC_INSTANCE=//p' "$REPO_DIR/topology.env" 2>/dev/null | tail -1)
MANAGER="${instance:-asox}-core-wazuh-manager-1"
PY=/var/ossec/framework/python/bin/python3

if [[ $(docker inspect -f '{{.State.Running}}' "$MANAGER" 2>/dev/null) != true ]]; then
  echo "ERROR manager container $MANAGER is not running (scripts/soc.sh up core)" >&2
  exit 2
fi
docker cp "$WAZUH_DIR/integrations/custom-n8n.py" "$MANAGER:/tmp/c1-custom-n8n.py"
docker cp "$TESTS_DIR/c1_retry_test.py" "$MANAGER:/tmp/c1_retry_test.py"
rc=0
docker exec "$MANAGER" "$PY" /tmp/c1_retry_test.py /tmp/c1-custom-n8n.py || rc=$?
docker exec "$MANAGER" rm -f /tmp/c1-custom-n8n.py /tmp/c1_retry_test.py
exit "$rc"
