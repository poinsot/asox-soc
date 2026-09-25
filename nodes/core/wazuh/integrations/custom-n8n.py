#!/usr/bin/env python3
# ASOX SOC: Wazuh -> n8n integration (contract C1, owners: Wazuh + n8n).
# Run by wazuh-integratord for every alert at or above the configured level:
#   custom-n8n <alert_file> <api_key> <hook_url>
# POSTs the raw Wazuh alert JSON to hook_url (${N8N_WEBHOOK_URL}/webhook/wazuh-alert)
# with the shared webhook token (api_key) in the X-ASOX-Token header.
# Configured in ossec.conf by config/entrypoint-scripts/20-n8n-integration.sh.
# Errors go to /var/ossec/logs/integrations.log.
import json
import sys
import time

try:
    import requests
except ImportError:
    print("No module 'requests' found")
    sys.exit(1)

LOG_FILE = "/var/ossec/logs/integrations.log"
TOKEN_HEADER = "X-ASOX-Token"
TIMEOUT_SECONDS = 10


def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%a %b %d %H:%M:%S %Z %Y')} custom-n8n: {message}\n")


def main(argv):
    if len(argv) < 4:
        log("wrong arguments: expected <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, token, hook_url = argv[1], argv[2], argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    alert_id = alert.get("id", "?")
    try:
        response = requests.post(
            hook_url, json=alert, headers={TOKEN_HEADER: token}, timeout=TIMEOUT_SECONDS
        )
    except requests.RequestException as e:
        log(f"alert {alert_id}: request to {hook_url} failed: {e}")
        return 1
    if response.status_code >= 300:
        log(f"alert {alert_id}: {hook_url} returned HTTP {response.status_code}: {response.text[:200]}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
