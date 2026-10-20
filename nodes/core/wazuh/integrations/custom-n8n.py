#!/usr/bin/env python3
# ASOX SOC: Wazuh -> n8n integration (contract C1, owners: Wazuh + n8n).
# Run by wazuh-integratord for every alert at or above the configured level,
# one alert at a time (integratord waits for this script, X-35):
#   custom-n8n <alert_file> <api_key> <hook_url> <debug> <options> <timeout> <retries>
# POSTs the raw Wazuh alert JSON to hook_url (${N8N_WEBHOOK_URL}/webhook/wazuh-alert)
# with the shared webhook token (api_key) in the X-ASOX-Token header.
# Configured in ossec.conf by config/entrypoint-scripts/20-n8n-integration.sh.
# Errors go to /var/ossec/logs/integrations.log.
#
# Retries (X-10, agreed with the n8n owner, nodes/core/n8n/docs/reply-wazuh-x10.md):
# - Retried: connection error, timeout, HTTP 404 (webhook not registered yet:
#   n8n starting or re-importing) and 5xx. Final: 2xx (done), 403 (token),
#   422 (bad JSON) and any other answer.
# - Up to <retries> more tries after the first, waiting 2, 5, 10, 20 s; each
#   try uses <timeout> seconds. Later alerts wait in alerts.json meanwhile.
# - Fast-fail: when a whole chain fails, a mark file is written. While it is
#   less than FAST_FAIL_SECONDS old, each alert gets one try and no waits, so
#   a long n8n outage costs one try per alert, not a chain. The first success
#   removes the mark; after FAST_FAIL_SECONDS the full chain applies again.
# - n8n deduplicates by alert id at queue insert, so a retry after a timeout
#   that had reached n8n doesn't create a second TheHive alert (N8N-1.9).
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print("No module 'requests' found")
    sys.exit(1)

LOG_FILE = os.environ.get("ASOX_C1_LOG", "/var/ossec/logs/integrations.log")
MARK_FILE = os.environ.get("ASOX_C1_MARK", "/var/ossec/var/run/custom-n8n.down")
TOKEN_HEADER = "X-ASOX-Token"
DEFAULT_TIMEOUT = 10
WAITS = (2, 5, 10, 20)        # before retries 1..4
if os.environ.get("ASOX_C1_WAITS"):  # tests only (tests/c1-retry.sh): shorter waits
    WAITS = tuple(float(w) for w in os.environ["ASOX_C1_WAITS"].split(","))
FAST_FAIL_SECONDS = 300
RETRY_STATUS = {404}          # plus every 5xx


def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%a %b %d %H:%M:%S %Z %Y')} custom-n8n: {message}\n")


def int_arg(value, default):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def fast_fail_active():
    try:
        return time.time() - os.path.getmtime(MARK_FILE) < FAST_FAIL_SECONDS
    except OSError:
        return False


def post_once(hook_url, alert, token, timeout):
    """(done, retryable, reason): done is True on 2xx."""
    try:
        r = requests.post(hook_url, json=alert, headers={TOKEN_HEADER: token}, timeout=timeout)
    except requests.RequestException as e:
        return False, True, f"request failed: {e}"
    if r.status_code < 300:
        return True, False, ""
    retryable = r.status_code in RETRY_STATUS or r.status_code >= 500
    return False, retryable, f"returned HTTP {r.status_code}: {r.text[:200]}"


def main(argv):
    if len(argv) < 4:
        log("wrong arguments: expected <alert_file> <api_key> <hook_url> [... <timeout> <retries>]")
        return 2
    alert_file, token, hook_url = argv[1], argv[2], argv[3]
    # integratord passes "<debug> <options> <timeout> <retries>" after the URL,
    # with empty strings for unused ones, and (without debug) a literal
    # "> /dev/null 2>&1" as one more argument (it appends the redirection
    # before splitting, then runs the script without a shell; v4.14.8
    # integrator.c). So: the first two numeric arguments after the URL.
    nums = [a for a in argv[4:] if a.strip().isdigit()]
    timeout = int_arg(nums[0], DEFAULT_TIMEOUT) if nums else DEFAULT_TIMEOUT
    retries = int_arg(nums[1], 0) if len(nums) > 1 else 0
    timeout = timeout or DEFAULT_TIMEOUT
    with open(alert_file) as f:
        alert = json.load(f)
    alert_id = alert.get("id", "?")

    fast = fast_fail_active()
    tries = 1 if fast else 1 + min(retries, len(WAITS))
    reason = ""
    for attempt in range(tries):
        if attempt:
            time.sleep(WAITS[attempt - 1])
        done, retryable, reason = post_once(hook_url, alert, token, timeout)
        if done:
            if os.path.exists(MARK_FILE):
                try:
                    os.remove(MARK_FILE)
                except OSError:
                    pass
                log(f"alert {alert_id}: delivered; n8n reachable again, full retries back on")
            elif attempt:
                log(f"alert {alert_id}: delivered on try {attempt + 1}")
            return 0
        if not retryable:
            log(f"alert {alert_id}: {hook_url} {reason} (not retried)")
            return 1

    if fast:
        log(f"alert {alert_id}: {hook_url} {reason} (fast-fail: one try while n8n is down)")
    elif tries == 1:
        log(f"alert {alert_id}: {hook_url} {reason}")  # no retries configured
    else:
        try:
            with open(MARK_FILE, "w") as f:
                f.write(f"{int(time.time())}\n")
        except OSError as e:
            log(f"could not write {MARK_FILE}: {e}")
        log(f"alert {alert_id}: {hook_url} {reason} after {tries} tries; "
            f"fast-fail for {FAST_FAIL_SECONDS} s")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
