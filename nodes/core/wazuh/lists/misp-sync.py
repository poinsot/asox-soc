#!/var/ossec/framework/python/bin/python3
"""MISP IOCs -> Wazuh CDB lists (owner: Wazuh; contract C14, W6.2-W6.5).

Runs inside the wazuh-manager container with Wazuh's bundled Python (it has
`requests`, like integrations/custom-n8n.py). Started by
config/entrypoint-scripts/40-misp-sync.sh: once before Wazuh starts
(--no-reload), then every WAZUH_MISP_SYNC_INTERVAL seconds (--loop).

Each sync asks MISP for the attributes of published events, flagged for
detection (to_ids), not deleted and not on a MISP warninglist, and writes
three CDB lists under /var/ossec/etc/lists/misp/:

  misp-ip      ip-src, ip-dst          (addresses; /8, /16, /24 as prefixes)
  misp-domain  domain, hostname
  misp-hash    md5, sha1, sha256

as "key:misp-event-<id>". A list is rewritten only when its content changed,
and then the ruleset is reloaded through the manager's own API
(PUT /manager/analysisd/reload, no restart). A failed fetch never empties a
list: the last good lists stay. Rules: rules/1080-misp-ioc.xml.

Environment (from nodes/core/.env through compose.yml; R-08):
  WAZUH_MISP_URL            e.g. https://misp-nginx:8443 (empty: C14 off)
  WAZUH_MISP_API_KEY        a Read Only MISP user's key (core's MISP_WAZUH_API_KEY)
  WAZUH_MISP_SYNC_INTERVAL  seconds between syncs (default 3600)
  API_USERNAME, API_PASSWORD  the manager's admin API user (already set)

Usage: misp-sync.py [--once|--loop [--after-failure]] [--no-reload]
Exit code (--once): 0 ok (changed or not), 1 MISP failed (lists kept),
2 not configured.
"""
import ipaddress
import os
import sys
import time

import requests
import urllib3

LIST_DIR = "/var/ossec/etc/lists/misp"
LISTS = {
    "misp-ip": ("ip-src", "ip-dst"),
    "misp-domain": ("domain", "hostname"),
    "misp-hash": ("md5", "sha1", "sha256"),
}
MAX_ENTRIES = 200000          # per list; MISP's large feeds belong in warninglists
PAGE_SIZE = 5000            # Diego, C14 reply: keeps misp-core under its 900m
TIMEOUT = 60
QUICK_SECONDS = int(os.environ.get("ASOX_MISP_QUICK_SECONDS") or 60)  # R-34
QUICK_TRIES = 10
API = "https://localhost:55000"

# MISP and the manager API use self-signed certificates in this lab (D25).
urllib3.disable_warnings()


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "misp-sync:", msg, flush=True)


def fetch_attributes(url, key):
    """All matching attributes, page by page. Raises on any error."""
    types = [t for ts in LISTS.values() for t in ts]
    headers = {"Authorization": key, "Accept": "application/json",
               "Content-Type": "application/json"}
    attrs, page = [], 1
    while True:
        body = {"returnFormat": "json", "type": types, "to_ids": 1,
                "published": 1, "deleted": 0, "enforceWarninglist": 1,
                "limit": PAGE_SIZE, "page": page}
        r = requests.post(url.rstrip("/") + "/attributes/restSearch", json=body,
                          headers=headers, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        chunk = r.json().get("response", {}).get("Attribute", [])
        attrs += chunk
        if len(chunk) < PAGE_SIZE:
            return attrs
        page += 1


def ip_key(value):
    """CDB key for an address or network, or None if it can't be one.
    address_match_key matches exact addresses, and networks written as the
    octet prefix ("10.1.2." for /24), so only /8, /16, /24 and /32 fit."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None  # IPv6 keys contain ':' (the CDB separator); not supported yet
    octets = str(net.network_address).split(".")
    return {32: str(net.network_address), 24: ".".join(octets[:3]) + ".",
            16: ".".join(octets[:2]) + ".", 8: octets[0] + "."}.get(net.prefixlen)


def build_lists(attrs):
    out = {name: {} for name in LISTS}
    skipped = 0
    for a in attrs:
        t, v, ev = a.get("type"), str(a.get("value", "")), a.get("event_id", "?")
        for name, types in LISTS.items():
            if t not in types:
                continue
            key = ip_key(v) if name == "misp-ip" else v.strip().lower()
            if not key or ":" in key or len(out[name]) >= MAX_ENTRIES:
                skipped += 1
                continue
            out[name].setdefault(key, "misp-event-" + str(ev))
    if skipped:
        log(f"skipped {skipped} value(s): IPv6, unsupported prefix, ':' in value or over {MAX_ENTRIES}")
    return {name: "".join(f"{k}:{v}\n" for k, v in sorted(entries.items()))
            for name, entries in out.items()}


def write_if_changed(name, content):
    path = os.path.join(LIST_DIR, name)
    try:
        with open(path) as f:
            if f.read() == content:
                return False
    except FileNotFoundError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.chmod(tmp, 0o660)
    try:
        import pwd
        import grp
        os.chown(tmp, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, path)
    return True


def reload_ruleset():
    user, pw = os.environ.get("API_USERNAME"), os.environ.get("API_PASSWORD")
    if not user or not pw:
        log("WARNING: API_USERNAME/API_PASSWORD not set; lists apply at the next manager start")
        return
    try:
        tok = requests.post(API + "/security/user/authenticate", auth=(user, pw),
                            verify=False, timeout=TIMEOUT).json()["data"]["token"]
        r = requests.put(API + "/manager/analysisd/reload",
                         headers={"Authorization": "Bearer " + tok}, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        log("ruleset reloaded (analysisd), no restart")
    except Exception as e:  # noqa: BLE001 - keep the loop alive, say why
        log(f"WARNING: reload failed ({e}); lists apply at the next manager start")


def sync(reload):
    url, key = os.environ.get("WAZUH_MISP_URL", ""), os.environ.get("WAZUH_MISP_API_KEY", "")
    if not url or not key:
        log("C14 off: WAZUH_MISP_URL or WAZUH_MISP_API_KEY is empty (R-08)")
        return 2
    try:
        attrs = fetch_attributes(url, key)
    except Exception as e:  # noqa: BLE001
        log(f"ERROR: MISP fetch failed ({e}); keeping the current lists")
        return 1
    lists = build_lists(attrs)
    changed = [n for n, c in lists.items() if write_if_changed(n, c)]
    counts = ", ".join(f"{n} {c.count(chr(10))}" for n, c in lists.items())
    log(f"{len(attrs)} attribute(s) -> {counts}; changed: {', '.join(changed) or 'none'}")
    if changed and reload:
        reload_ruleset()
    return 0


def loop(reload, after_failure):
    """Sync every WAZUH_MISP_SYNC_INTERVAL seconds. After a failed sync, and
    from the start when the first sync failed (--after-failure), retry every
    QUICK_SECONDS up to QUICK_TRIES times first (R-34): with `soc.sh up full`
    core starts before intel, and in distributed mode intel may come up
    later, so the lists shouldn't stay empty for a whole interval."""
    interval = int(os.environ.get("WAZUH_MISP_SYNC_INTERVAL") or 3600)
    quick = QUICK_TRIES if after_failure else 0
    if quick:
        log(f"first sync failed; retrying every {QUICK_SECONDS} s, up to {QUICK_TRIES} times")
    while True:
        time.sleep(QUICK_SECONDS if quick else interval)
        rc = sync(reload)
        if rc == 1:                       # MISP unreachable or an error
            if quick:
                quick -= 1
                if not quick:
                    log(f"still failing after {QUICK_TRIES} quick retries; next try in {interval} s")
            else:
                quick = QUICK_TRIES
                log(f"sync failed; retrying every {QUICK_SECONDS} s, up to {QUICK_TRIES} times")
        else:
            quick = 0


def main(argv):
    reload = "--no-reload" not in argv
    if "--loop" in argv:
        loop(reload, "--after-failure" in argv)
    return sync(reload)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
