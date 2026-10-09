# Request: C14 design, MISP IOCs as Wazuh CDB lists (proposal)

**To:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner; cc Inigo (@poinsot), integrator and n8n owner
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-07
**Refs:** C14, W6.1–W6.5, X-24, R-08, D12, D25, D45 (C10); Inigo's memo item 9 (`n8n-requests-2026-09-30.md`)
**Status:** sent (2026-10-08, with the second checkpoint PR)

## What C14 does

Wazuh flags events that match IOCs kept in MISP. Every so often, MISP's IOCs (IP addresses, domains, file hashes) are exported into Wazuh **CDB lists**. Rules then raise an alert when an event's `srcip`, `dstip`, domain or file hash is on a list. It is **detection only** (D12): a match is an alert that goes through C1 to n8n, and any blocking stays an n8n playbook.

## Proposal: the sync runs inside the Wazuh manager (option a)

```
MISP (intel)  --REST, read-only key-->  misp-sync (in wazuh-manager)  --writes-->  etc/lists/misp-*
                                                     |
                                                     +--> PUT /manager/analysisd/reload (localhost, no restart)
```

1. **Where:** `nodes/core/wazuh/lists/misp-sync.py`, run with the Python bundled in the manager image (the one `custom-n8n.py` already uses, with `requests`). An entrypoint script (`40-misp-sync.sh`) runs one sync before Wazuh starts, so the lists exist when the rules load. It then starts a background loop.
2. **How often:** every `WAZUH_MISP_SYNC_INTERVAL` seconds (proposed: **3600**, one hour), and once at every manager start.
3. **No restart:** after writing changed lists, the script calls the manager's own API on `localhost`, using the admin API user the container already has (`PUT /manager/analysisd/reload`). **Tested 2026-10-07 on 4.14.8:**
   - a sshd event from an address not on a list → no list rule;
   - the address added to the list, reload → HTTP 200 in 0.7 s ("Ruleset reloaded successfully");
   - the same event → the list rule fired.

   No manager restart, so no gap in agent or syslog intake.
4. **Lists**, format `value:misp-event-<id>`:

   | List | MISP attribute types |
   |---|---|
   | `misp-ip` | `ip-src`, `ip-dst` (addresses and CIDRs) |
   | `misp-domain` | `domain`, `hostname` |
   | `misp-hash` | `md5`, `sha1`, `sha256` |

   They're written only when their content changed. The generated lists are data, so they're never committed.
5. **Which IOCs (proposed filter):** attributes of **published** events, with **`to_ids: true`**, not deleted, of the types above, via `POST /attributes/restSearch`. Tested from inside the manager over `soc-net`: HTTP 200 in 1.6 s.
6. **When MISP is unreachable or answers an error:** keep the last lists, log a `WARNING`, and try again next interval. A failed fetch never empties a list. A manager start without MISP still starts, with the lists from the last sync, or empty lists on a fresh machine.
7. **Rules (W6.4, my side):** `rules/1080-misp-ioc.xml`, IDs 108000–108999, groups `asox,misp_ioc` plus the matched event's standard groups. Level **12**, so it reaches n8n through C1 and TheHive's `ioc-match` template. They match:

   | List | Event fields |
   |---|---|
   | `misp-ip` | `srcip`, `dstip` (agents, syslog); Suricata's `src_ip`, `dest_ip` |
   | `misp-domain` | domain fields (Suricata DNS and HTTP, from M3) |
   | `misp-hash` | `syscheck.md5_after`, `sha1_after`, `sha256_after` (FIM) |

8. **Check (for `contracts-check.sh`, later):** `nodes/lab/trigger.sh --scenario ioc-ip` (the seed IOC `203.0.113.66` as `data.srcip`) produces a 1080xx alert at level 12.

## Why the manager and not n8n (option b)

With option b, n8n would run the export as a scheduled workflow reusing C10's key. But n8n would then need **write access to Wazuh's lists and a reload permission**: a new Wazuh API permission and a contract change, like C9. Option a needs no new Wazuh user (it uses the manager's own API from inside the container) and no n8n change, and Inigo prefers it (memo item 9). It ties C14 to MISP's REST API only, the same way Cortex uses it (C7).

## What I need from you

**Diego (MISP, `nodes/intel/misp/`):**
1. **A Read Only MISP user for Wazuh**, e.g. `wazuh@asox.local`, with its own API key. It would be created by `misp-config.sh apply` the same way as n8n's (C10), and stored as `MISP_WAZUH_API_KEY` in `nodes/intel/.env`. Its own key means a leak from core can only read, and you can revoke it alone.
2. **The seed IOC as a detection IOC.** Today the seed attribute `203.0.113.66` has `to_ids: false`, so the proposed filter would skip it, and `ioc-ip` couldn't test C14. Either set `to_ids: true` on it (it stays harmless: documentation range), or add a second seed attribute with `to_ids: true`. Your call, as long as C7 keeps passing.
3. **Confirm or change the filter** (published, `to_ids`, the types above) and the interval (1 h). Should anything be excluded, e.g. tags such as `tlp:red`, or events older than N days until decaying models exist?

**Inigo (shared files, R-08):**
1. `nodes/core/.env.example`:
   - `WAZUH_MISP_URL`: in single-host mode `MISP_URL` as today (`https://misp-nginx:8443` over `soc-net`); in distributed mode the intel host's published 9443.
   - `WAZUH_MISP_API_KEY=__from:intel__` (from `MISP_WAZUH_API_KEY`).
   - Optional `WAZUH_MISP_SYNC_INTERVAL=3600`.

   `soc.sh init` already bootstraps intel before core, so the key exists when core renders.
2. **Certificate:** MISP's certificate is self-signed per machine. I'd skip verification as C7 and C10 do (D25), unless you prefer mounting MISP's certificate into core.
3. The C14 row in PROJECT.md 5 once Diego agrees, and the check in `contracts-check.sh` when W6.4 is built.

**Me (Wazuh, W6.2–W6.5, by 2026-11-20):**
- `misp-sync.py` and `40-misp-sync.sh`;
- passing the variables in `compose.yml`;
- the `<list>` entries in `ossec.conf`;
- the rules and their test cases;
- measuring the manager's memory with the lists loaded (`WAZUH_MANAGER_MEM` 700m).

## By

**2026-10-16** for the design (C14 is due then in the register, X-24). After that, R-08 on `main` when convenient before W6.2 (2026-11-20 milestone). Not a change to any existing contract: it adds C14.
