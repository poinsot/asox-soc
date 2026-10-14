# Reply: C14 design (MISP IOCs as Wazuh CDB lists), and X-36 (2026-10-14)

**To:** Daniel (@dmelgar1110), Wazuh owner; cc Inigo (@poinsot), integrator and n8n owner; Park, TheHive owner (new test IOC)
**From:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner
**Refs:** C14, C7, C10, R-08, X-24, X-36; answers `nodes/core/wazuh/docs/request-cortex-misp-c14-design.md` (2026-10-07)
**Files (branch `cortex-misp`):** `nodes/intel/misp/misp-config.sh`, `misp-config.json`, `seed/seed-event.json`, `nodes/intel/.env.example`

Hi Daniel,

**I agree with option a**: the sync runs inside the Wazuh manager with its own Read Only MISP key. Answers to your three points are below. They're built on `cortex-misp` and checked by `misp-config.sh apply`, but not yet run on a live instance.

## 1. Read Only user for Wazuh: done

- `misp-config.json` → `wazuh.user` = `wazuh@asox.local`, role **Read Only**, its own API key.
- `misp-config.sh apply` creates it, the same way as n8n's C10 user (`bootstrap.sh intel` runs it, R-22). The key is stored as **`MISP_WAZUH_API_KEY`** in `nodes/intel/.env` (`__bootstrap__` in `.env.example`).
- `apply` checks that the key gets the seed IOC through C14's filter (below), and that a write gets 403.
- **Inigo (R-08):** `WAZUH_MISP_API_KEY=__from:intel__` copies `MISP_WAZUH_API_KEY`. Skipping certificate verification as in C7 and C10 (D25) is fine with me.

## 2. Seed IOC: new address, `to_ids: true` (also settles X-36)

With Inigo, we went with **X-36 option (a)**. The seed IOC is now **`101.99.75.184`**:

- It's an `ip-dst` address from Botvrij's "3 examples of malspam pushing Loki-Bot malware" event, where it already has `to_ids: true`. It's copied into the seed event so the tests don't depend on the feed's content.
- It's outside the reserved ranges and, checked 2026-10-14, on none of our 215 warninglists. My first pick, a Botvrij C2 address (`61.4.102.97`), turned out to be on the vpn-ipv4 datacenter list, which is why `apply` now **fails** whenever the seed IOC is on an enabled warninglist. So C10 won't tag it as a common value.
- The seed attribute now has **`to_ids: true`**, so C14's filter exports it and `ioc-ip` can test C14.
- The seed event's title changed to `ASOX seed event: test IOC 101.99.75.184`. `bootstrap.sh intel` creates the new event. `apply` then **deletes the old `203.0.113.66` seed event**, so every instance ends up with the same single seed. C7 reads the IOC from `seed-event.json`, so it follows the change by itself.
- The address is only ever written into test logs. Nothing in the lab contacts it.

**To update** (your files, not changed by me):

| Owner | File |
|---|---|
| Daniel | `nodes/lab/trigger.sh --scenario ioc-ip`, `nodes/core/wazuh/tests/cases/lab-scenarios.cases` |
| Inigo | `nodes/core/n8n/fixtures/synthetic/100100-misp-hit.json` and its expected verdict (MISP_2_1 now also finds the Botvrij event) |
| Park | `nodes/cases/thehive/scripts/thehive-test-alert.sh` (3 scenarios) |

Until you update them, the `203.0.113.66` scenarios get no MISP hit on an instance where the old seed event has been deleted.

## 3. Filter and interval

**Filter: confirmed, plus `enforceWarninglist`.** Your `POST /attributes/restSearch` body:

```json
{"returnFormat": "json",
 "type": ["ip-src", "ip-dst", "domain", "hostname", "md5", "sha1", "sha256"],
 "to_ids": 1, "published": 1, "enforceWarninglist": 1}
```

- **`enforceWarninglist: 1` (new):** MISP drops attributes that are on an enabled warninglist (215 lists, R-14), so a feed listing `8.8.8.8` or a top site can't make Wazuh raise a level 12 alert for it. Same lists as C10, so Wazuh and n8n agree on what's *common*.
- **Deleted attributes** are excluded by default.
- **Page the query** (`limit` 5000, `page` 1, 2…) so one sync can't push misp-core past its 900m limit as feeds grow. Botvrij alone is ~29k attributes before the filter.
- **No `tlp:red` exclusion for now:** nothing in our MISP carries it. The TLP/PAP policy (X-08, 2026-11-10) will say whether C14 needs one, and I'll tell you then.
- **No age limit for now.** Old feed IPs are the main false-positive risk, but the right fix is decaying models (MISP backlog, later), not a fixed cutoff. If your rules turn out noisy with Botvrij's older events, tell me and we'll add a `date` window for `misp-ip` and `misp-domain` (hashes don't go stale).

**Interval: 1 hour is fine.** Feeds refresh only through `misp-config.sh fetch` today (scheduled refresh is on my backlog), so a shorter interval wouldn't find anything new.

Thanks!
Diego
