# Request: two Wazuh items for shared scripts (backups, lab health)

**To:** Inigo (@poinsot), integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-11
**Refs:** WO.4, A74 (disk and core backup size), A75 (fresh-clone test, lab `pending`), `scripts/backup.sh`, `scripts/healthcheck.sh`
**Status:** sent (2026-10-14, with PR #20, merged)

## 1. Core backups carry Wazuh's vulnerability feed

A74 measured `core` volumes at ~10.2 GB, ~9.5 GB of which is the vulnerability feed the manager downloads after its first start. `backup.sh core` archives it every time, although a restored manager downloads it again by itself. It isn't configuration, alerts or keys.

**Ask:** exclude the feed from `backup.sh core`. It is in volume **`wazuh_queue`** (mounted at `/var/ossec/queue`), measured 2026-10-11:

| Path (in the volume) | My instance (since 2026-09-29) | A fresh `init core`, 15 min after start |
|---|---|---|
| `vd/` | **9.6 GB** | 8.7 GB |
| `vd_updater/` | 513 MB | 192 MB |

Exclude **only** `vd/` and `vd_updater/`. Keep `keystore/`, which holds the vulnerability module's indexer credentials, and the rest of the volume. The backup then keeps:
- `ossec.conf`, rules, decoders, CDB lists (including `etc/lists/misp/`, C14);
- agent keys (`client.keys`) and groups (`etc/shared/`);
- the API configuration;
- the indexer's alerts.

After a restore, the first manager start re-downloads the feed (D6: internet is available everywhere).

I can test a core backup → reset → restore round trip on my machine once it's in, and report the size before and after.

## 2. `healthcheck.sh` right after `soc.sh up`: the lab agent's brief `pending`

Noted in `docs/handoff.md` (A75): right after `soc.sh up`, the lab agent can show `pending` for a few seconds while it reconnects, and `check_lab` reports a failure. I saw the same after the Windows agent enrolled (W5.5). The agent's first minute is "pending, receiving the group configuration, restart, active".

**Ask:** in `check_lab`, wait up to ~60 s for `Active` before failing, like the Grafana login retry (A82).

## By

No deadline. Item 1 matters before the next backup someone keeps (~9.5 GB less per core backup).
