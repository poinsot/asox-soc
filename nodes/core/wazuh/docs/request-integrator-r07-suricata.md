# Request: R-07 Suricata variables and pinned images (M3 built)

**To:** Inigo (@poinsot), integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-08
**Refs:** R-07, W3.1, W3.2, W3.6, D49, D39, D40; README "Network IDS: Suricata"
**Status:** sent (2026-10-14, with PR #20, merged)

## What exists (branch `wazuh`, tested live 2026-10-08)

Suricata runs in the lab node as service `suricata` (`nodes/lab/docker-compose.yml`). It shares `lab-agent`'s network namespace, writes alerts only to `eve.json`, and the lab agent forwards them (built-in 86601). `rules/1010-suricata.xml` sets their levels. `trigger.sh --scenario ids-test` and `ids-scan` produced 101001 and 4 × 101010, and all five reached `recv-wazuh-alert`. `healthcheck.sh` checks it like any service (`lab/suricata: running, healthy`).

Until R-07, the compose file uses defaults: `${SURICATA_IMAGE:-jasonish/suricata:8.0.7}` and `${SURICATA_MEM:-750m}`. It already works on every machine; R-07 only moves the values to where the others live.

## What I need (your files)

1. **`nodes/lab/.env.example`:**
   - `SURICATA_IMAGE=jasonish/suricata:8.0.7`
   - `SURICATA_MEM` sized by profile (D40): **`low` 750m** (measured: 482–518 MiB anonymous at rest, 576 MiB peak while `suricata-update` runs and the ~53,000 ET Open signatures load, × 1.15 + 64 MiB → 726, rounded up to 750). For `standard` I'd use the same 750m: the lab's traffic doesn't change with the profile, and the config pins one thread per interface.
2. **`docs/decisions.md`, pinned images (D49 says "recorded when W3.2 is built"):**

   | Image | Used by |
   |---|---|
   | `jasonish/suricata:8.0.7` | the `suricata` service, released 2026-09-29, ~620 MB uncompressed |
   | `instrumentisto/nmap:7.98-r2` | only `trigger.sh --scenario ids-scan`, run and removed (13 MB); `NMAP_IMAGE` overrides it |
3. **CHECKLIST.md section 1 (disk) and section 8:** `core` mode adds about 0.65 GB (the Suricata image and its rules volume). Internet access is needed at the first start (ET Open download), then at most once a day.
4. **Memory (D39):** `core` + lab + Suricata on `low` peaked at about 3.8 GB of the VM on my machine (WSL 8 GB). `scripts/mem-report.sh` on the 6 GB reference is yours to confirm.

## Two notes

- **Port-scan detection needs `HOME_NET` = the protected host.** `nodes/lab/suricata/start.sh` sets it to the lab agent's addresses at start. With the default (all private ranges), traffic between Docker containers never counts as "external", and ET SCAN rules stay silent. This will matter again on the Phase 2 sensor machine (W7.3).
- `testmynids.org` doesn't resolve on the university network, so `ids-test` sends the same signature's content (`uid=0(root)`) to `example.com`.

## By

Before the final checkpoint. Nothing is blocked meanwhile: the defaults apply.
