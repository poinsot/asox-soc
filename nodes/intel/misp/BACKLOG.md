# MISP backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. Cortex has its own backlog: [nodes/cases/cortex/BACKLOG.md](../../cases/cortex/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for MISP, so other owners can see where things stand and what to expect. Last updated: 2026-09-30.

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

The baseline is done: MISP runs and Cortex finds the seed event (C7). The current work is **warninglists and feeds as code** (`misp-config.json` + `misp-config.sh`). It is tested on `cases-intel` (standard profile) and waiting for a checkpoint merge.

## Done (baseline, `v1.0-baseline`)

| Item | Notes |
|---|---|
| ✅ MISP 2.5.47 (core, nginx, modules, MariaDB, Valkey) | `compose.yml`; HTTPS on 9443 with a self-signed certificate |
| ✅ Read Only user `cortex@asox.local` + API key | Used by Cortex's MISP analyzer (C7) |
| ✅ Seed event with test IOC `203.0.113.66` | `seed/seed-event.json`; C7 checks it |

## In progress (tested 2026-09-30, not merged yet)

| Item | Status | Notes |
|---|---|---|
| `misp-config.sh apply / fetch / export` + `misp-config.json` | 🔨 tested: two `apply` runs are idempotent, `export` round-trips unchanged | Run by hand after `soc.sh init`, on the machine that hosts `intel` |
| Warninglists: every list with ≤ 100,000 entries enabled (215 of 225), larger ones disabled | 🔨 tested | Checked: `8.8.8.8` → public DNS resolvers, `10.0.0.5` → RFC 1918, `185.220.101.1` → Tor exit nodes, `github.com` → top-site lists. See "Known issue" below for why the big lists are off. |
| Feed "The Botvrij.eu Data" enabled | 🔨 tested: 435 events imported | Gives Cortex's MISP analyzer real indicators to find |
| Feed "CIRCL OSINT Feed" | Listed but **off** | Large; turn on only after the memory and disk re-measure below |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ Re-measure intel memory with the warninglists and Botvrij on, on `standard` and `low` | — | Memory limits rule (PROJECT.md D40). If limits must rise, the integrator changes the `.env.example` files. |
| ⏭️ Scheduled feed refresh (daily) | Check the misp-core image's cron settings | Today feeds refresh only with `misp-config.sh fetch` |
| ⏭️ Turn on CIRCL OSINT | The re-measure above | Also grows `intel` backups |
| ⏭️ Choose which taxonomies and galaxies to use | TheHive (Park) for tag names | Tags that show up on cases |
| ⏭️ Export/import of more MISP settings (beyond feeds and warninglists) | — | So UI changes reach git (PROJECT.md 11.2) |

## Proposal: contract C10, n8n → MISP warninglist check

⛔ **Needs agreement from the n8n owner (Inigo) and changes by the integrator.** Not implemented.

- **What:** before enrichment, n8n sends all of an alert's observables to MISP in one call (`POST /warninglists/checkValue`) and learns which ones are *common* (public DNS, cloud and CDN ranges, top sites, private ranges…). A match means *common*, **not** *safe*: attackers use Google, GitHub and AWS too. The decision rules would live in n8n; in particular, an indicator on a list is never auto-contained without analyst approval (D12).
- **Why direct and not through Cortex:** one call for all observables, and it always uses MISP's current lists. Until C10 exists, n8n can get the same answer one observable at a time through the MISPWarningLists analyzer in Cortex (C6).
- **Changes it would need:**
  - MISP (me): a Read Only user `n8n@asox.local` with its own API key.
  - Integrator: `MISP_N8N_API_KEY=__from:intel__` in `nodes/core/.env.example`, `MISP_URL` for n8n, an n8n credential in `bootstrap.sh`, and a C10 check in `contracts-check.sh`.
  - n8n (Inigo): the warninglist step in the playbooks.

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 Decaying models (old IOCs lose weight) | — | |
| 🕓 Confirmed case IOCs from TheHive into MISP | TheHive (Park) | Analyst-triggered responder in Cortex (D12) |
| 🕓 MISP IOCs pushed into Wazuh CDB lists for proactive detection | Wazuh (Daniel) | Later also to Snort (Phase 2) |
| 🕓 Sharing with external MISP communities | — | Needs the TLP/PAP policy first (Cortex backlog) |

## Known issue: large warninglists crash misp-core

MISP enables a 1,000,000-entry warninglist (Cisco Umbrella top 1M) by default. With it on, **every warninglist check was killed for lack of memory** under misp-core's 900m limit, and enabling any list of that size did the same. **This also affects the current `main`**, so any fresh `intel` node has it until this work is merged. `misp-config.sh apply` fixes it by disabling lists above 100,000 entries (`maxEntries` in `misp-config.json`). The trade-off is that matches against the top-1M site lists and the big file-hash lists are lost; the top-50k site lists stay on.

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | Proposal C10 above, which needs your agreement. Until then, use the MISPWarningLists analyzer through Cortex. |
| **TheHive** (Park) | Later: sending confirmed IOCs to MISP, and tag names (taxonomies). |
| **Wazuh** (Daniel) | Later: MISP IOCs into CDB lists. |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | Please note the known issue above. C10 changes only if it's agreed. |
