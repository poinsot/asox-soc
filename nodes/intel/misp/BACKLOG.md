# MISP backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. Cortex has its own backlog: [nodes/cases/cortex/BACKLOG.md](../../cases/cortex/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for MISP, so other owners can see where things stand and what to expect. Last updated: 2026-09-30, after the integration session (PROJECT.md 5, D44–D49; [docs/integration-backlog.md](../../../docs/integration-backlog.md)).

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

The baseline is done: MISP runs and Cortex finds the seed event (C7). The current work is **warninglists and feeds as code** (`misp-config.json` + `misp-config.sh`). It is tested on `cases-intel` (standard profile) and waiting for a checkpoint merge; it carries the warninglist size cap that unblocks C10 (R-14).

## Decisions (2026-09-30)

| Decision | What it means for MISP | Where it is recorded |
|---|---|---|
| **C10 accepted** (D45): n8n → MISP warninglist check | No longer blocked on agreement. Goes live only after R-14 is merged and misp-core is re-measured under batch checks | PROJECT.md 5 (C10), 15 (D45); X-31 |
| **C14 numbered** (proposed): MISP → Wazuh CDB lists | Design owed by Daniel and me **by 2026-10-16** (Wazuh W6.1), the earliest cross-owner deadline | PROJECT.md 5 (C14); X-24 |
| **Suricata replaces Snort** (D49) | IOC export to the network IDS (later) targets Suricata | PROJECT.md 15 (D49); X-34 |

## Dates

Aligned with the shared team dates (integration backlog, section F).

| Target | Date |
|---|---|
| C14 design agreed with Wazuh (Daniel) | **2026-10-16** |
| Warninglists and feeds as code merged (R-14), intel re-measured | **2026-10-20** (checkpoint 1) |
| C10 live, with the n8n owner (N8N-2.11) | 2026-11-10 (v1.2) |
| Feature freeze / delivery | 2026-11-24 / 2026-12-01 |

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
| Warninglists: every list with ≤ 100,000 entries enabled (215 of 225), larger ones disabled | 🔨 tested | Checked: `8.8.8.8` → public DNS resolvers, `10.0.0.5` → RFC 1918, `185.220.101.1` → Tor exit nodes, `github.com` → top-site lists. This is R-14's fix; see "Known issue" below. |
| Feed "The Botvrij.eu Data" enabled | 🔨 tested: 435 events imported | Gives Cortex's MISP analyzer real indicators to find |
| Feed "CIRCL OSINT Feed" | Listed but **off** | Large; turn on only after the memory and disk re-measure below. Rough, unmeasured estimate for `standard`: intel +~1.1 GB (misp-core ~1.5g, MariaDB ~1g with a 512M buffer pool, Valkey ~256m) |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ C14 design with Daniel: which attributes (IPs, domains, MD5/SHA-256), which events (published, `to_ids`, a tag), refresh cadence, who runs the sync | Wazuh (W6.1) | **Due 2026-10-16.** Open: a Wazuh-side script with its own read-only MISP key (R-08), or an n8n scheduled workflow reusing C10's key (R-08 dropped). Written up for Inigo, who completes C14 in PROJECT.md 5 |
| ⏭️ Re-measure intel memory with the warninglists and Botvrij on, on `standard` and `low`, including batch `checkValue` calls | — | Memory limits rule (PROJECT.md D40). Needed before C10 goes live (R-14). If limits must rise, the integrator changes the `.env.example` files. |
| ✅ Read Only role can call `POST /warninglists/checkValue` | — | Verified 2026-10-01 with the Read Only key of `cortex@asox.local`: a batch of six values returns HTTP 200 with the expected lists, and `POST /events/add` is refused (HTTP 403). C10 needs no custom role |
| ⏭️ Scheduled feed refresh (daily) | Check the misp-core image's cron settings | Today feeds refresh only with `misp-config.sh fetch` |
| ⏭️ Turn on CIRCL OSINT | The re-measure above | Also grows `intel` backups |
| ⏭️ Choose which taxonomies and galaxies to use | TheHive (Park) for tag names | Tags that show up on cases |
| ⏭️ Export/import of more MISP settings (beyond feeds and warninglists) | — | So UI changes reach git (PROJECT.md 11.2) |

## Contract C10: n8n → MISP warninglist check

✅ **Accepted 2026-09-30 (D45)** by the n8n owner (Inigo) and me. Full text in PROJECT.md 5. Not built yet.

- **What:** before enrichment, n8n sends all of an alert's observables to MISP in one call (`POST /warninglists/checkValue`) and learns which ones are *common* (public DNS, cloud and CDN ranges, top sites, private ranges…). A match means *common*, **not** *safe*: attackers use Google, GitHub and AWS too. n8n may skip quota-limited online analyzers for a match and tags the observable, but never closes, suppresses or downgrades an alert because of it (D12). MISP unreachable = n8n continues without it.
- **Why direct and not through Cortex:** one call for all observables, and it always uses MISP's current lists. There is **no interim fallback through Cortex**: the catalog's MISPWarningLists analyzer doesn't query MISP and fails without its own copy of the lists (tested 2026-10-01, disabled; Cortex backlog). Until C10 is live, n8n has no warninglist signal. Analysts see C10's result as n8n's tag on the observable, so TheHive needs no warninglist analyzer.
- **Before it goes live:** R-14's size cap merged (this branch), misp-core re-measured under batch checks. The Read Only role is verified for `checkValue` (2026-10-01).
- **Work:**
  - MISP (me): ✅ a Read Only user `n8n@asox.local` with its own API key (2026-10-01: created by `misp-config.sh apply`, key in `nodes/intel/.env` as `MISP_N8N_API_KEY`; reachable from the n8n container). What is left for n8n and the integrator: [C10-handoff-n8n.md](C10-handoff-n8n.md).
  - Integrator (R-13): `MISP_N8N_API_KEY=__from:intel__` and `MISP_URL` in `nodes/core/.env.example` and `render-env.sh`, the user in `bootstrap.sh intel`, the n8n credential "MISP API (n8n)" in `bootstrap.sh core`, and `chk-misp-api` + C10 in `contracts-check.sh` (`8.8.8.8` is on a public-DNS list; a write is refused).
  - n8n (Inigo): `lib-misp-warninglist` (N8N-2.11), target v1.2 (2026-11-10).

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 C14 build: MISP IOCs pushed into Wazuh CDB lists for proactive detection | Wazuh (Daniel, W6.2–W6.5, M6 2026-11-20); n8n if it runs the sync | After the design above. Later also to Suricata (Phase 2, D49) |
| 🕓 Decaying models (old IOCs lose weight) | — | Matters most for IPs from older feed events |
| 🕓 Confirmed case IOCs from TheHive into MISP (X-25) | TheHive (Park, T5.4, target 2026-11-17) | Analyst-triggered responder in Cortex (D12), or TheHive's MISP connector (uses the license's single MISP-server slot) |
| 🕓 Sharing with external MISP communities | — | Needs the TLP/PAP policy first (Cortex backlog) |

## Known issue: large warninglists crash misp-core (R-14)

MISP enables a 1,000,000-entry warninglist (Cisco Umbrella top 1M) by default. With it on, **every warninglist check was killed for lack of memory** under misp-core's 900m limit, and enabling any list of that size did the same. **This also affects the current `main`**, so any fresh `intel` node has it until this work is merged. `misp-config.sh apply` fixes it by disabling lists above 100,000 entries (`maxEntries` in `misp-config.json`). The trade-off is that matches against the top-1M site lists and the big file-hash lists are lost; the top-50k site lists stay on. It **blocks C10** until merged and re-measured.

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | C10 is accepted; build `lib-misp-warninglist` (N8N-2.11) once R-13 and R-14 are in. Until then there is no warninglist check: the MISPWarningLists analyzer in Cortex doesn't work and is disabled (2026-10-01), so don't plan on it through C6. If C14's sync runs in n8n, it reuses C10's key. |
| **TheHive** (Park) | Later: sending confirmed IOCs to MISP (T5.4), and tag names (taxonomies). |
| **Wazuh** (Daniel) | C14 design together by 2026-10-16 (W6.1). |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | R-14 is fixed in this branch (checkpoint merge). R-13 for C10 after that. R-08 depends on the C14 design. |
