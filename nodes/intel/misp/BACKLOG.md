# MISP backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. Cortex has its own backlog: [nodes/cases/cortex/BACKLOG.md](../../cases/cortex/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for MISP, so other owners can see where things stand and what to expect. Last updated: 2026-10-21, after merging `main` (up to PR #33) into `cortex-misp` (PROJECT.md 5; [docs/integration-backlog.md](../../../docs/integration-backlog.md)).

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

Warninglists, feeds and the C10 user are on `main` (PR #12); `bootstrap.sh intel` applies them (R-22). My C14 user, the new seed IOC and the warninglist description proposal are on `main` too (PR #22, 2026-10-14). Since then:

- **C10 is live** (2026-10-13, PR #17), now with list names in the observable's description and one `warninglist` tag (my proposal, agreed by TheHive and applied by n8n, PR #29).
- **C14 is live** (2026-10-15, PR #26): the Wazuh manager syncs MISP IOCs into its CDB lists with my user `wazuh@asox.local`, and `contracts-check.sh` checks it (A100). After a failed sync it retries every 60 s, up to 10 times (R-34, PR #31).
- **X-36 is done everywhere:** the seed IOC `101.99.75.184` is used by Wazuh's `ioc-ip` scenario, n8n's fixtures and TheHive's test alerts.

Open: the intel memory re-measure (overdue, was due 2026-10-20), Inigo's C10 settings questions, and housekeeping.

## Decisions

| Decision | What it means for MISP | Where it is recorded |
|---|---|---|
| **C10 accepted** (D45, 2026-09-30); **live** 2026-10-13 | n8n checks MISP's warninglists before creating a TheHive alert, with its own Read Only key | PROJECT.md 5 (C10), 15 (D45); X-31, R-13 |
| **C14, option a** (D50, agreed 2026-10-14); **live** 2026-10-15 (PR #26) | The sync runs inside the Wazuh manager with its own Read Only key; filter: published, `to_ids`, IP/domain/hash types, `enforceWarninglist`; 1 h, plus quick retries after a failure (R-34) | [C14-reply-wazuh.md](C14-reply-wazuh.md); PROJECT.md 5 (C14), 15 (D50); X-24, R-08, A100 |
| **X-36, option a** (2026-10-14) | Seed IOC moved out of the reserved ranges to `101.99.75.184` (Botvrij, Loki-Bot malspam), `to_ids: true` | [C14-reply-wazuh.md](C14-reply-wazuh.md) §2; X-36 |
| **Warninglist description** (answer G revised, 2026-10-14) | Observables get one `warninglist` tag; every matching list's name goes in the observable's description, no cap | `nodes/cases/thehive/docs/reply-n8n-misp-2026-10-14.md` §1; ALERT-FORMAT §5, §7 |
| **Suricata replaces Snort** (D49) | IOC export to the network IDS (later) targets Suricata | PROJECT.md 15 (D49); X-34 |

## Dates

Aligned with the shared team dates (integration backlog, section F).

| Target | Date |
|---|---|
| ~~C14 design agreed with Wazuh (Daniel)~~ | ✅ 2026-10-14 (target was 2026-10-16) |
| ~~`cortex-misp` merged (C14 user, seed IOC)~~ | ✅ 2026-10-14 (PR #22) |
| Intel re-measured (warninglists, Botvrij, C14) | **overdue** (was 2026-10-20, checkpoint 1) |
| ~~C10 live, with the n8n owner (N8N-2.11)~~ | ✅ 2026-10-13 (target was 2026-11-10) |
| Feature freeze / delivery | 2026-11-24 / 2026-12-01 |

## Done

| Item | Notes |
|---|---|
| ✅ MISP 2.5.47 (core, nginx, modules, MariaDB, Valkey) | `compose.yml`; HTTPS on 9443 with a self-signed certificate |
| ✅ Read Only user `cortex@asox.local` + API key | Used by Cortex's MISP analyzer (C7) |
| ✅ Seed event (C7) | `seed/seed-event.json`. Was `203.0.113.66`; replaced 2026-10-14 by `101.99.75.184` (below) |
| ✅ `misp-config.sh apply / fetch / export` + `misp-config.json` (PR #12) | Since 2026-10-10 `bootstrap.sh intel` runs `apply` (R-22). Run it by hand only after changing `misp-config.json` |
| ✅ Warninglists: every list with ≤ 100,000 entries enabled (215 of 225), larger ones disabled | R-14's fix (see "Known issue" below). Checked: `8.8.8.8` → public DNS resolvers, `10.0.0.5` → RFC 1918, `185.220.101.1` → Tor exit nodes, `github.com` → top-site lists |
| ✅ Feed "The Botvrij.eu Data" enabled | 435 events (~29k attributes); gives Cortex's MISP analyzer real indicators to find |
| ✅ Read Only role can call `POST /warninglists/checkValue` | Verified 2026-10-01; a write gets 403. C10 needs no custom role |
| ✅ C10: Read Only user `n8n@asox.local` + `MISP_N8N_API_KEY` | Created by `apply`. C10 live on `main` 2026-10-13 (PR #17). Batch `checkValue` measured by Inigo 2026-10-10: misp-core 388 → 553 MiB of 900m, no OOM kill |
| ✅ C14: Read Only user `wazuh@asox.local` + `MISP_WAZUH_API_KEY` (PR #22) | `misp-config.json` `wazuh.user`; created by `apply`, key in `nodes/intel/.env` (`__bootstrap__` in `.env.example`, R-32). `apply` checks that C14's filter returns the seed IOC and that a write gets 403. Core's side: R-08, mapped in Wazuh's compose (PR #26) |
| ✅ C14 design answer to Daniel (PR #22) | [C14-reply-wazuh.md](C14-reply-wazuh.md): option a, the filter (plus `enforceWarninglist`, paging), 1 h interval, no `tlp:red` or age exclusion for now |
| ✅ C14 live (Wazuh, PR #26, 2026-10-15) | Built instance: 4,466 IOCs synced (misp-ip 373, misp-domain 915, misp-hash 3,121); `ioc-ip` → rule 108000 → TheHive alert with `ioc-match`. `contracts-check.sh --only C14` checks it (A100). Quick retries after a failed sync (R-34, PR #31): on a cold `soc.sh up full` the lists fill within ~1–10 min |
| ✅ X-36: new seed IOC `101.99.75.184`, `to_ids: true` (PR #22) | `apply` fails if the seed IOC is ever on an enabled warninglist, and deletes older seed events (tag `asox:seed`, other title) once the new one exists. Fixtures updated by Daniel (PR #26), Inigo (PR #23) and Park (PR #27) |
| ✅ C10 presentation: list names in the observable's description, a single `warninglist` tag | [request-n8n-warninglist-description.md](request-n8n-warninglist-description.md). Agreed by Park (answer G revised, PR #27), applied by Inigo (PR #29) |

## In progress

| Item | Status | Notes |
|---|---|---|
| Housekeeping | 🔨 | Done: `misp-config.sh` header no longer says "run by hand" (R-22); README lists `misp-config.*` and the contract notes. Still to do: README "Snort" → Suricata (D49); mark `C10-handoff-n8n.md` and `request-n8n-warninglist-description.md` done |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ **Re-measure intel memory** with the warninglists, Botvrij and C14 on, on `standard` and `low` | — | **Overdue** (was due 2026-10-20). Memory limits rule (PROJECT.md D40). Batch `checkValue` is measured (Done). Still to measure: `apply` + a feed fetch on `low`, and C14's paged `restSearch` (live since PR #26). Daniel saw misp-core at its 900m limit during the Botvrij import (Wazuh README, C14); my 2026-10-10 anon peak was 488 MiB, so it is probably page cache: check `anon` in `memory.stat` and `memory.events` for `oom_kill` |
| ⏭️ Scheduled feed refresh (daily) | Check the misp-core image's cron settings | Today feeds refresh only with `misp-config.sh fetch`. Also sets how fresh C14's lists can be |
| ⏭️ Turn on CIRCL OSINT | The re-measure above | Also grows `intel` backups and C14's lists |
| ⏭️ Answer Inigo's C10 settings questions (2026-10-10) | — | `skip_online_analyzers: true`; `prefer` order (top-site lists?); `8.8.8.8` and `185.220.101.1` on the vpn-ipv4 list (expected: it covers datacenter ranges) |
| ⏭️ Choose which taxonomies and galaxies to use | TheHive (Park) for tag names | Tags that show up on cases |
| ⏭️ Export/import of more MISP settings (beyond feeds and warninglists) | — | So UI changes reach git (PROJECT.md 11.2) |

## Contract C10: n8n → MISP warninglist check

✅ **Live on `main` since 2026-10-13** (PR #17; accepted 2026-09-30, D45). Full text in PROJECT.md 5.

- **What:** before creating the TheHive alert, n8n sends all of an alert's eligible observables to MISP in one call (`POST /warninglists/checkValue`) and learns which ones are *common* (public DNS, cloud and CDN ranges, top sites, private ranges…). A match means *common*, **not** *safe*: attackers use Google, GitHub and AWS too. n8n tags the observable and skips quota-limited online analyzers for it, but never closes, suppresses or downgrades an alert because of it (D12). MISP unreachable = n8n continues without it.
- **Why direct and not through Cortex:** one call for all observables, and it always uses MISP's current lists. The catalog's MISPWarningLists analyzer doesn't query MISP and fails without its own copy of the lists (tested 2026-10-01, disabled; Cortex backlog).
- **Built:** MISP (me): the Read Only user `n8n@asox.local` and its key, applied by `bootstrap.sh intel` (R-22). Integrator (R-13): env, credential "MISP API (n8n)", C10 in `contracts-check.sh`. n8n (Inigo): `chk-misp-api`, `lib-misp-warninglist` (N8N-2.11). Handoff: [C10-handoff-n8n.md](C10-handoff-n8n.md).
- **Presentation (since PR #29, 2026-10-15):** a single `warninglist` tag, with every list's name in the observable's description under "On MISP warninglists (common, not safe):"; kept when the alert is promoted to a case.

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 MISP IOCs to Suricata (Phase 2, D49) | Wazuh (Daniel) | C14 to Wazuh's CDB lists is done (above) |
| 🕓 Decaying models (old IOCs lose weight) | — | Matters most for IPs from older feed events; the alternative to a fixed age cutoff in C14's filter |
| 🕓 Confirmed case IOCs from TheHive into MISP (X-25) | TheHive (Park, T5.4, target 2026-11-17) | Analyst-triggered responder in Cortex (D12), or TheHive's MISP connector (uses the license's single MISP-server slot) |
| 🕓 Sharing with external MISP communities | — | Needs the TLP/PAP policy first (Cortex backlog) |

## Known issue: large warninglists crash misp-core (R-14)

MISP enables a 1,000,000-entry warninglist (Cisco Umbrella top 1M) by default. With it on, **every warninglist check was killed for lack of memory** under misp-core's 900m limit. `misp-config.sh apply` disables lists above 100,000 entries (`maxEntries` in `misp-config.json`). That's merged (PR #12), and `bootstrap.sh intel` applies it (R-22). The trade-off: matches against the top-1M site lists and the big file-hash lists are lost; the top-50k site lists stay on. An `intel` initialised before 2026-10-10 keeps MISP's default until its owner pulls `main` and runs `scripts/bootstrap.sh intel` once (R-23).

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | Nothing new. Your C10 settings questions are under Next |
| **TheHive** (Park) | Nothing new. Later: confirmed IOCs to MISP (T5.4), tag names (taxonomies) |
| **Wazuh** (Daniel) | Nothing new. If misp-core's memory during the Botvrij import was more than page cache (an `oom_kill` in `memory.events`), tell me: it goes into my re-measure |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | Nothing new. The intel re-measure may change `MISP_CORE_MEM` |
