# MISP backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. Cortex has its own backlog: [nodes/cases/cortex/BACKLOG.md](../../cases/cortex/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for MISP, so other owners can see where things stand and what to expect. Last updated: 2026-10-14, after merging `main` (PR #19) into `cortex-misp` and a fresh `full` run (PROJECT.md 5; [docs/integration-backlog.md](../../../docs/integration-backlog.md)).

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

Warninglists, feeds and the C10 user are on `main` (PR #12). `bootstrap.sh intel` applies them (R-22), and **C10 is live** (2026-10-13, PR #17). The current work, on `cortex-misp` and not merged yet, is:

- **C14 (MISP → Wazuh CDB lists):** my answer to Daniel's design ([C14-reply-wazuh.md](C14-reply-wazuh.md)) and the Read Only user `wazuh@asox.local`.
- **X-36:** a new seed IOC that is on no warninglist (`101.99.75.184`).
- **A presentation change for C10**, proposed to n8n: list names in the observable's description instead of one tag per list ([request-n8n-warninglist-description.md](request-n8n-warninglist-description.md)).

**Tested 2026-10-14** on a fresh `full` instance (standard profile, WSL 15.6 GiB) from `cortex-misp`: `soc.sh init full` passes, and so do C1–C8 and C10.

## Decisions

| Decision | What it means for MISP | Where it is recorded |
|---|---|---|
| **C10 accepted** (D45, 2026-09-30); **live** 2026-10-13 | n8n checks MISP's warninglists before creating a TheHive alert, with its own Read Only key | PROJECT.md 5 (C10), 15 (D45); X-31, R-13 |
| **C14, option a** (my answer 2026-10-14, waiting for Daniel's OK) | The sync runs inside the Wazuh manager with its own Read Only key; filter: published, `to_ids`, IP/domain/hash types, `enforceWarninglist`; 1 h | [C14-reply-wazuh.md](C14-reply-wazuh.md); X-24, R-08 |
| **X-36, option a** (2026-10-14, Inigo's preference) | Seed IOC moved out of the reserved ranges to `101.99.75.184` (Botvrij, Loki-Bot malspam), `to_ids: true` | [C14-reply-wazuh.md](C14-reply-wazuh.md) §2; X-36 |
| **Suricata replaces Snort** (D49) | IOC export to the network IDS (later) targets Suricata | PROJECT.md 15 (D49); X-34 |

## Dates

Aligned with the shared team dates (integration backlog, section F).

| Target | Date |
|---|---|
| C14 design agreed with Wazuh (Daniel) | **2026-10-16** (answered 2026-10-14) |
| `cortex-misp` merged (C14 user, seed IOC), intel re-measured | **2026-10-20** (checkpoint 1) |
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

## In progress (on `cortex-misp`, tested 2026-10-14, not merged yet)

| Item | Status | Notes |
|---|---|---|
| C14: Read Only user `wazuh@asox.local` + `MISP_WAZUH_API_KEY` | 🔨 tested | `misp-config.json` `wazuh.user`; created by `apply`, key in `nodes/intel/.env` (`__bootstrap__` in `.env.example`). `apply` checks that C14's filter returns the seed IOC and that a write gets 403. Core's side is R-08 (integrator: `WAZUH_MISP_API_KEY=__from:intel__`) |
| C14 design answer to Daniel | 🔨 sent for review | [C14-reply-wazuh.md](C14-reply-wazuh.md): option a, the filter (plus `enforceWarninglist`, paging), 1 h interval, no `tlp:red` or age exclusion for now |
| X-36: new seed IOC `101.99.75.184`, `to_ids: true` | 🔨 tested | `apply` fails if the seed IOC is ever on an enabled warninglist, and deletes older seed events (tag `asox:seed`, other title) once the new one exists. First pick `61.4.102.97` was on the vpn-ipv4 datacenter list: caught by that check. **Others update their fixtures:** Daniel (`trigger.sh` `ioc-ip`, `lab-scenarios.cases`), Inigo (`100100-misp-hit.json`), Park (`thehive-test-alert.sh`) |
| C10 presentation: list names in the observable's description, a single `warninglist` tag | 🔨 proposed to Inigo, cc Park | [request-n8n-warninglist-description.md](request-n8n-warninglist-description.md). Tested on my instance by patching n8n's workflows locally; **those n8n files aren't mine: not to be committed from this branch**. Changes question G's answer (TheHive) |
| Housekeeping | 🔨 | `misp-config.sh` header no longer says "run by hand" (R-22); README lists `misp-config.*` and the contract notes. Still to do: README "Snort" → Suricata (D49); `C10-handoff-n8n.md` marked done |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ Re-measure intel memory with the warninglists and Botvrij on, on `standard` and `low` | — | Memory limits rule (PROJECT.md D40). Batch `checkValue` is measured (Done). Still to measure: `apply` + a feed fetch on `low`, and C14's paged `restSearch` once Wazuh's sync exists |
| ⏭️ Scheduled feed refresh (daily) | Check the misp-core image's cron settings | Today feeds refresh only with `misp-config.sh fetch`. Also sets how fresh C14's lists can be |
| ⏭️ Turn on CIRCL OSINT | The re-measure above | Also grows `intel` backups |
| ⏭️ Answer Inigo's C10 settings questions (2026-10-10) | — | `skip_online_analyzers: true`; `prefer` order (top-site lists?); `8.8.8.8` and `185.220.101.1` on the vpn-ipv4 list (expected: it covers datacenter ranges) |
| ⏭️ Choose which taxonomies and galaxies to use | TheHive (Park) for tag names | Tags that show up on cases |
| ⏭️ Export/import of more MISP settings (beyond feeds and warninglists) | — | So UI changes reach git (PROJECT.md 11.2) |

## Contract C10: n8n → MISP warninglist check

✅ **Live on `main` since 2026-10-13** (PR #17; accepted 2026-09-30, D45). Full text in PROJECT.md 5.

- **What:** before creating the TheHive alert, n8n sends all of an alert's eligible observables to MISP in one call (`POST /warninglists/checkValue`) and learns which ones are *common* (public DNS, cloud and CDN ranges, top sites, private ranges…). A match means *common*, **not** *safe*: attackers use Google, GitHub and AWS too. n8n tags the observable and skips quota-limited online analyzers for it, but never closes, suppresses or downgrades an alert because of it (D12). MISP unreachable = n8n continues without it.
- **Why direct and not through Cortex:** one call for all observables, and it always uses MISP's current lists. The catalog's MISPWarningLists analyzer doesn't query MISP and fails without its own copy of the lists (tested 2026-10-01, disabled; Cortex backlog).
- **Built:** MISP (me): the Read Only user `n8n@asox.local` and its key, applied by `bootstrap.sh intel` (R-22). Integrator (R-13): env, credential "MISP API (n8n)", C10 in `contracts-check.sh`. n8n (Inigo): `chk-misp-api`, `lib-misp-warninglist` (N8N-2.11). Handoff: [C10-handoff-n8n.md](C10-handoff-n8n.md).
- **Proposed 2026-10-14:** a single `warninglist` tag, with every list's name in the observable's description (see In progress).

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 C14 build: MISP IOCs pushed into Wazuh CDB lists for proactive detection | Wazuh (Daniel, W6.2–W6.5, M6 2026-11-20) | After Daniel agrees to the design. Later also to Suricata (Phase 2, D49) |
| 🕓 Decaying models (old IOCs lose weight) | — | Matters most for IPs from older feed events; the alternative to a fixed age cutoff in C14's filter |
| 🕓 Confirmed case IOCs from TheHive into MISP (X-25) | TheHive (Park, T5.4, target 2026-11-17) | Analyst-triggered responder in Cortex (D12), or TheHive's MISP connector (uses the license's single MISP-server slot) |
| 🕓 Sharing with external MISP communities | — | Needs the TLP/PAP policy first (Cortex backlog) |

## Known issue: large warninglists crash misp-core (R-14)

MISP enables a 1,000,000-entry warninglist (Cisco Umbrella top 1M) by default. With it on, **every warninglist check was killed for lack of memory** under misp-core's 900m limit. `misp-config.sh apply` disables lists above 100,000 entries (`maxEntries` in `misp-config.json`). That's merged (PR #12), and `bootstrap.sh intel` applies it (R-22). The trade-off: matches against the top-1M site lists and the big file-hash lists are lost; the top-50k site lists stay on. An `intel` initialised before 2026-10-10 keeps MISP's default until its owner pulls `main` and runs `scripts/bootstrap.sh intel` once (R-23).

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | New seed IOC `101.99.75.184`: update `synthetic/100100-misp-hit.json` (X-36). Proposal for C10's presentation: [request-n8n-warninglist-description.md](request-n8n-warninglist-description.md). Your C10 settings questions are under Next |
| **TheHive** (Park) | Your question E answer (MISP hit = suspicious, `ioc: false`) is fine with me. New seed IOC: `thehive-test-alert.sh` (3 scenarios). Question G would change if Inigo takes the proposal above. Later: confirmed IOCs to MISP (T5.4), tag names (taxonomies) |
| **Wazuh** (Daniel) | C14 answer: [C14-reply-wazuh.md](C14-reply-wazuh.md) (due 2026-10-16). New seed IOC for `ioc-ip`, now `to_ids: true` |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | R-08: `WAZUH_MISP_API_KEY=__from:intel__` (from `MISP_WAZUH_API_KEY`) in `nodes/core/.env.example`. X-36 decided (option a) |
