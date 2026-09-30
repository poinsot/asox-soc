# Cortex backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. MISP has its own backlog: [nodes/intel/misp/BACKLOG.md](../../intel/misp/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for Cortex, so other owners can see where things stand and what to expect. Last updated: 2026-09-30.

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

The baseline is done: Cortex runs and contracts C5, C6 and C7 pass. The current work is **turning the analyzer setup into code** (the first task in PROJECT.md 11.6) and **adding the online analyzers** that the n8n playbooks will use for enrichment.

## Done (baseline, `v1.0-baseline`)

| Item | Notes |
|---|---|
| ✅ Cortex 4.1 on the shared Elasticsearch 8 | `compose.yml`; analyzers run as Docker containers |
| ✅ Org `SOC`, org admin, API users `thehive` and `n8n` | Created by `scripts/bootstrap.sh cases` |
| ✅ MISP analyzer `MISP_2_1` | Contract C7: finds the seed event in MISP |
| ✅ Contracts C5 (TheHive → Cortex), C6 (n8n → Cortex), C7 (Cortex → MISP) | `scripts/contracts-check.sh --only C5,C6,C7` |

## In progress

| Item | Status | Notes |
|---|---|---|
| Analyzers as code: `analyzers/analyzers.json` + `analyzers/analyzers.sh apply / export / test` | 🔨 written, shellcheck clean, **not yet run against Cortex** | `apply` enables the analyzers from the JSON file; `export` writes UI changes back to the file; `test` runs each analyzer on a sample value using n8n's API key. The MISP analyzer stays with `bootstrap.sh` (C7). |
| Online analyzers: AbuseIPDB, OTXQuery, URLhaus, MalwareBazaar, VirusTotal_GetReport | 🔨 defined in `analyzers.json`, **need API keys** | Keys go in `analyzers/analyzer-keys.env` (git-ignored; see the `.example`). Each person gets their own free keys. Analyzers without a key are skipped. The setting names come from pre-repo work and still need checking against the Cortex catalog. |
| MISPWarningLists analyzer (no key needed) | 🔨 | Tells n8n whether an indicator is *common* (public DNS, cloud ranges, top domains…). This works through the existing C6. |
| Data-sharing defaults on every analyzer | 🔨 | `max_tlp` / `max_pap` = 2 (AMBER): TLP:RED data is never sent to online services. Job cache 10 min. Rate limits: AbuseIPDB 1000/day, VirusTotal 500/day. |
| n8n enrichment guide (`n8n-enrichment.md`) | 🔨 | For the n8n owner: which Cortex calls to use, how to read verdicts, which analyzers per observable type, and the "common is not safe" rules for warninglist matches. |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ Verify the analyzer setting names, run `apply` + `test` with real keys | My own API keys | Then merge at a checkpoint |
| ⏭️ Written TLP/PAP data-sharing policy | — | What each TLP level may be sent to; today only the defaults above exist |
| ⏭️ Local analyzers: FileInfo, YARA, GeoIP (MaxMind) | MaxMind free key for GeoIP | No data leaves the lab |
| ⏭️ Re-measure Cortex memory with several analyzers running in parallel | — | Memory limits rule (PROJECT.md D40); each analyzer container is capped at 256 MiB |
| ⏭️ Load custom analyzers from `analyzers/` | Integrator review (compose/catalog change) | Cortex has to be told to read this folder as well as the online catalog |

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 Custom analyzer "seen before in Wazuh?" | Wazuh (Daniel) | Needs read access to the Wazuh indexer |
| 🕓 Custom analyzer "asset owner lookup" | — | Source of asset data still open |
| 🕓 Responder: export confirmed IOCs from TheHive to MISP | TheHive (Park) | Only analyst-triggered actions that don't change systems (D12); blocking or isolating stays in n8n |

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | Read `n8n-enrichment.md` when it lands. Your existing "Cortex API (n8n)" credential keeps working (C6 is unchanged); new analyzers simply show up in `GET /api/analyzer`. Direct warninglist checks against MISP are proposed as a new contract (C10) in the [MISP backlog](../../intel/misp/BACKLOG.md). |
| **TheHive** (Park) | New analyzers appear in TheHive automatically through the Cortex connector (C5). Nothing to configure. |
| **Wazuh** (Daniel) | Nothing yet. Later: the "seen before in Wazuh?" analyzer, and MISP IOCs pushed to Wazuh CDB lists (MISP backlog). |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | This branch adds one line to the root `.gitignore` (`nodes/cases/cortex/analyzers/analyzer-keys.env`), to review in the checkpoint PR. No contract changes. |

## Notes

- `analyzers.sh` is run by hand after `soc.sh init` (it isn't part of `bootstrap.sh`), on the machine that hosts `cases`.
- The free VirusTotal key allows 4 lookups/min and 500/day, shared with anything else using the same key, so VirusTotal is meant for the severe path only.
