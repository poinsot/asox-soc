# Cortex backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. MISP has its own backlog: [nodes/intel/misp/BACKLOG.md](../../intel/misp/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for Cortex, so other owners can see where things stand and what to expect. Last updated: 2026-09-30, after the integration session (PROJECT.md 5, D44–D49; [docs/integration-backlog.md](../../../docs/integration-backlog.md)).

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

The baseline is done: Cortex runs and contracts C5, C6 and C7 pass. The current work is **turning the analyzer setup into code** (the first task in PROJECT.md 11.6) and **adding the online analyzers** that the n8n playbooks will use for enrichment (X-06, X-07). Both are due at checkpoint 1 (2026-10-20), because n8n's first slice (`pb-generic`) needs them.

## Decisions (2026-09-30)

| Decision | What it means for Cortex | Where it is recorded |
|---|---|---|
| **D-N3 confirmed** (X-17): n8n enriches automatically at intake through C6; analysts re-run analyzers by hand from TheHive through C5 | No double analysis. n8n is the only automatic caller; `n8n-enrichment.md` is written for that path | docs/decisions.md D-N3, n8n N8N-5.4, TheHive T4.1 |
| **C13 acknowledged** (D48): "seen before in Wazuh?" is a custom Cortex analyzer that calls n8n's read-only webhook `/webhook/wazuh-lookup` with its own token `N8N_LOOKUP_TOKEN`; n8n queries the Wazuh indexer | The analyzer holds **no Wazuh credential** and never reaches the indexer directly. It replaces TheHive's link B (T5.3) and serves both C5 and C6 | PROJECT.md 5 (C13), 15 (D48); X-26 |
| **C10 accepted** (D45): n8n → MISP warninglist check | Warninglist checks go through C10 only: there is no Cortex fallback (the MISPWarningLists analyzer is disabled, see "In progress"). Analysts see the result as n8n's tag on the observable | [MISP backlog](../../intel/misp/BACKLOG.md) |
| **C12 rejected** (D47) | Nothing for Cortex | PROJECT.md 15 |

## Dates

Aligned with the shared team dates (integration backlog, section F).

| Target | Date |
|---|---|
| Analyzers as code + online analyzers merged, `n8n-enrichment.md` delivered (X-06, X-07) | **2026-10-20** (checkpoint 1) |
| Written TLP/PAP policy (X-08), local analyzers | 2026-11-10 (v1.2) |
| C13 analyzer, if R-10, R-15 and R-16 are in | 2026-11-17 (v1.3) |
| Feature freeze / delivery | 2026-11-24 / 2026-12-01 |

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
| Analyzers as code: `analyzers/analyzers.json` + `analyzers/analyzers.sh apply / export / test` | 🔨 run against Cortex 2026-10-01 without keys: `apply` is idempotent, keyed analyzers are skipped, `export` round-trips unchanged; **`test` not yet exercised on a working analyzer** | `apply` enables the analyzers from the JSON file; `export` writes UI changes back to the file; `test` runs each analyzer on a sample value using n8n's API key. The MISP analyzer stays with `bootstrap.sh` (C7). |
| Online analyzers: AbuseIPDB, OTXQuery, URLhaus, MalwareBazaar, VirusTotal_GetReport | 🔨 defined in `analyzers.json`, **need API keys** | Keys go in `analyzers/analyzer-keys.env` (git-ignored, R-09; see the `.example`). Each person gets their own free keys. Analyzers without a key are skipped. Setting names checked against the Cortex catalog on 2026-10-01: all match (AbuseIPDB_2_0, OTXQuery_2_0, URLhaus_2_0, MalwareBazaar_1_0, VirusTotal_GetReport_3_1). These are the analyzers analysts see and run from TheHive (C5). |
| MISPWarningLists analyzer | ⛔ disabled (`"enabled": false`) | Tested 2026-10-01: the job fails with "wrong configuration settings". The catalog analyzer doesn't query our MISP; it needs its own copy of the `misp-warninglists` repository or a database inside the analyzer container, and the image has neither. Not needed: n8n checks MISP's warninglists directly (C10) and tags the observable in TheHive. |
| Data-sharing defaults on every analyzer | 🔨 | `max_tlp` / `max_pap` = 2 (AMBER): TLP:RED data is never sent to online services. TheHive defaults new alerts to TLP/PAP AMBER (T2.5), so analyzers can run. Job cache 10 min. Rate limits: AbuseIPDB 1000/day, VirusTotal 500/day (X-18). |
| n8n enrichment guide (`n8n-enrichment.md`) | 🔨 due 2026-10-20 | The deliverable for X-06 and X-07 (n8n's N8N-2.4 `lib-enrich-observable`): which Cortex calls to use, which analyzers per observable type with expected run time, how to reduce reports to a verdict, quotas, and the "common is not safe" rules for warninglist matches. |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ Run `apply` + `test` with real keys | My own API keys | Then merge at checkpoint 1 |
| ⏭️ Written TLP/PAP data-sharing policy (X-08) | — | What each TLP level may be sent to; n8n enforces it before running online analyzers (N8N-2.4, N8N-2.6). Today only the defaults above exist |
| ⏭️ Local analyzers: FileInfo, YARA, GeoIP (MaxMind) | MaxMind free key for GeoIP | No data leaves the lab |
| ⏭️ Re-measure Cortex memory with several analyzers running in parallel | — | Memory limits rule (PROJECT.md D40); each analyzer container is capped at 256 MiB. The last report already flags Cortex's limit (600 → 650). **2026-10-01: Cortex was OOM-killed at its 650m limit** (`standard`) during an `analyzers.sh` session (several catalog listings, one analyzer job, then disabling an analyzer); it restarted on its own and kept its configuration. To report to the integrator with a measurement (`CORTEX_MEM` is in `nodes/cases/.env.example`) |
| ⏭️ Load custom analyzers from `analyzers/` | Integrator (R-10, compose/config change) | Cortex has to read this folder as well as the online catalog. **Needed by C13** |
| ⏭️ C13 analyzer "seen before in Wazuh?" (`analyzers/`) | R-10; R-15 (token, bootstrap); R-16 (`n8n-indexer`); n8n's `recv-wazuh-lookup` (N8N-2.10); Wazuh field names (W2.5) | POSTs `{dataType, data, days}` to `${N8N_WEBHOOK_URL}/webhook/wazuh-lookup` with header `X-ASOX-Token`; answers count, first/last seen, top rules, agents, up to 10 alert IDs. Reaches n8n like MISP (A49). Check: wrong token → 403; `lab-agent` returns the C1 test alert |

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 Custom analyzer "asset owner lookup" | — | Source of asset data still open |
| 🕓 Responder: export confirmed IOCs from TheHive to MISP (X-25) | TheHive (Park, T5.4, target 2026-11-17) | Only analyst-triggered actions that don't change systems (D12); blocking or isolating stays in n8n. If done through TheHive's MISP connector instead, it uses the license's single MISP-server slot |

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | Read `n8n-enrichment.md` when it lands (by 2026-10-20). Your "Cortex API (n8n)" credential keeps working (C6 is unchanged); new analyzers show up in `GET /api/analyzer`. D-N3 is confirmed: you run enrichment at intake. C13 needs your `recv-wazuh-lookup` webhook (N8N-2.10). C10 is accepted (MISP backlog). |
| **TheHive** (Park) | New analyzers appear in TheHive through the Cortex connector (C5); nothing to configure. D-N3 confirmed (T4.1). T5.3 is now C13: my analyzer, nothing to build in TheHive. |
| **Wazuh** (Daniel) | C13 uses the field map in PROJECT.md 5 (`data.srcip`, `agent.name`, `data.srcuser`, `syscheck.sha256_after`…); please keep it stable (W2.5). MISP IOCs to CDB lists is C14 (MISP backlog). |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | R-09 (`.gitignore` line for `analyzer-keys.env`, in this branch's checkpoint PR). R-10 (custom analyzers folder) is needed before C13. R-15 (C13 token and bootstrap). |

## Notes

- `analyzers.sh` is run by hand after `soc.sh init` (it isn't part of `bootstrap.sh`), on the machine that hosts `cases`.
- The free VirusTotal key allows 4 lookups/min and 500/day, shared with anything else using the same key, so VirusTotal is meant for the severe path only.
- AbuseIPDB's `days: 30` in `analyzers.json` is the report lookback window (`maxAgeInDays`), not a time limit on the analyzer.
