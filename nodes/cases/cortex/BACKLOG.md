# Cortex backlog

Owner: Diego (@DiegoGuerraA00835430). Branch: `cortex-misp`. MISP has its own backlog: [nodes/intel/misp/BACKLOG.md](../../intel/misp/BACKLOG.md).

This file shows what is done, what is being worked on now, and what comes next for Cortex, so other owners can see where things stand and what to expect. Last updated: 2026-10-21, after merging `main` (up to PR #33) into `cortex-misp` (PROJECT.md 5; [docs/integration-backlog.md](../../../docs/integration-backlog.md)).

**Status:** ✅ done · 🔨 in progress (on `cortex-misp`, not merged into `main` yet) · ⏭️ next · 🕓 later · ⛔ blocked (waiting on someone)

## Where I am now

Analyzers as code are on `main` (PR #12). n8n's enrichment through C6 is built and runs `MISP_2_1` (N8N-2.4, merged 2026-10-13). It waits for two things from me. They were due at checkpoint 1 (2026-10-20) and are **overdue**: the handoff lists them as the only checkpoint item still missing, and n8n's online analyzers (N8N-2.4) wait on them:

- **`n8n-enrichment.md`**, which answers Inigo's 6 questions (`diego-enrichment-questions.md`, 2026-10-06);
- **the online analyzers' API keys.**

**Tested 2026-10-14** on a fresh `full` instance from `cortex-misp` (standard profile): C5, C6 and C7 pass. C7 finds the new seed IOC `101.99.75.184` (MISP backlog, X-36).

## Decisions

| Decision | What it means for Cortex | Where it is recorded |
|---|---|---|
| **D-N3 confirmed** (X-17): n8n enriches automatically at intake through C6; analysts re-run analyzers by hand from TheHive through C5 | No double analysis. n8n is the only automatic caller; `n8n-enrichment.md` is written for that path | docs/decisions.md D-N3, n8n N8N-5.4, TheHive T4.1 |
| **C13 acknowledged** (D48): "seen before in Wazuh?" is a custom Cortex analyzer that calls n8n's read-only webhook `/webhook/wazuh-lookup` with its own token `N8N_LOOKUP_TOKEN`; n8n queries the Wazuh indexer | The analyzer holds **no Wazuh credential** and never reaches the indexer directly. It replaces TheHive's link B (T5.3) and serves both C5 and C6 | PROJECT.md 5 (C13), 15 (D48); X-26 |
| **C10 live** (D45, 2026-10-13): n8n → MISP warninglist check | Warninglist checks go through C10 only: there is no Cortex fallback (the MISPWarningLists analyzer stays disabled). Analysts see the result on the observable in TheHive. A warninglisted value goes to local analyzers only (`skip_online_analyzers`) | [MISP backlog](../../intel/misp/BACKLOG.md) |
| **MISP hit = suspicious, `ioc: false`** (question 6 / E) | `MISP_2_1`'s own taxonomy level stands; the analyst marks the IOC after checking. TheHive agreed 2026-10-14; my confirmation goes in `n8n-enrichment.md` | `nodes/cases/thehive/docs/reply-n8n-2026-10-14.md` (E) |
| **C12 rejected** (D47) | Nothing for Cortex | PROJECT.md 15 |

## Dates

Aligned with the shared team dates (integration backlog, section F).

| Target | Date |
|---|---|
| `n8n-enrichment.md` delivered, online analyzers with keys (X-06, X-07). Questions 1 and 6 earlier if possible | **overdue** (was 2026-10-20, checkpoint 1) |
| Written TLP/PAP policy (X-08), local analyzers | 2026-11-10 (v1.2) |
| C13 analyzer, if R-10, R-15 and R-16 are in | 2026-11-17 (v1.3) |
| Feature freeze / delivery | 2026-11-24 / 2026-12-01 |

## Done

| Item | Notes |
|---|---|
| ✅ Cortex 4.1 on the shared Elasticsearch 8 | `compose.yml`; analyzers run as Docker containers |
| ✅ Org `SOC`, org admin, API users `thehive` and `n8n` | Created by `scripts/bootstrap.sh cases` |
| ✅ MISP analyzer `MISP_2_1` | Contract C7: finds the seed event in MISP (seed IOC `101.99.75.184` since 2026-10-14) |
| ✅ Contracts C5 (TheHive → Cortex), C6 (n8n → Cortex), C7 (Cortex → MISP) | `scripts/contracts-check.sh --only C5,C6,C7`; last passed 2026-10-14 (`full`) |
| ✅ Analyzers as code: `analyzers/analyzers.json` + `analyzers/analyzers.sh apply / export / test` (PR #12) | `apply` is idempotent, keyed analyzers without a key are skipped, `export` round-trips unchanged. **`test` not yet exercised on a working analyzer** (needs keys) |
| ✅ n8n's enrichment path through C6 (n8n's N8N-2.4, merged 2026-10-13) | `MISP_2_1` only; one job at a time, `force: false` (uses the 10-min cache). The online analyzers are defined in n8n but disabled until my doc and keys |

## In progress

| Item | Status | Notes |
|---|---|---|
| n8n enrichment guide (`n8n-enrichment.md`) | 🔨 overdue (was due 2026-10-20) | The deliverable for X-06 and X-07. **Answers Inigo's 6 questions** (`diego-enrichment-questions.md`): 1. analyzers per observable type (`ip`, `domain`, `fqdn`, `url`, `hash`, `filename`) with expected run time; 2. verdict overrides (e.g. AbuseIPDB confidence, VirusTotal engines); 3. quotas for OTX and abuse.ch, VirusTotal on Critical only?; 4. `max_tlp`/`max_pap` 2 as the interim policy, and `MISP_2_1`'s values; 5. drop `filename` (`syscheck.path`)?; 6. MISP hit = suspicious, `ioc: false` (TheHive agrees). Inigo asked for 1 and 6 first |
| Online analyzers: AbuseIPDB, OTXQuery, URLhaus, MalwareBazaar, VirusTotal_GetReport | 🔨 defined in `analyzers.json`, **need API keys** | Keys go in `analyzers/analyzer-keys.env` (git-ignored, R-09; see the `.example`). Each person gets their own free keys. Setting names checked against the Cortex catalog on 2026-10-01: all match (AbuseIPDB_2_0, OTXQuery_2_0, URLhaus_2_0, MalwareBazaar_1_0, VirusTotal_GetReport_3_1). These are the analyzers analysts see and run from TheHive (C5) |
| MISPWarningLists analyzer | ⛔ disabled (`"enabled": false`), not needed | Tested 2026-10-01: fails with "wrong configuration settings" (it needs its own copy of the lists). n8n checks MISP's warninglists directly (C10). ✅ My proposal (list names in the observable's description, one `warninglist` tag) was agreed by TheHive and applied by n8n (PR #29, 2026-10-15; [MISP request](../../intel/misp/request-n8n-warninglist-description.md)) |
| Data-sharing defaults on every analyzer | 🔨 | `max_tlp` / `max_pap` = 2 (AMBER): TLP:RED data is never sent to online services. TheHive defaults new alerts to TLP/PAP AMBER (T2.5). n8n enforces the same values until the written policy (X-08). Job cache 10 min. Rate limits: AbuseIPDB 1000/day, VirusTotal 500/day + 4/min (X-18) |

## Next

| Item | Depends on | Notes |
|---|---|---|
| ⏭️ Run `apply` + `test` with real keys | My own API keys | Then tell Inigo which analyzers to enable in n8n |
| ⏭️ **Send the 10-01 Cortex memory measurement (R-21)** | — | **Asked by the integrator 2026-10-06 and 2026-10-10.** 2026-10-01: Cortex was OOM-killed at its 650m limit (`standard`) during an `analyzers.sh` session; it restarted on its own and kept its configuration. n8n's light-load test (2026-10-06): 491 MiB of 650. Measure again with the online analyzers running in parallel (D40 method); it decides `CORTEX_MEM` in `render-env.sh` |
| ⏭️ Written TLP/PAP data-sharing policy (X-08) | — | What each TLP level may be sent to; n8n enforces it before running online analyzers (N8N-2.4, N8N-2.6). Also the rule Jev follows (C15, X-40) |
| ⏭️ Local analyzers: FileInfo, YARA, GeoIP (MaxMind) | MaxMind free key for GeoIP | No data leaves the lab |
| ⏭️ Load custom analyzers from `analyzers/` | Integrator (R-10, compose/config change) | Cortex has to read this folder as well as the online catalog. **Needed by C13** |
| ⏭️ C13 analyzer "seen before in Wazuh?" (`analyzers/`) | R-10; R-15 (token, bootstrap); R-16 (`n8n-indexer`); n8n's `recv-wazuh-lookup` (N8N-2.10); Wazuh field names (W2.5) | POSTs `{dataType, data, days}` to `${N8N_WEBHOOK_URL}/webhook/wazuh-lookup` with header `X-ASOX-Token`; answers count, first/last seen, top rules, agents, up to 10 alert IDs. Reaches n8n like MISP (A49). Check: wrong token → 403; `lab-agent` returns the C1 test alert |
| ⏭️ README: "first task" wording | — | `analyzers.sh` exists; the README still calls the export scripts the "first task" (register section G) |

## Later

| Item | Works with | Notes |
|---|---|---|
| 🕓 `intel-fields.json` and the TLP/PAP rule for Jev (C15, X-40, proposed) | n8n (Inigo) | Which report fields may leave the platform. Not asked formally yet; rides on X-08 |
| 🕓 Custom analyzer "asset owner lookup" | — | Source of asset data still open |
| 🕓 Responder: export confirmed IOCs from TheHive to MISP (X-25) | TheHive (Park, T5.4, target 2026-11-17) | Only analyst-triggered actions that don't change systems (D12); blocking or isolating stays in n8n. If done through TheHive's MISP connector instead, it uses the license's single MISP-server slot |

## For the other owners

| Owner | What changes for you |
|---|---|
| **n8n** (Inigo) | `n8n-enrichment.md` is late (was due 2026-10-20; questions 1 and 6 first), then the keys. Your "Cortex API (n8n)" credential keeps working (C6 is unchanged). C13 needs your `recv-wazuh-lookup` webhook (N8N-2.10). Web access log URLs (X-44) are path-only, so Cortex's URL analyzers can't use them: the enrichment doc will say so |
| **TheHive** (Park) | New analyzers appear in TheHive through the Cortex connector (C5); nothing to configure. Question E: agreed (suspicious, `ioc: false`). T5.3 is now C13: my analyzer, nothing to build in TheHive |
| **Wazuh** (Daniel) | C13 uses the field map in PROJECT.md 5 (`data.srcip`, `agent.name`, `data.srcuser`, `syscheck.sha256_after`…); please keep it stable (W2.5). C14: see the MISP backlog |
| **Grafana** (Jesus) | Nothing planned. |
| **Integrator** | R-21: my Cortex memory measurement, then `CORTEX_MEM`. R-10 (custom analyzers folder) before C13. R-15 (C13 token and bootstrap) |

## Notes

- `analyzers.sh` is run by hand after `soc.sh init` (it isn't part of `bootstrap.sh`), on the machine that hosts `cases`.
- The free VirusTotal key allows 4 lookups/min and 500/day, shared with anything else using the same key, so VirusTotal is meant for the severe path only.
- AbuseIPDB's `days: 30` in `analyzers.json` is the report lookback window (`maxAgeInDays`), not a time limit on the analyzer.
