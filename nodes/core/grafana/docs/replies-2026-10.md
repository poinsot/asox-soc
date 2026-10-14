# Grafana → integrator, n8n, Wazuh: replies before checkpoint 1 (2026-10)

**From:** Jesus (@JC-535), Grafana owner
**To:** Inigo (@poinsot), integrator and n8n owner; Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-14
**Refs:** C11 (D46), X-27, X-42, X-32, R-11, R-16, GRAF-0.6, GRAF-0.7, GRAF-2.2, GRAF-4.4, D-G3, integration backlog section F
**Status:** draft

The delivering tasks are in [BACKLOG.md](../BACKLOG.md).

## Reply tracker

| # | Ask (short) | From | Due | Grafana task | Status | Reply |
|---|---|---|---|---|---|---|
| 1 | Acknowledge C11 (the schema grew) | Integrator (X-27, X-42) | 2026-10-20 | GRAF-0.6 | answered | **Acknowledged**, with assumptions to confirm. See A1 |
| 2 | Confirm the team dates | Integrator (section F) | 2026-10-20 | GRAF-0.7 | answered | **Confirmed**; GRAF-3.1 depends on R-16, R-11 and N8N-2.9. See A2 |
| 3 | Attack-start marker: query and level 3 | Wazuh (`request-grafana-attack-start-marker.md`, item 1) | 2026-10-20 | GRAF-2.2 | answered | **Query works, level 3 accepted**; annotation built (`df3716e`). See A3 |

## Answers

**A1. C11 (D46): acknowledged by Grafana.**
- The schema and the MTTD/MTTA/MTTR definitions in PROJECT.md 5 cover GRAF-3.1 to 3.3.
- **Assumptions, to confirm with n8n (N8N-2.9):**
  - Panels use **`t_alert`** as the datasource time field (MTTA and MTTR are measured from it).
  - `severity` holds TheHive's values 1–4. Grafana maps them onto D-G4's buckets.
  - A false positive is `resolution: FalsePositive`. The FP rate is FalsePositive over closed alerts with a resolution.
  - MTTD is computed only on documents with `t_attack_start` (lab runs). Other alerts are left out, not counted as zero.
- Grafana excludes `outcome: contract-check` (the `chk-metrics` document) from every panel.
- Grafana's side: the datasource `provisioning/datasources/asox-metrics.yml` (GRAF-0.8), single index `asox-metrics`, `grafana-ro`, same URL and CA as C8. It goes in together with R-11, so its health check doesn't fail before the index exists.
- If the Jev fields (C16) change the template, I review them under C16, not as a new C11 acknowledgement (X-42).

**A2. Team dates: confirmed.**
- 2026-10-20 (checkpoint 1), 2026-11-24 (feature freeze), 2026-12-01 (delivery).
- Grafana targets are in BACKLOG.md "Dates": GRAF-2.1/2.2 by 10-20, D-G5 after D-N4 (11-03), GRAF-3.1 by 11-10, GRAF-3.2/3.3 and GRAF-4.1 by 11-17.
- **Dependency:** GRAF-3.1 by 11-10 only if **R-16, R-11** (integrator) and **N8N-2.9** (n8n) are in by then. None has a date yet: **please give one**, or "Desempeño y cumplimiento" ships empty on 12-01.

**A3. Attack-start marker (X-32, D-G3), Daniel's item 1.**
- Tested on 2026-10-14 with `nodes/lab/trigger.sh --scenario ssh-bruteforce` (run `c6643b64-de3a-40a3-ac44-3b9d379419aa`): marker 100101 at 01:44:01 UTC with `data.scenario` and `data.run_id`, then 5763 (level 10) two seconds later.
- The query `rule.id:100101` returns the marker through Grafana's `wazuh-indexer` datasource (C8, as `grafana-ro`).
- The annotation "Inicio de ataque (lab)" is on SOC Status (`df3716e`): time `timestamp`, text `data.scenario`, tags `data.run_id`. It doesn't apply `$min_level`.
- **Level 3: accepted.** The annotation doesn't depend on the level, and staying below C1's threshold keeps the marker out of n8n and TheHive.
- All six scenarios also checked on 2026-10-14, now on the dashboard "Attack Scenarios" (`asox-attack-scenarios`). One difference from `trigger.sh`'s table: **`new-user` fired 5902, 100211 and 40501 (level 15, a built-in correlation rule), not 5901.** Is 40501 expected? At level 15 it reaches n8n (C1) on every run of this scenario.
- Item 2 of the request (linking alerts to runs for C11) is for Inigo; Grafana is fine with either option, since the annotation doesn't need it.

## Notes for the integrator

- **Grafana memory (GRAF-4.4):** on 2026-10-14 Grafana reached 244 of 256 MiB (`GRAFANA_MEM=256m`) at 260–280 % CPU, with requests over 35 s and "Handler timeout" errors, with one dashboard open. After a restart it sits at 185–203 MiB idle, so there is little headroom. Please measure and consider raising `GRAFANA_MEM`.
- `docs/project-status.md` (lines 64 and 81) still says Wazuh hasn't acknowledged C11 and that there's no attack-start marker. Both changed on 2026-10-07 (W1.7, W1.6).
