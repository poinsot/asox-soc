# Grafana (Dashboard analítico) backlog: base draft

IDs use the prefix `GRAF-` so other backlogs and `docs/integration-backlog.md` can reference them.

Owner: Jesus (@JC-535). Branch: `grafana`. Node: `core`. Run mode: `core`.

Based on PROJECT.md (v2.1), docs/decisions.md, docs/handoff.md, CHECKLIST.md, CONTRIBUTING.md, `nodes/core/grafana/README.md` and the component READMEs (Wazuh, n8n, TheHive, Cortex + MISP). This is a base draft to refine, and to compare against the other owners' backlogs (Wazuh, n8n, TheHive, Cortex + MISP).

**Updated 2026-10-13** after merging `main` (PR #17) into `grafana`, against PROJECT.md v2.2 (C11, D46), `docs/integration-backlog.md` (X-27, X-32, X-42, R-11, R-16) and Wazuh's `request-grafana-attack-start-marker.md`.

**Caveats**
- The docs may lag behind the repo; teammates may already have pushed changes.
- Sizes are rough guesses: S ≤ 1 day, M 2–4 days, L > 4 days.
- KPI names and thresholds here are a proposal, not yet agreed with the other owners.
- Several items below are blocked on **n8n's own open decisions** (D-N2, D-N4), not on anything Grafana controls. Tracked, not duplicated, here.

## Three risks to check first

1. **Grafana only has `wazuh-alerts-*` today (C8), read-only.** The contract for everything else now exists on paper: **C11** (`asox-metrics`, D46), acknowledged by n8n and Wazuh (2026-10-07), **Grafana's acknowledgement still owed** (GRAF-0.6). It is not built: it waits on R-16 (`n8n-indexer`, index template), R-11 (`grafana-ro` read) and N8N-2.9 (the writer), none with a date. Until then "Desempeño y cumplimiento" is an empty shell, and the integration backlog flags it against 2026-12-01. Our acknowledgement also gates C16 (X-42).
2. **One agent (`lab-agent`), few rules.** Since Wazuh PRs #15/#16 (2026-10-07/08) there are custom detections (`1002-linux-auth`: 100200, 100211), the attack-start rule 100101 and six lab scenarios (`nodes/lab/trigger.sh --scenario`), so E1 and E2 panels can be validated with repeatable data. Breakdowns by endpoint still show one bucket until Phase 2 adds endpoints.
3. **D-N4 (n8n/TheHive) is still open, due 2026-11-03: n8n will auto-create a case only for *Critical* alerts of named playbooks, not every relevant alert.** This shrinks what "% alertas con caso automático" and MTTA can mean — most alerts will only get a case if an analyst promotes it by hand, so a naive count would understate n8n's real coverage. GRAF-3.x panels need to scope their denominator to Critical alerts specifically, and that scoping itself isn't final until D-N4 closes.

## Item format

`ID | Item | Priority | Size | Meets with / depends on`. Contract impact is stated explicitly where it exists.

## E0: Foundations and decisions

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-0.1 | ~~Confirm every field these dashboards rely on (`rule.level`, `agent.id/name`, `rule.description`, `data.srcip`, `rule.groups`, `data.dstuser`, `rule.mitre.tactic`, `rule.hipaa`) actually exists in the live index, via the panel field explorer~~ Done 2026-10-05 (see E1 status) | P0 | S | Wazuh |
| GRAF-0.2 | Adopt `$min_level` (already used by `soc-overview.json`) as the standard template variable on every new panel | P1 | S | none |
| GRAF-0.3 | Record decisions D-G1…D-G5 (below) in `docs/decisions.md`. **D-G1 to D-G4 are recorded**; D-G5 waits on D-N4 (2026-11-03) | P0 | S | All |
| GRAF-0.4 | ~~Propose the `asox-metrics` contract to n8n~~ Done: accepted as **C11** (D46, 2026-09-30), schema completed with `t_event`, `t_ack`, `severity`, `resolution`, `t_attack_start` (PROJECT.md 5). n8n's side moved from N8N-9.3 to **N8N-2.9** (X-28). Follow-up in GRAF-0.6 and GRAF-0.8 | P1 | M | n8n (Inigo) |
| GRAF-0.6 | **Acknowledge C11** (X-27, X-42) in `docs/integration-backlog.md`: check that the schema and the MTTD/MTTA/MTTR definitions in PROJECT.md 5 cover GRAF-3.1–3.3 (time field for panels, `severity` values, `resolution` values for the false-positive rate), raise any change with Inigo before acknowledging. **By 2026-10-20** | P0 | S | n8n, Wazuh, integrator |
| GRAF-0.7 | **Confirm the team dates** (integration backlog, section F): checkpoint 1 2026-10-20, feature freeze 2026-11-24, delivery 2026-12-01, with the "Dates" table below. **By 2026-10-20**, or checkpoint 1 slips for everyone | P0 | S | Integrator |
| GRAF-0.8 | **Done 2026-10-20:** health OK, `contracts-check.sh` C11 reads back through it. `provisioning/datasources/asox-metrics.yml`: OpenSearch datasource (uid `asox-metrics`), same URL, CA and `grafana-ro` credentials as `wazuh-indexer.yml`, single index `asox-metrics` (not a daily pattern), time field `t_alert`. Its health check fails until R-16 creates the index and R-11 grants read: add it with R-11, or ask the integrator whether a failing datasource is acceptable before then. Every C11 panel excludes `outcome:contract-check` (the `chk-metrics` document) | P1 | S | Integrator (R-11, R-16) |
| GRAF-0.5 | Naming convention for panels and dashboards (title, uid stability, folder) so exports stay reviewable in `git diff` | P1 | S | none |

## E1: Dashboard "Estado del SOC" — Nivel 1, `wazuh-alerts-*` only

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-1.1 | Stat panels: alerts 24h (+ trend), critical (≥12) / high (10–11), active endpoints (15 min override) | P0 | S | none |
| GRAF-1.2 | Severity distribution (4 range queries as one bar chart) | P0 | S | none |
| GRAF-1.3 | Top rules and top endpoints (Terms on `rule.id` + `rule.description` / `agent.name`; plain `keyword` fields, no `.keyword` subfield) | P0 | S | Wazuh (more rules/agents needed to validate) |
| GRAF-1.4 | Top source IPs table | P0 | S | none |
| GRAF-1.5 | Failed authentications over time + top targeted users (`rule.groups:authentication_failed`, `data.dstuser`) | P1 | M | Wazuh (rule must exist) |
| GRAF-1.6 | FIM spikes (`rule.groups:syscheck`) | P1 | S | Wazuh (rule must exist) |
| GRAF-1.7 | Alerts by MITRE tactic and by HIPAA control | P1 | M | Wazuh (rules must tag `rule.mitre` / `rule.hipaa`) |

**Status (2026-10-05):** GRAF-1.1 to 1.7 built in `provisioning/dashboards/soc-status.json` ("SOC Status", uid `asox-soc-status`), every panel on `$min_level` except "Active endpoints" (activity of any level). Fields checked against the live index mapping and with queries through Grafana as `grafana-ro` (GRAF-0.1):
- All fields exist; strings are plain `keyword` (no `.keyword` subfield), `rule.level` is `long`.
- sshd failed logins put the user in `data.srcuser` (invalid user, rule 5710) or `data.dstuser` (valid user, 5760), Windows in `data.win.eventdata.targetUserName`: "Top targeted users" merges the three. "Top source IPs" merges `data.srcip` and Suricata's `data.src_ip` (X-34).
- Failed authentications = groups `authentication_failed` / `win_authentication_failed`; brute-force correlation alerts (`authentication_failures`) are a separate series so they aren't double counted.
- "Active endpoints" counts agents with an alert in the last 15 min (manager 000 excluded): agent connection state isn't in the indexer.
- The OpenSearch plugin (2.34.4) returns nothing for a `filters` bucket alone; severity buckets use `filters` + `date_histogram`, reduced in the panel.
- Validated with lab data only: sshd failures and a FIM change written on the lab agent, plus `trigger.sh`. Real breakdowns still wait on Wazuh's rules (risk 2).

## E2: Dashboard "Escenarios de ataque"

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-2.1 | Per-scenario panel: KPI + sparkline per lab scenario of `nodes/lab/trigger.sh --scenario` (Wazuh W1.5): `ssh-bruteforce` (5763), `ssh-success-after-fail` (5763 → 40112), `sudo-fail` (5404), `new-user` (5901/5902 → 100211), `ioc-ip` (5712), `root-login` (100200). A run's alerts carry `asox_run=<uuid>` in `full_log`. AD brute force and phishing + ransomware stay for Phase 2 (Windows endpoints). **Target 2026-10-20** | P0 | M | Wazuh |
| GRAF-2.2 | Attack-start annotation (D-G3, X-32). **Wazuh's side is built** (W1.6): rule **100101**, level 3, groups `asox,test,attack_start`, fields `data.scenario`, `data.run_id`. Grafana's side: annotation on "Escenarios de ataque" (and optional on "SOC Status") from the `wazuh-indexer` datasource, query `rule.id:100101`, text `data.scenario`, tag `data.run_id`; it must **not** use `$min_level`, since level 3 is under any useful threshold. Then answer Daniel's `request-grafana-attack-start-marker.md` (query works, level 3 accepted or not). **By 2026-10-20** | P1 | M | Wazuh (rule owner), Lab scripts |
| GRAF-2.3 | Escaneo de red / DDoS panels | P2 | M | Wazuh + Snort or OPNsense (Phase 2, not built yet) |
| GRAF-2.4 | Full simulacro timeline (ataque → detección → alerta → respuesta → caso), one row per stage. **Note:** for playbooks that require analyst approval (D-N5, task-based in TheHive), the "respuesta" stage includes human wait time — split "MTTR automatizado" from "MTTR con aprobación" or the metric misrepresents n8n's own speed | P2 | M | n8n, TheHive (needs GRAF-0.4) |

**Status (2026-10-14):** GRAF-2.1 and GRAF-2.2 built and checked with all six lab scenarios (one run each, two of `ssh-bruteforce`):
- `provisioning/dashboards/attack-scenarios.json` ("Attack Scenarios", uid `asox-attack-scenarios`): one stat + sparkline per scenario on the rule IDs it fires, detections over time by scenario, runs per scenario and recent runs (time, scenario, run ID, agent) from the markers. No `$min_level`: each panel is fixed to its rules.
- Annotation "Inicio de ataque (lab)" (`rule.id:100101`, text `data.scenario`, tags `data.run_id`) on this dashboard and on SOC Status. Answer to Wazuh in `docs/replies-2026-10.md` (A3).
- The detection panels count every alert of those rules, real or lab: the runs table and the markers say which ones came from a run.
- `new-user` fired 5902, 100211 and **40501 (level 15)**, not 5901 as `trigger.sh` says. Raised with Wazuh (replies, A3). Wazuh: expected (40501 replaces 5901 or 5902 after other scenarios). **2026-10-20:** kept, in its own panel "Attack followed by new account (40501)" (row Correlations; replies, A5).

## E3: Dashboard "Desempeño y cumplimiento" — Nivel 2/3

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-3.1 | **Drafted 2026-10-20** in `performance.json` against `tests/metrics-sample.sh` documents; to validate with real data (`cases` running, or the build instance). MTTD / MTTA / MTTR stat panels reading `asox-metrics` (C11 definitions: MTTD = `t_event − t_attack_start`, lab runs only; MTTA = `t_ack − t_alert`; MTTR = `t_contained`, else `t_closed`, `− t_alert`). Can be drafted against a hand-written test document in a scratch index; wired once R-16, R-11 and N8N-2.9 are in. **Target 2026-11-10 if they are** | P1 | M | n8n (N8N-2.9), integrator (R-16, R-11) |
| GRAF-3.2 | **Partial 2026-10-20:** FP rate, closed alerts by resolution, open/closed alerts by severity in `performance.json`; the auto/analyst split waits on D-N4. Open/closed cases by severity, false-positive rate. **Scope per D-N4:** report "cases from auto-promotion" and "cases from analyst promotion" as separate series, not one blended count, since only Critical alerts auto-promote | P1 | M | TheHive, n8n |
| GRAF-3.3 | Playbooks executed (success/fail/reverted), **% of Critical alerts with auto-ticket** (not % of all alerts — rename the KPI to match D-N4's actual scope once it closes) | P1 | S | n8n |
| GRAF-3.4 | Anomalous-alert count and top hosts/users by score | P2 | S | IA team (needs a published index/field) |
| GRAF-3.5 | Priority queue panel (alerts ordered by model score) | P2 | S | IA team |
| GRAF-3.6 | Phishing classifier precision/recall as static stat panels from its evaluation report | P2 | S | IA team |

## E4: Alerting and ops

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-4.1 | Grafana alert rules (`provisioning/alerting/`): critical alert spike, endpoint silent > 15 min | P1 | M | none |
| GRAF-4.2 | Document the daily index-pattern caveat (`[wazuh-alerts-4.x-]YYYY.MM.DD`) so no one wildcards it back and breaks the datasource health check (D35) | P1 | S | none |
| GRAF-4.3 | Admin password rotation doc (`grafana cli admin reset-admin-password`) for when a machine's `.env` and Grafana's stored password ever drift apart | P2 | S | none |
| GRAF-4.4 | Re-measure memory after any Grafana version bump per the pinning note (D34) before moving off 12.4.x. No Postgres-profile interaction to worry about here: n8n is staying on SQLite (D-N6, decided) | P2 | S | Integrator |

## E5: Phase 3 readiness

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-5.1 | Grafana alert → n8n webhook, if the team wants Grafana-triggered playbooks | P2 | S | n8n |

## Where Grafana meets the other owners

| Owner | What Grafana needs from them | What Grafana gives them | Contract impact |
|---|---|---|---|
| **Wazuh (Daniel)** | More rules (auth failures, FIM, MITRE/HIPAA tags), decoders for pfSense/Snort so GRAF-2.3 becomes possible. Attack-start rule 100101 delivered (X-32) | Answer on the marker query and level 3 (GRAF-2.2, by 2026-10-20); a "noisy rule" list once top-rules panels are live | C8: none; C11 (index in his indexer, acknowledged) |
| **n8n (Inigo)** | The `asox-metrics` writer (N8N-2.9, C11) and a date for it; D-N4 (due 2026-11-03) for GRAF-3.2/3.3 | C11 acknowledgement (GRAF-0.6); panel/query examples so Inigo knows what shape the data needs to be in | C11 (accepted, D46) |
| **TheHive (Park)** | Nothing directly; data arrives through n8n. Watching D-N4 and D-N5 since both shape what GRAF-3.2 can show | Dashboard views useful for case review (open/closed, FP rate) | None yet |
| **Cortex + MISP (Diego)** | Nothing blocking | Nothing yet | None |
| **IA team** | A published field or index for anomaly scores and classifier metrics | Panels ready to consume it once it exists | New contract, TBD |
| **Integrator** | R-16 (`n8n-indexer`, `asox-metrics` template, `chk-metrics`) and R-11 (`grafana-ro` read on `asox-metrics`), with dates | Dates confirmed (GRAF-0.7); the `asox-metrics` datasource file (GRAF-0.8) | C11 |

## Decisions to make before building

To be recorded with their status in `docs/decisions.md` ("Owner design decisions") once agreed, same convention as n8n's D-N table.

| # | Decision | Recommendation | Status |
|---|---|---|---|
| D-G1 | Metrics source of truth for MTTD/MTTA/MTTR | New `asox-metrics` index written by n8n, not TheHive queried directly (keeps Grafana on one auth model: OpenSearch) | Recorded; accepted as C11 (D46) |
| D-G2 | Dashboard structure | Three dashboards by audience (admin de TI, equipo/pruebas, dirección), not one dashboard with folders/tabs | Recorded, decided |
| D-G3 | Attack-start marker | A dedicated low-noise Wazuh rule + Grafana annotation, not a manual timestamp typed in after each test | Recorded; Wazuh built rule 100101 (X-32), Grafana's annotation is GRAF-2.2 |
| D-G4 | Severity bucketing | Fixed ranges (baja 0–6, media 7–9, alta 10–11, crítica ≥12), matching Wazuh's own documented levels, not custom cutoffs | Recorded, decided |
| D-G5 | "Caso automático" KPI scope | Report against Critical alerts only, mirroring n8n/TheHive's D-N4, not against all alerts | **Blocked on D-N4** (open, 3-way, due 2026-11-03) |

## Dates

Proposed against the shared team dates (integration backlog, section F); to confirm with the integrator (GRAF-0.7). Items that depend on others say on what.

| Target | Date |
|---|---|
| C11 acknowledged (GRAF-0.6), dates confirmed (GRAF-0.7), answer to Wazuh on the marker and annotation built (GRAF-2.2), per-scenario panels (GRAF-2.1) | **2026-10-20** (checkpoint 1) |
| D-G5 decided once D-N4 closes; GRAF-3.2/3.3 definitions fixed | 2026-11-03 (M3) |
| `asox-metrics` datasource (GRAF-0.8) and MTTD/MTTA/MTTR (GRAF-3.1), **if R-16, R-11 and N8N-2.9 are in** | 2026-11-10 (M4) |
| GRAF-3.2, GRAF-3.3, alert rules (GRAF-4.1), lab timeline (GRAF-2.4) | 2026-11-17 (M5) |
| Feature freeze / delivery | 2026-11-24 / 2026-12-01 |

## Suggested milestones

- **v1.1 baseline (already done):** `soc-overview.json` with alerts-over-time and a recent-alerts table.
- **v1.2 Estado del SOC (~1 week):** all of E0, all of E1. Fully usable dashboard even while GRAF-1.5–1.7 wait on more Wazuh rules.
- **v1.3 Escenarios de ataque (by 2026-10-20):** GRAF-2.1, 2.2 on the six lab scenarios. GRAF-2.3/2.4 wait on Phase 2 (Snort/pfSense) and `asox-metrics`.
- **v1.4 Desempeño y cumplimiento:** C11 is agreed (GRAF-0.4 done); building waits on R-16, R-11 and N8N-2.9. GRAF-3.1 can start once they are in; don't fix GRAF-3.2/3.3 before D-N4 closes (2026-11-03), or the KPI definitions will need rework.
- **Phase 2+:** GRAF-2.3, GRAF-3.4–3.6, E5.