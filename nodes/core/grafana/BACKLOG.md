# Grafana (Dashboard analítico) backlog: base draft

IDs use the prefix `GRAF-` so other backlogs and `docs/integration-backlog.md` can reference them.

Owner: Jesus (@JC-535). Branch: `grafana`. Node: `core`. Run mode: `core`.

Based on PROJECT.md (v2.1), docs/decisions.md, docs/handoff.md, CHECKLIST.md, CONTRIBUTING.md, `nodes/core/grafana/README.md` and the component READMEs (Wazuh, n8n, TheHive, Cortex + MISP). This is a base draft to refine, and to compare against the other owners' backlogs (Wazuh, n8n, TheHive, Cortex + MISP).

**Caveats**
- The docs may lag behind the repo; teammates may already have pushed changes.
- Sizes are rough guesses: S ≤ 1 day, M 2–4 days, L > 4 days.
- KPI names and thresholds here are a proposal, not yet agreed with the other owners.

## Two risks to check first

1. **Grafana only has `wazuh-alerts-*` today (C8), read-only.** Every MTTD/MTTA/MTTR and case-based KPI needs a new contract with n8n (a metrics index n8n writes to and `grafana-ro` can read). Until that contract exists, the "Desempeño y cumplimiento" dashboard is an empty shell with real panels wired to nothing.
2. **Only one rule (`100100`) and one agent (`lab-agent`) exist today.** Breakdown panels (top rules, top endpoints, MITRE, HIPAA, auth failures, FIM) will show a single bucket or "No data" until Daniel's rule set grows. Build them now anyway; validating them is blocked on E1 items below, not on Grafana's own work.

## Item format

`ID | Item | Priority | Size | Meets with / depends on`. Contract impact is stated explicitly where it exists.

## E0: Foundations and decisions

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-0.1 | Confirm every field these dashboards rely on (`rule.level`, `agent.id/name`, `rule.description`, `data.srcip`, `rule.groups`, `data.dstuser`, `rule.mitre.tactic`, `rule.hipaa`) actually exists in the live index, via the panel field explorer | P0 | S | Wazuh |
| GRAF-0.2 | Adopt `$min_level` (already used by `soc-overview.json`) as the standard template variable on every new panel | P1 | S | none |
| GRAF-0.3 | Record decisions D-G1…D-G4 (below) in `docs/decisions.md` | P0 | S | All |
| GRAF-0.4 | Propose the `asox-metrics` contract to n8n: schema (`alert_id`, `case_id`, `t_alert`, `t_case`, `t_contained`, `t_closed`, `playbook`, `outcome`), who writes it, and the `grafana-ro` role change needed to read it | P1 | M | n8n (Inigo) |
| GRAF-0.5 | Naming convention for panels and dashboards (title, uid stability, folder) so exports stay reviewable in `git diff` | P1 | S | none |

## E1: Dashboard "Estado del SOC" — Nivel 1, `wazuh-alerts-*` only

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-1.1 | Stat panels: alerts 24h (+ trend), critical (≥12) / high (10–11), active endpoints (15 min override) | P0 | S | none |
| GRAF-1.2 | Severity distribution (4 range queries as one bar chart) | P0 | S | none |
| GRAF-1.3 | Top rules and top endpoints (Terms on `rule.description.keyword` / `agent.name.keyword`) | P0 | S | Wazuh (more rules/agents needed to validate) |
| GRAF-1.4 | Top source IPs table | P0 | S | none |
| GRAF-1.5 | Failed authentications over time + top targeted users (`rule.groups:authentication_failed`, `data.dstuser`) | P1 | M | Wazuh (rule must exist) |
| GRAF-1.6 | FIM spikes (`rule.groups:syscheck`) | P1 | S | Wazuh (rule must exist) |
| GRAF-1.7 | Alerts by MITRE tactic and by HIPAA control | P1 | M | Wazuh (rules must tag `rule.mitre` / `rule.hipaa`) |

## E2: Dashboard "Escenarios de ataque"

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-2.1 | Per-scenario panel (fuerza bruta AD, phishing+ransomware): KPI + sparkline, doable today with agents | P0 | M | Wazuh |
| GRAF-2.2 | Attack-start marker convention: lab/attack scripts emit `ASOX_ATTACK_START scenario=<x> id=<uuid>`, a dedicated rule catches it, Grafana draws it as an annotation | P1 | M | Wazuh (rule owner), Lab scripts |
| GRAF-2.3 | Escaneo de red / DDoS panels | P2 | M | Wazuh + Snort or OPNsense (Phase 2, not built yet) |
| GRAF-2.4 | Full simulacro timeline (ataque → detección → alerta → respuesta → caso), one row per stage | P2 | M | n8n, TheHive (needs GRAF-0.4) |

## E3: Dashboard "Desempeño y cumplimiento" — Nivel 2/3

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-3.1 | MTTD / MTTA / MTTR stat panels reading `asox-metrics` | P1 | M | n8n (depends on GRAF-0.4 and N8N-9.3) |
| GRAF-3.2 | Open/closed cases by severity, false-positive rate | P1 | M | TheHive, n8n |
| GRAF-3.3 | Playbooks executed (success/fail/reverted), % alerts with auto-ticket | P1 | S | n8n |
| GRAF-3.4 | Anomalous-alert count and top hosts/users by score | P2 | S | IA team (needs a published index/field) |
| GRAF-3.5 | Priority queue panel (alerts ordered by model score) | P2 | S | IA team |
| GRAF-3.6 | Phishing classifier precision/recall as static stat panels from its evaluation report | P2 | S | IA team |

## E4: Alerting and ops

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-4.1 | Grafana alert rules (`provisioning/alerting/`): critical alert spike, endpoint silent > 15 min | P1 | M | none |
| GRAF-4.2 | Document the daily index-pattern caveat (`[wazuh-alerts-4.x-]YYYY.MM.DD`) so no one wildcards it back and breaks the datasource health check (D35) | P1 | S | none |
| GRAF-4.3 | Admin password rotation doc (`grafana cli admin reset-admin-password`) for when a machine's `.env` and Grafana's stored password ever drift apart | P2 | S | none |
| GRAF-4.4 | Re-measure memory after any Grafana version bump per the pinning note (D34) before moving off 12.4.x | P2 | S | Integrator |

## E5: Phase 3 readiness

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| GRAF-5.1 | Grafana alert → n8n webhook, if the team wants Grafana-triggered playbooks | P2 | S | n8n |

## Where Grafana meets the other owners

| Owner | What Grafana needs from them | What Grafana gives them | Contract impact |
|---|---|---|---|
| **Wazuh (Daniel)** | More rules (auth failures, FIM, MITRE/HIPAA tags), decoders for pfSense/Snort so GRAF-2.3 becomes possible | Nothing blocking; a "noisy rule" list once top-rules panels are live | C8: none |
| **n8n (Inigo)** | The `asox-metrics` contract (GRAF-0.4): who writes it, the schema, timing | Panel/query examples so Inigo knows what shape the data needs to be in | New contract |
| **TheHive (Park)** | Nothing directly; data arrives through n8n | Dashboard views useful for case review (open/closed, FP rate) | None yet |
| **Cortex + MISP (Diego)** | Nothing blocking | Nothing yet | None |
| **IA team** | A published field or index for anomaly scores and classifier metrics | Panels ready to consume it once it exists | New contract, TBD |
| **Integrator** | Role change on `grafana-ro` when GRAF-0.4 lands (`scripts/bootstrap.sh`) | n/a | Update at a checkpoint |

## Decisions to make before building

| # | Decision | Recommendation |
|---|---|---|
| D-G1 | Metrics source of truth for MTTD/MTTA/MTTR | New `asox-metrics` index written by n8n, not TheHive queried directly (keeps Grafana on one auth model: OpenSearch) |
| D-G2 | Dashboard structure | Three dashboards by audience (admin de TI, equipo/pruebas, dirección), not one dashboard with folders/tabs |
| D-G3 | Attack-start marker | A dedicated low-noise Wazuh rule + Grafana annotation, not a manual timestamp typed in after each test |
| D-G4 | Severity bucketing | Fixed ranges (baja 0–6, media 7–9, alta 10–11, crítica ≥12), matching Wazuh's own documented levels, not custom cutoffs |

## Suggentions

- **v1.1 baseline (already done):** `soc-overview.json` with alerts-over-time and a recent-alerts table.
- **v1.2 Estado del SOC (~1 week):** all of E0, all of E1. Fully usable dashboard even while GRAF-1.5–1.7 wait on more Wazuh rules.
- **v1.3 Escenarios de ataque:** GRAF-2.1, 2.2. GRAF-2.3/2.4 wait on Phase 2 (Snort/pfSense, `asox-metrics`).
- **v1.4 Desempeño y cumplimiento:** blocked on GRAF-0.4 being agreed with n8n; then GRAF-3.1–3.3.
- **Phase 2+:** GRAF-2.3, GRAF-3.4–3.6, E5.