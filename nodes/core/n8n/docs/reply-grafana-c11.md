# Reply: C11 assumptions (Grafana A1) and dates

**To:** Jesus (@JC-535), Grafana owner; cc Park (@Jinhyuk-P), TheHive owner (point 3), Daniel (@dmelgar1110) for the indexer
**From:** Inigo (@poinsot), n8n owner (and integrator for R-16 / R-11)
**Date:** 2026-10-14
**Refs:** C11 (PROJECT.md 5, D46), X-27, X-42, X-32, R-11, R-16, N8N-2.9, GRAF-0.8, GRAF-3.1–3.3; your `nodes/core/grafana/docs/replies-2026-10.md` (A1, A2)
**Status:** n8n's answer; no change to C11's fields or permissions. Points 2 and 3 fix **values** inside the agreed fields, to confirm by 2026-10-20

Thanks for the acknowledgement. Your assumptions, checked against C11's row in PROJECT.md 5 and the places n8n will write from (`lib-thehive-writeback` and the C4 handlers in `recv-thehive-event`):

| # | Your assumption | n8n | Detail |
|---|---|---|---|
| 1 | Panels use **`t_alert`** as the time field | **Confirmed**, with one caveat | `t_alert` = the TheHive alert's `_createdAt`, written by `lib-thehive-writeback` when `pb-generic` **creates** the alert (a repeated delivery never overwrites it). A Wazuh alert that never became a TheHive alert (parked after a TheHive outage, or a machine without TheHive) has a document **without** `t_alert`, so it is not in `t_alert` panels. For "alerts received" counts use `t_event` (always there: the Wazuh alert's `timestamp`) |
| 2 | `severity` holds TheHive's 1–4 | **Confirmed**, plus updates | n8n writes the severity it sent (ALERT-FORMAT §2, with the asset-criticality +1). If an analyst changes it, the C4 alert or case update carrying `severity` updates the document, so the field follows TheHive |
| 3 | A false positive is `resolution: FalsePositive`; FP rate = FalsePositive over closed alerts with a resolution | **Correction** | TheHive 5.7 has no separate resolution field: a closed case has `stage: Closed` and `status` = the resolution (`TruePositive`, `FalsePositive`, `Duplicated`, `Indeterminate`, `Other`; seen in n8n's fixture `18-case-update-closed-falsepositive.json`). n8n writes that into `resolution`. But **TheHive's TRIAGE.md closes a false positive without a case: the analyst ignores the alert**, so most false positives never get a case. For those n8n writes **`resolution: Ignored`** (the alert's status) and `t_closed`. So the FP rate is (`FalsePositive` + `Ignored`) over documents with a `resolution`. Park: please confirm that an ignored alert always means false positive (TRIAGE.md, "False positive") |
| 4 | MTTD only on documents with `t_attack_start` | **Confirmed** | `t_attack_start` is filled only for lab scenario alerts: n8n reads `asox_run=<run id>` from `full_log` and looks up the marker (rule 100101, `data.run_id`) in `wazuh-alerts-*` as `n8n-indexer`. Every other document has no `t_attack_start`: leave it out, never count it as zero |
| 5 | Panels exclude `outcome: contract-check` | **Confirmed** | Only `chk-metrics` writes that value, and deletes its document afterwards; excluding it covers a check that stopped half-way |

Also good to know when you build GRAF-3.1:

- **Document ID = Wazuh alert ID**, so every write is an upsert; times are ISO 8601 in UTC, typed `date` by the index template (R-16).
- **Test alerts** (`source` `asox-test`: rule 100100 from `trigger.sh` without a scenario and the C1 check) **get no document**: they are never promoted (ALERT-FORMAT §6 R6) and would only skew MTTA. Lab **scenario** alerts keep theirs (that's where `t_attack_start` comes from). C11's "one document per Wazuh alert" means every alert n8n hands to a playbook (at or above `WAZUH_ALERT_MIN_LEVEL`, not a test alert). Say so if you want them anyway.
- **`outcome`** is `none` for every document until a playbook acts on a system (C9, Phase 2), so **`t_contained` stays empty in Phase 1** and MTTR is `t_closed − t_alert`. **Update 2026-10-22 (C9 v0):** `pb-ssh-response` writes `t_contained` (the time of Wazuh's answer) and `outcome: success` after a live `firewall-drop` that Wazuh accepted (an analyst approved it with the tag `approve:firewall-drop`), and `outcome: failed` when a live send didn't go through; dry runs write nothing. Every other document keeps `outcome: none` and an empty `t_contained` (MTTR falls back to `t_closed − t_alert`); n8n README "Metrics (C11)".
- **`auto_promoted`** is `false` until D-N4 (auto-promotion of Critical alerts of named playbooks, to decide by 2026-11-03).
- **`t_ack`** is the first time the alert leaves status New; an alert ignored straight from New gets `t_ack` = `t_closed`.
- A **merged** alert (ALERT-FORMAT §6 R4) gets `case_id` and `t_case` of the case it was merged into.
- **Deleted** alerts and cases are not tracked (TheHive's delete events carry no `object`); TheHive's answer Q8: analysts never delete real cases, only close them.

## Where n8n writes from

| Time / field | Written by | Event |
|---|---|---|
| `alert_id`, `rule_id`, `rule_level`, `severity`, `playbook`, `n8n_execution_id`, `outcome`, `t_event`, `t_alert`, `thehive_alert_id`, `t_attack_start` | `lib-thehive-writeback` (new `lib-metrics-upsert`) | `pb-generic` created the alert |
| `t_ack`; `resolution: Ignored` + `t_closed` | `recv-thehive-event`, route `alert-status` (stub today) | C4 alert update with `status` |
| `case_id`, `t_case` | routes `alert-promoted` and `case-created` | C4 alert update with `caseId`, case create (`fromAlert.sourceRef`) |
| `resolution`, `t_closed` | route `case-status` | C4 case update with `stage: Closed` |
| `severity` | a new route for updates carrying `severity` (today they end in "Recorded, no handler") | C4 alert or case update |

Case events carry no `sourceRef`; n8n gets the case's alerts from TheHive (n8n's account can read them) and updates each one's document.

**Corrected 2026-10-14 (after R-16 was built, `docs/decisions.md` A98):** `n8n-indexer` is not write-only. Its role `asox_n8n_indexer` has `read` on `asox-metrics` besides index, update and delete of documents by ID (still no index creation, mapping change or `delete_by_query`). N8N-2.9 uses that read to set the first-time times (`t_ack`, `t_case`, `t_contained`, `t_closed`) only when the document doesn't have them yet, and `chk-metrics` uses it to check a document before deleting it. Nothing changes for Grafana.

## Dates

| Item | Who | Date |
|---|---|---|
| R-16: indexer user `n8n-indexer`, the `asox-metrics` index template (Daniel's settings: 1 shard, 0 replicas, no deletion policy before 2026-12-01), n8n's credential, `chk-metrics` and C11 in `contracts-check.sh` | integrator | **2026-10-27** |
| R-11: `grafana-ro` reads `asox-metrics`; your datasource (GRAF-0.8) goes in with it | integrator (+ your GRAF-0.8) | **2026-10-27** |
| N8N-2.9: `lib-metrics-upsert`, the writeback and C4 writers above | n8n | **2026-11-10** |

From 2026-10-27 the index and your datasource exist, so its health check passes; the index stays empty (`chk-metrics` deletes its document) until N8N-2.9 writes real documents.
