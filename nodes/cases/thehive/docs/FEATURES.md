# TheHive component: features and backlog

Owner: Park (@Jinhyuk-P) · Branch `thehive` · Folder `nodes/cases/thehive/` · Run mode `cases`

**Role in the SOC ("Dashboard operativo"):** TheHive is where people work. Wazuh detects, n8n orchestrates and acts, Cortex + MISP enrich, Grafana measures; TheHive holds the **alerts and cases** analysts triage, investigate and close. This component owns everything that shapes that work: the alert format it accepts, how alerts become cases, the case templates and their tasks, the custom fields, and the triage procedure.

```
Wazuh ──C1──▶ n8n ──C3──▶ TheHive alert ──triage──▶ case (template: tasks + fields) ──▶ closed
                ▲                │  └──C5──▶ Cortex ──C7──▶ MISP (enrichment)
                └──────C4────────┘  events back to n8n (playbooks, approvals)
```

Status: ✅ done · 🟡 proposed, needs another owner's agreement · ⬜ to do

## Delivered

| ID | Feature | Status | What it is | How to check |
|---|---|---|---|---|
| F1 | **Configuration as code** | ✅ | `scripts/thehive-export.sh` / `thehive-import.sh`: custom fields, observable types and case templates ↔ `entities/*.json` (README, section "Exporting and importing") | Export, delete in UI, import: it comes back; import again: all *unchanged* |
| F2 | **Custom fields** (9) | ✅ | Wazuh traceability (`wazuh-alert-id`, `wazuh-rule-id`, `wazuh-rule-level`, `wazuh-agent-name`), context (`mitre-technique`, `asset-criticality`), automation (`playbook`, `n8n-execution-id`), response (`containment-action`) | Entities management → Custom fields |
| F3 | **Case templates** (4) | ✅ | `ssh-bruteforce`, `malware-detection`, `ids-network-alert`, `wazuh-generic`: each with Triage → Investigation → Response → Closure tasks and the F2 fields | Organisation → Templates → Cases |
| F4 | **Observable type `user-account`** | ✅ | Targeted / source user names as real observables instead of `other` | Entities management → Observable types |
| F5 | **Test alert generator** | ✅ | `scripts/thehive-test-alert.sh [ssh\|malware\|ids\|generic\|all] [--critical-asset]`, `--cleanup`: realistic Wazuh-style alerts through n8n's own account (checks C3 permissions too) | Alerts list shows them with the right severity and template |
| F6 | **Triage procedure and roles** | ✅ | [TRIAGE.md](TRIAGE.md): queue, step-by-step triage, working and closing a case; accounts and the 2-user license plan | Walk a test alert through it |

## Proposed: needs the n8n owner's agreement

| ID | Feature | Status | What it is | Depends on |
|---|---|---|---|---|
| F7 | **Alert format** | 🟡 | [ALERT-FORMAT.md](ALERT-FORMAT.md) §1, 4, 5: fields, tags, custom fields and observables of every alert n8n creates; `sourceRef` = Wazuh alert ID (deduplication) | Inigo (n8n playbooks) |
| F8 | **Severity / TLP / PAP mapping** | 🟡 | ALERT-FORMAT.md §2: Wazuh level → severity, +1 for critical assets; TLP / PAP AMBER so the MISP analyzer can run | Inigo; Diego (analyzer TLP/PAP limits) |
| F9 | **Template routing** | 🟡 | ALERT-FORMAT.md §3: which Wazuh rule groups get which case template (`caseTemplate` on the alert) | Inigo (Router de Playbooks) |
| F10 | **Alert-to-case rules** | 🟡 | ALERT-FORMAT.md §6: R1–R6 (alerts first, Critical promoted at once, merge same agent + template < 24 h, false positives, tests) and triage targets | Inigo (optional auto-promotion of Critical) |

## Next

| ID | Feature | Status | What it is | Depends on |
|---|---|---|---|---|
| F11 | **Operational dashboards** | ⬜ | TheHive dashboards: open alerts by severity, cases by template / status, triage targets missed; extend F1 to export them | — |
| F12 | **Case metrics for Grafana** | ⬜ | Time to triage / to close per severity (MTTD / MTTR) for Grafana's management dashboards | Jesus (Grafana) |
| F13 | **Response approval in TheHive** | ⬜ | Analyst approves an n8n action (block IP, isolate host) from the case; n8n learns it through the C4 webhook; result written back to the case | Inigo; Daniel (C9, Phase 2) |
| F14 | **IOC export to MISP** | ⬜ | Confirmed IOCs of closed cases pushed to MISP (TheHive's MISP connector: the license allows 1 MISP server) | Diego (MISP) |
| F15 | **Tags and taxonomies** | ⬜ | Consistent tags: TLP, MITRE ATT&CK, verdict; custom tags in the SOC organisation | — |
| F16 | **Playbook pages** | ⬜ | Knowledge-base pages linked to each template (how to investigate, useful queries) | — |
| — | **More templates** | ⬜ | e.g. privilege escalation, web attack, suspicious login, file integrity change: added as the Wazuh owner writes detection rules | Daniel (Wazuh rules) |

## Definition of done (every feature)

1. Built in TheHive (UI or API) and **exported** (`thehive-export.sh`), so it is in `entities/` or `docs/`.
2. Works on a fresh instance after `thehive-import.sh`.
3. Tested with `thehive-test-alert.sh` where it concerns alerts or cases.
4. `scripts/healthcheck.sh` green and `scripts/contracts-check.sh --only C3,C4,C5` passing if an integration is touched.
5. Committed on `thehive`, then merged into `main` through a checkpoint pull request.
