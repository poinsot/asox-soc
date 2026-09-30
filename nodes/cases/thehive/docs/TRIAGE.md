# Triage procedure and roles

Owner: TheHive (Park). How an analyst handles what arrives in TheHive, from alert to closed case. Alert format, severity and the alert-to-case rules (R1–R6) are in [ALERT-FORMAT.md](ALERT-FORMAT.md).

## Users and roles

The Community license allows **2 Normal users** in **1 organisation** (`SOC`). Service, platform-admin and read-only accounts don't count.

| Account | Type / profile | Counts? | Used for |
|---|---|---|---|
| `admin@thehive.local` | Platform admin | No | License, custom fields, observable types, platform settings |
| `analyst@asox.local` | Normal, **org-admin** in SOC | **Yes (1/2)** | Daily triage **and** the organisation's configuration (templates) |
| `n8n@asox.local` | Service, analyst | No | n8n's API account (C3): creates and updates alerts / cases |
| `bootstrap@asox.local` | Service, org-admin | No | `bootstrap.sh` and the export/import scripts; its API key exists only while they run |
| *(reserved)* second Normal user | Normal, **analyst** | Yes (2/2) | Kept free for the optional shared instance: a second analyst who triages but can't change the configuration |
| *(optional)* `viewer@asox.local` | Normal, **read-only** | No | Demos, teachers, the Grafana owner checking case data |

These accounts are created in the UI (Organisation → Users, by an org-admin); they aren't scripted because they carry passwords. If the team wants the viewer on every machine, ask the integrator to add it to `bootstrap.sh`.

## The alert queue

Open **Alerts**, filter on status **New**, sort by **severity**, then oldest first. Targets: Critical 15 min · High 1 h · Medium 4 h · Low next working day.

## Triage, step by step (for each alert)

1. **Read it** (1–2 min): title, severity, agent, `wazuh-rule-id` / `wazuh-rule-level`, description and observables.
2. **Look for related activity:** TheHive's *similar cases / alerts* panel (same observables), and Grafana's SOC Overview filtered on the agent, for the same period.
3. **Enrich:** n8n has already run the automatic analyzers at intake (D-N3); re-run Cortex analyzers by hand on the IP, domain, URL and hash observables when needed (the MISP analyzer answers only for TLP/PAP ≤ AMBER). Once available, the "seen before in Wazuh?" analyzer (C13) shows the Wazuh history of an `ip`, `hostname` or `user-account` observable.
4. **Decide** (rules R2–R6):

| Verdict | Action in TheHive |
|---|---|
| Test alert (`asox-test`, `contract-check`) | Delete, or `thehive-test-alert.sh --cleanup` |
| False positive | *Ignore* the alert, comment with the reason. Third time for the same rule → tell the Wazuh owner (tuning) |
| Same incident as an open case (same agent + template, < 24 h) | *Merge into case* |
| True positive / needs investigation, or Critical | *Create case from alert*: the alert's template adds the tasks and fields |

5. **Assign** the case to yourself and set `asset-criticality` if you know the host (high / critical raises the severity by one).

## Working the case

- Follow the template's tasks in order (Triage → Investigation → Response → Closure). Close each task with a short log: what you checked, what you found.
- Add every new indicator as an observable; mark it **IOC** only when it's confirmed bad.
- **Response actions go through n8n, never by hand** (PROJECT.md 6.2: n8n is the only component that changes systems). Request the playbook's action, wait for its comment on the case, and check `containment-action` is set.
- **What automation can do (C9, Phase 2):** block an IP (`containment-action` = `ip-blocked`) or disable an account (`user-disabled`). Host isolation and file removal have no automated action yet: if they are done outside the SOC's tools, set `host-isolated` / `file-removed` yourself and describe it in a comment.
- Change the severity if the facts change (e.g. SSH brute force followed by a successful login → Critical).

## Closing

1. All tasks completed or cancelled with a reason.
2. **Summary**: what happened, impact, actions taken, open follow-ups.
3. **Resolution status**: True positive (with or without impact), False positive, Duplicated, Indeterminate, Other.
4. Confirmed IOCs stay marked as IOC, for the MISP export (BACKLOG.md T5.4, with the Cortex + MISP owner).
