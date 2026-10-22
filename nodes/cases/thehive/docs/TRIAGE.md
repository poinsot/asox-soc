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

Open **Alerts**, filter on status **New**, sort by **severity**, then oldest first. Alerts reach TheHive a few seconds after Wazuh raises them (up to ~30 s during a burst: n8n queues them). Targets: Critical 15 min · High 1 h · Medium 4 h · Low next working day.

## Triage, step by step (for each alert)

1. **Read it** (1–2 min): title, severity, agent, `wazuh-rule-id` / `wazuh-rule-level`, description and observables.
2. **Look for related activity:** TheHive's *similar cases / alerts* panel (same observables), and Grafana's SOC Overview filtered on the agent, for the same period.
3. **Enrich:** n8n has already run the automatic analyzers at intake (D-N3); re-run Cortex analyzers by hand on the IP, domain, URL and hash observables when needed (the MISP analyzer answers only for TLP/PAP ≤ AMBER). Once available, the "seen before in Wazuh?" analyzer (C13) shows the Wazuh history of an `ip`, `hostname` or `user-account` observable.
4. **Decide** (rules R2–R6):

| Verdict | Action in TheHive |
|---|---|
| Test alert (`asox-test`, `contract-check`) | Delete, or `thehive-test-alert.sh --cleanup` |
| False positive (incl. expected, authorized activity) | *Ignore* the alert and write the reason in its summary / comment. **Ignore means false positive**: Grafana's FP rate counts every ignored alert as one (C11), so never ignore a real or unclear alert; promote or merge it instead. Third time for the same rule → tell the Wazuh owner (tuning); `scripts/thehive-fp-report.sh` lists them by rule |
| Same incident as an open case (same agent + template, < 24 h) | *Merge into case* |
| True positive / needs investigation, or Critical | *Create case from alert*: the alert's template adds the tasks and fields |

5. **Assign** the case to yourself and set `asset-criticality` if you know the host (high / critical raises the severity by one).

## Working the case

- Follow the template's tasks in order (Triage → Investigation → Response → Closure). Close each task with a short log: what you checked, what you found.
- Add every new indicator as an observable; mark it **IOC** only when it's confirmed bad. n8n's enrichment tags observables `asox:verdict=<verdict>`: a MISP hit shows as `suspicious` and is **not** marked IOC automatically (it may only be listed in a public feed). Check the MISP event first, then mark it yourself.
- **`warninglist` tag** (from MISP, added by n8n): the value is **common** (public DNS resolver, Tor exit node, well-known site), **not safe**. Open the observable to see which lists: their names are in its description. A Tor exit node attacking you is still an attack; use the tag as context, never as a reason to ignore the alert.
- **Attacker-written values** (`uri_path` of a web attack, file paths, user names): read them, never open them as links or paste them into a shell. A `fim:deleted` hash is the file's last known content: the file itself is gone.
- **`ssh-campaign:<ip>` / `ssh:login-after-bruteforce` tags** (n8n's SSH playbook): alerts from the same attacking IP within an hour. `login-after-bruteforce` means the brute force was followed by a successful login: the alert is raised to Critical; treat the host as compromised and work those alerts in one case (merge, R4).
- **`asox:verdict=malicious` on an alert** (n8n's malware playbook): an analyzer flagged a file hash as malicious, so the alert is raised to Critical. Promote at once (R2) and check the writeback's "Same hash on other alerts" list: other hosts may have the same file.
- **Alerts from pfSense or routers** arrive over syslog: the host in the title and the `agent:` tag is the device (`pfsense`), not a Wazuh agent, and its IP is the `agent`-tagged `ip` observable.
- **Response actions go through n8n, never by hand** (PROJECT.md 6.2: n8n is the only component that changes systems). Request the playbook's action, wait for its comment on the case, and check `containment-action` is set.
- **What automation can do (C9, Phase 2):** block an IP (`containment-action` = `ip-blocked`) or disable an account (`user-disabled`). Host isolation and file removal have no automated action yet: if they are done outside the SOC's tools, set `host-isolated` / `file-removed` yourself and describe it in a comment.
- Change the severity if the facts change (e.g. SSH brute force followed by a successful login → Critical).

## Approving a response action (D-N5)

Some playbook actions change systems (block an IP, disable an account: C9). n8n never runs them without an analyst's approval, given in TheHive itself:

1. The playbook adds a task **"Approve: `<action>`"** (group `Approval`) to the case, e.g. "Approve: firewall-drop 101.99.75.184 on lab-agent", with what it will do, on which host and for how long in the task description.
2. The analyst assigned to the case decides:
   - **Approve**: close the task (*Completed*). Add a log if there is anything to add.
   - **Reject**: *cancel* the task and write why in a log (e.g. "IP is our VPN gateway").
3. TheHive sends the task update to n8n (C4). n8n runs the action only for a task closed by a user other than `n8n@asox.local`, then comments on the case with the result and sets `containment-action` (`ip-blocked`, `user-disabled`).
4. **No answer within 1 hour**: n8n cancels the task with a log "Timed out, not executed". Nothing is done; the analyst can ask the playbook again.

Only one pending approval per action and case. Closing the case cancels any pending approval task. A Slack button may later approve the same task through n8n's channel abstraction; TheHive stays the record of who approved what.

### Interim for the physical-lab demo (2026-10-23): approval by tag

Until n8n's approval tasks (E7) exist, **only for the demo**, the SSH playbook (`pb-ssh-bruteforce`) proposes and the analyst approves with a tag. Only one action exists: **`firewall-drop` of the attacking IP on the attacked agent, 300 s**, which Wazuh reverts by itself (C9 v0, D44; n8n's `ALERT-TO-THEHIVE.md` §13).

1. **Read the proposal** in n8n's writeback comment on the alert: *Proposed: firewall-drop `<ip>` on `<agent>` for 300 s (`live` or `dry_run`). Approve by adding the tag approve:firewall-drop to this alert within 1 h.*, followed by the line `[asox-n8n response-proposal] <agent id> <ip> firewall-drop 300`. Without a proposal the writeback says `Recommended: block <ip> … (no proposal: <reason>)` and nothing can be approved.
2. **Check before approving:** the IP is the attacker in this alert (`src`), it is **not** a SOC host, gateway, DNS or the manager, and the agent is the attacked host.
3. **Approve:** add the tag **`approve:firewall-drop`** to that alert, from **your own analyst account**, within 1 h. To reject, don't add it and write the reason in a comment.
4. **Check n8n's answer**, a comment on the alert:
   - `[asox-n8n response] firewall-drop <ip> on <agent> (live): sent`: Wazuh accepted it and sent it to the agent (not yet proof that the packet filter changed). n8n tags the alert `asox:response=firewall-drop` and sets `containment-action` = `ip-blocked`; the comment says when the automatic revert happens (about 300 s). If it says **NO automatic revert**, unblock by hand as it explains.
   - `… (dry_run): not sent (dry_run)`: test mode, nothing was blocked.
   - `[asox-n8n response-refused] <code>`: nothing ran, e.g. `expired` (more than 1 h), `already-executed`, `protected` (protected host), `agent_not_in_group` (agent not in `asox-response`).
5. If the alert is already in a case, set `containment-action` = `ip-blocked` on the case too (n8n sets it on the alert only) and add a log saying who approved.

No tag, no action. This interim is replaced by the approval task above as soon as E7 is built; it is not part of the delivery procedure unless the team decides so after the demo.

## Closing

1. All tasks completed or cancelled with a reason.
2. **Summary**: what happened, impact, actions taken, open follow-ups.
3. **Resolution status**: True positive (with or without impact), False positive, Duplicated, Indeterminate, Other.
4. Confirmed IOCs stay marked as IOC, for the MISP export (BACKLOG.md T5.4, with the Cortex + MISP owner).

**Never delete a real case: close it.** Deleting a case puts its alert back to *InProgress* without a case, and TheHive sends no event for the alert, so n8n and the metrics (C11) never learn of it. Deleting is only for test objects (`asox-test`, `contract-check`), with `thehive-test-alert.sh --cleanup`.
