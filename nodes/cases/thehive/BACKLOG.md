# TheHive owner backlog

Owner: Park (@Jinhyuk-P). Branch `thehive`. Folder `nodes/cases/thehive/`. Plan as of 2026-09-29.

**Delivery: 2026-12-01.** Feature freeze 2026-11-24. Priorities: P1 is the delivery, P2 should have, P3 nice to have; if behind, drop P3 first, then P2. M7 is after the delivery. Contracts: PROJECT.md section 5. `X-nn` tags point to the integrator's register (`docs/integration-backlog.md`).

Tick a box (`[x]`) when its "done when" check passes, and commit this file with the work.

## Features (what this component does)

**Role in the SOC:** TheHive is where people work. Wazuh detects, n8n orchestrates and acts, Cortex + MISP enrich, Grafana measures; TheHive holds the **alerts and cases** that analysts triage, investigate and close. This component owns everything that shapes that work: the alert format it accepts, how alerts become cases, the case templates and their tasks, the custom fields, and the triage procedure.

```
Wazuh ──C1──▶ n8n ──C3──▶ TheHive alert ──triage──▶ case (template: tasks + fields) ──▶ closed
                ▲                │  └──C5──▶ Cortex ──C7──▶ MISP (enrichment)
                └──────C4────────┘  events back to n8n (playbooks, approvals)
```

| Feature | What it does |
|---|---|
| **Configuration as code** | `thehive-export.sh` / `thehive-import.sh` copy custom fields, observable types and case templates between TheHive and `entities/*.json`, so every change made in the UI reaches git and loads on any machine |
| **Custom fields** | Every alert and case carries its Wazuh origin (`wazuh-alert-id`, `wazuh-rule-id`, `wazuh-rule-level`, `wazuh-agent-name`), its context (`mitre-technique`, `asset-criticality`), which n8n playbook handled it (`playbook`, `n8n-execution-id`) and what was done (`containment-action`) |
| **Case templates** | A case created from an alert gets a ready-made checklist: `ssh-bruteforce`, `malware-detection`, `ids-network-alert` or `wazuh-generic`, each with Triage → Investigation → Response → Closure tasks |
| **Observable type `user-account`** | User names (targeted or source accounts) are stored as real observables, not as `other` |
| **Alert format** | One agreed shape for every alert n8n creates: fields, tags, custom fields, observables, and `sourceRef` = Wazuh alert ID so the same alert can never be created twice ([docs/ALERT-FORMAT.md](docs/ALERT-FORMAT.md)) |
| **Severity / TLP / PAP mapping** | Wazuh rule level → TheHive severity (+1 for critical hosts); TLP / PAP AMBER by default so Cortex's MISP analyzer can run |
| **Template routing** | The alert names its case template from the Wazuh rule groups (`caseTemplate`), so promotion applies the right tasks automatically |
| **Alert-to-case rules** | When an alert becomes a case, is merged into an existing one, or is ignored; triage time targets per severity |
| **Triage procedure and roles** | How an analyst works the queue, step by step, and which account does what under the 2-user Community license ([docs/TRIAGE.md](docs/TRIAGE.md)) |
| **Test alerts** | `thehive-test-alert.sh` creates realistic Wazuh-style alerts through n8n's own account, so the whole flow can be tried in `cases` mode without Wazuh |

## Done when (100% functional)

- `soc.sh init cases` from a fresh clone, then `thehive-import.sh`, gives a TheHive with every field, template and observable type of `entities/`, and a green `healthcheck.sh`.
- `contracts-check.sh --only C3,C4,C5` passes, and C1–C8 pass in `full` after each checkpoint merge.
- Every Wazuh alert type the team detects has a case template, and the alert format, severity mapping and template routing are agreed with the n8n owner.
- An alert travels end to end: Wazuh → n8n → TheHive alert (right severity, fields, template) → case → closed following `docs/TRIAGE.md`.
- The README, this backlog and the docs are up to date, and each milestone reached `main` through a checkpoint pull request.

## M0 · Setup and baseline check (target: 2026-10-02)

Your machine runs the `cases` mode, licensed and backed up, before you change anything.

- [x] **T0.1** Accept the GitHub invite and check SSH access from WSL · P1
  - Done when: `ssh -T git@github.com` greets @Jinhyuk-P; `git fetch origin` works.
- [x] **T0.2** Complete the teammate gate of CHECKLIST.md · P1
  - Done when: Sections 1–5, 7 and 9 checked; `scripts/preflight.sh cases` passes.
  - Files: `CHECKLIST.md`
- [x] **T0.3** Set up topology.env and run `./scripts/soc.sh init cases` · P1
  - Done when: `MEM_PROFILE=standard` (64 GB machine, WSL 16 GB); `init` ends with `healthcheck.sh` green except the MISP analyzer image, which `cases` mode doesn't pull (reported to Inigo).
  - Files: `topology.env`
- [x] **T0.4** Activate the Community license and back it up · P1, X-19
  - Done when: `soc.sh info cases` shows Community, valid until 2027-09-29; `backup.sh cases --with-secrets` done right after; `healthcheck.sh` shows no webhook warning.
- [ ] **T0.5** Verify the baseline you own · P1, C5
  - Done when: `contracts-check.sh --only C5` passes in `cases`; C3 and C4 (they need n8n) checked once in `full` or on the integrator's run.
- [ ] **T0.6** Read the contracts and the TheHive chapter · P2
  - Done when: Read PROJECT.md 5, 6.4, 11, `nodes/cases/thehive/README.md`, CONTRIBUTING.md; run `scripts/ci-checks.sh all` once.
  - Files: `PROJECT.md`, `CONTRIBUTING.md`, `nodes/cases/thehive/README.md`
- [ ] **T0.7** Tell the integrator your RAM, Windows version and license result · P3, X-19
  - Done when: Inigo has PROJECT.md 16 questions 1 and 3 (64 GB, Windows 11) and the X-19 input from T0.4.
  - With: Inigo (integrator)

## M1 · Configuration as code and tools (target: 2026-10-09)

Everything built in the UI reaches git, and alerts can be tested without Wazuh.

- [x] **T1.1** Export / import scripts for the UI configuration · P1
  - Done when: `thehive-export.sh` writes custom fields, observable types and case templates to `entities/*.json` (sorted, no IDs); `thehive-import.sh` recreates them by name, never deletes, and a second run says *unchanged*. Round trip tested on the real instance.
  - Files: `nodes/cases/thehive/scripts/`, `nodes/cases/thehive/entities/`
- [x] **T1.2** Test alert generator · P1, C3
  - Done when: `thehive-test-alert.sh [ssh|malware|ids|generic|all] [--critical-asset]` creates realistic Wazuh-style alerts through n8n's own account; `--cleanup` deletes them; `shellcheck` clean.
  - Files: `nodes/cases/thehive/scripts/thehive-test-alert.sh`
- [ ] **T1.3** Run the starter configuration on the real instance · P1, X-15
  - Done when: `thehive-import.sh` creates 9 fields, 1 observable type, 4 templates; `thehive-test-alert.sh all` creates 4 alerts; a case created from the SSH alert gets its 6 tasks and fields; `thehive-export.sh` then shows no diff. This also confirms the n8n account's `analyst` profile is enough (X-15).

## M2 · Data model and alert format v1 (target: 2026-10-20)

The data every other component relies on, agreed and merged at checkpoint 1 (milestone tag `v1.1-detections`).

- [x] **T2.1** Custom fields · P1, X-03
  - Done when: 9 fields in `entities/custom-fields.json`: `wazuh-alert-id`, `wazuh-rule-id`, `wazuh-rule-level`, `wazuh-agent-name`, `mitre-technique`, `asset-criticality`, `containment-action`, `playbook`, `n8n-execution-id`.
  - Files: `nodes/cases/thehive/entities/custom-fields.json`
- [x] **T2.2** Case templates v1 · P1, X-12
  - Done when: `ssh-bruteforce`, `malware-detection`, `ids-network-alert`, `wazuh-generic`, each with Triage → Investigation → Response → Closure tasks and the T2.1 fields.
  - Files: `nodes/cases/thehive/entities/case-templates.json`
- [x] **T2.3** Observable type `user-account` · P2
  - Done when: In `entities/observable-types.json`; used by the SSH test alert.
- [ ] **T2.4** Agree the alert format with the n8n owner · P1, C3, X-02
  - Done when: `docs/ALERT-FORMAT.md` §1, 4, 5 accepted by Inigo (fields, tags, custom fields, observables, `source` = `wazuh`, `sourceRef` = Wazuh alert ID for deduplication); status changed from proposal to agreed.
  - Files: `nodes/cases/thehive/docs/ALERT-FORMAT.md`
  - With: Inigo (n8n owner)
- [ ] **T2.5** Agree the severity / TLP / PAP mapping · P1, X-02, X-08
  - Done when: `docs/ALERT-FORMAT.md` §2 accepted: level 12–15 Critical, 10–11 High, 7–9 Medium, +1 for critical assets; TLP / PAP AMBER. Consistent with Daniel's level policy (W2.1) and Suricata mapping (W3.5: severity 1 → 12, 2 → 10), and with Diego's analyzer TLP / PAP limits.
  - With: Inigo, Daniel (W2.1), Diego (X-08)
- [ ] **T2.6** Agree the template routing · P1, X-04
  - Done when: `docs/ALERT-FORMAT.md` §3 matches Daniel's rule ID plan and rule groups (W1.3, W2.5), and Inigo's router uses it to set `caseTemplate`.
  - With: Inigo (router), Daniel (rule groups)
- [ ] **T2.7** Checkpoint 1 pull request (by 2026-10-20) · P1, C3, C4, C5
  - Done when: `git pull --no-rebase --no-edit origin main`, `healthcheck.sh` green, `contracts-check.sh --only C5` passes (C3, C4 in `full`), `ci-checks.sh all` passes, pull request `thehive` → `main` opened and merged by the integrator.
  - With: Inigo (review and merge)

## M3 · Triage and case workflow (target: 2026-11-03)

Analysts can work every alert type from queue to closed case.

- [x] **T3.1** Triage procedure · P1
  - Done when: `docs/TRIAGE.md`: alert queue, triage step by step, working and closing a case.
  - Files: `nodes/cases/thehive/docs/TRIAGE.md`
- [x] **T3.2** Users and roles under the 2-user license · P1, X-15
  - Done when: `docs/TRIAGE.md` lists every account and profile; second seat reserved for the shared instance; optional read-only viewer.
- [ ] **T3.3** Agree the alert-to-case rules · P1, X-13
  - Done when: `docs/ALERT-FORMAT.md` §6 accepted: analysts promote, n8n may auto-promote Critical only; merge same agent + template within 24 h; triage targets.
  - With: Inigo (n8n owner)
- [ ] **T3.4** Walk every test alert through the procedure · P1
  - Done when: For each scenario of `thehive-test-alert.sh`: triage, promote or merge or ignore, work the tasks, close with a summary and resolution status. Screenshots kept for the delivery; gaps fixed in the templates or TRIAGE.md.
- [ ] **T3.5** Templates for the new detections · P2, X-12
  - Done when: A template (or a documented choice of `wazuh-generic`) for each detection Daniel adds: login success after failures, sudo failure / privilege escalation, new user, IOC match (W6.4), pfSense port scan (W4.3). Exported, and routed in ALERT-FORMAT.md §3.
  - Files: `nodes/cases/thehive/entities/case-templates.json`, `nodes/cases/thehive/docs/ALERT-FORMAT.md`
  - With: Daniel (W2.2, W4.3, W6.4)
- [ ] **T3.6** Adapt `ids-network-alert` to Suricata · P2
  - Done when: Template text and ALERT-FORMAT.md use Suricata (Daniel's W3.1) instead of Snort: rule groups `suricata` / `ids`, rule 86601, fields `data.alert.signature`, `data.src_ip`, `data.dest_ip`, `data.dest_port`; the `ids` test alert uses them.
  - With: Daniel (W3.7)

## M4 · Interface with n8n (target: 2026-11-10)

TheHive and n8n work together without loops, duplicates or unapproved actions.

- [ ] **T4.1** Decide who runs enrichment · P1, C5, C6, X-17
  - Done when: Recorded with Inigo and Diego: n8n enriches automatically at intake (C6); analysts re-run analyzers by hand from TheHive (C5).
  - With: Inigo, Diego
- [ ] **T4.2** Check C4 end to end and loop prevention · P1, C4, X-14, X-19
  - Done when: In `full` (or the integrator's run): C4 passes with the Community license; n8n ignores events caused by `n8n@asox.local`; the "n8n (C4)" rule and `n8n` endpoint untouched.
  - With: Inigo (integrator)
- [ ] **T4.3** Approval design in TheHive · P2, X-16
  - Done when: Agreed with Inigo: the playbook adds a task "Approve: <action>" (group `Approval`); closing it approves, cancelling rejects (with a comment); C4 carries the task update; no answer in 1 h → n8n cancels it. Written in TRIAGE.md.
  - With: Inigo (n8n owner)
- [ ] **T4.4** False-positive report for Wazuh tuning · P2, X-11
  - Done when: `scripts/thehive-fp-report.sh` lists cases and alerts closed as False positive / Ignored, grouped by `wazuh-rule-id` with counts and reasons; Daniel uses it for W2.4.
  - Files: `nodes/cases/thehive/scripts/`
  - With: Daniel (W2.4)

## M5 · Direct Wazuh ↔ TheHive links and intel (target: 2026-11-17)

The two extra links the team discussed (every existing connection stays; README, "Design discussion"), and the intel flows.

- [ ] **T5.1** Decide the direct links as new contracts (by 2026-11-03) · P2
  - Done when: With Daniel and Inigo: A (Wazuh → TheHive alerts) and B (TheHive → Wazuh lookup) accepted or rejected; if accepted, Inigo adds the contracts (e.g. C10, C11) to PROJECT.md 5.
  - With: Daniel (Wazuh), Inigo (integrator), Diego (for B)
- [ ] **T5.2** Link A, TheHive side · P2
  - Done when: TheHive Service account for Wazuh requested from Inigo (`bootstrap.sh`); an alert sent twice (by A and by n8n, same `sourceRef`) exists once; its fields match ALERT-FORMAT.md.
  - With: Daniel (integration script), Inigo (account)
- [ ] **T5.3** Link B, lookup from a case · P3, X-26
  - Done when: From a case, a Cortex analyzer returns the Wazuh events for an observable (IP, host, user, hash) using a read-only Wazuh account.
  - With: Diego (analyzer), Daniel (read-only account)
- [ ] **T5.4** IOC export to MISP · P3, X-25
  - Done when: Confirmed IOCs of a closed case reach MISP (TheHive's MISP connector or a Cortex responder; the license allows 1 MISP server).
  - With: Diego (MISP)
- [ ] **T5.5** Case data for Grafana (MTTD / MTTR) · P3, X-27, X-28
  - Done when: Agreed with Jesus how Grafana reads case times (contract change); TheHive side provides creation, promotion and closing times per severity.
  - With: Jesus (Grafana), Inigo (contract)

## DL · Delivery (target: 2026-12-01)

Everything merged into `main`, tested end to end and ready to show one day early. No new features after the freeze.

- [ ] **TD.1** Feature freeze (2026-11-24) · P1
  - Done when: Every P1 task of M1–M5 is done, or dropped with the integrator's agreement and noted in the README. From here on, only fixes.
  - With: Inigo (integrator)
- [ ] **TD.2** Final checkpoint pull request merged (by 2026-11-26) · P1, C3, C4, C5
  - Done when: `thehive` → `main` merged; CI green; `entities/` exported from the final configuration.
  - With: Inigo (review and merge)
- [ ] **TD.3** End-to-end run in `full` (by 2026-11-27) · P1, C1, C3, C4, C5
  - Done when: From `main`, after `thehive-import.sh`: `trigger.sh --scenario ssh-bruteforce` (Daniel's W1.5) produces a TheHive alert with the right severity, fields and template; promoted, worked and closed following TRIAGE.md.
  - With: Inigo (runs `full`), Daniel (scenarios)
- [ ] **TD.4** Evidence for the delivery (by 2026-11-30) · P1
  - Done when: README final; table of templates and fields; screenshots of an alert, a case with its tasks, and a closed case; export / import and test-alert output.
  - Files: `nodes/cases/thehive/README.md`
- [ ] **TD.5** Rehearse the demo (by 2026-11-30) · P1
  - Done when: Attack scenario → Wazuh → n8n → TheHive alert → case → Cortex / MISP enrichment → closed, start to finish without surprises.
  - With: Team

## M7 · After the delivery (target: after 2026-12-01)

Not part of the 1 December delivery.

- [ ] **T7.1** Operational dashboards in TheHive · P3
  - Done when: Open alerts by severity, cases by template and status, triage targets missed; export / import extended to dashboards.
- [ ] **T7.2** Tags and taxonomies · P3
  - Done when: Consistent TLP, MITRE ATT&CK and verdict tags; custom tags of the SOC organisation exported.
- [ ] **T7.3** Playbook pages · P3
  - Done when: A knowledge-base page per template: how to investigate, useful Wazuh queries.
- [ ] **T7.4** Approvals for C9 response actions · P3, C9
  - Done when: T4.3's approval task drives real Wazuh active response through n8n (Daniel's W7.1–W7.2).
  - With: Inigo, Daniel

## OPS · Every session and every checkpoint (target: ongoing)

Habits that keep your work safe and mergeable.

- [ ] **TO.1** Export, then push at the end of every work session · P1
  - Done when: `thehive-export.sh` run if anything changed in the UI; `git add -A && git commit -m "…" && git push` on `thehive`; only your folder changed (`git diff --stat origin/main`).
- [ ] **TO.2** Open a checkpoint pull request about every two weeks · P1
  - Done when: Export, pull main, re-test, open the pull request.
  - With: Inigo
- [ ] **TO.3** Protect the license · P1
  - Done when: Never `soc.sh reset cases`; `backup.sh cases --with-secrets` after any license change, and a copy kept outside WSL.
- [ ] **TO.4** Keep the README and the register current · P2
  - Done when: README, this backlog and the TheHive rows (`X-nn`, `R-08`) of `docs/integration-backlog.md` reflect what you changed.
  - With: Inigo (register)
- [ ] **TO.5** Re-check local patches on any TheHive upgrade · P3, C3, C4, C5
  - Done when: Each row of the README's local patches table re-checked; export / import and test alerts still work.
  - With: Inigo
