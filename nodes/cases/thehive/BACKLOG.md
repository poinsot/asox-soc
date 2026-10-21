# TheHive owner backlog

Owner: Park (@Jinhyuk-P). Branch `thehive`. Folder `nodes/cases/thehive/`. Plan as of 2026-09-30, updated after the integration session (`docs/integration-backlog.md`, PROJECT.md 5 and D44–D49).

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

## Decisions of 2026-09-30 that change this backlog

| Decision | What it means for TheHive | Items |
|---|---|---|
| **C12 rejected (D47):** no direct Wazuh → TheHive alert link; everything goes C1 → n8n → C3 (n8n is the single orchestration point, D12) | Link A is closed; no Service account for Wazuh (R-12 closed) | T5.1, T5.2 closed |
| **C13 accepted (D48):** "seen before in Wazuh?" is a Cortex analyzer that calls n8n's read-only `wazuh-lookup` webhook; n8n queries the indexer | Replaces link B: nothing to build in TheHive; analysts run the analyzer from a case (C5). Its field map already covers the `user-account` observable type | T5.3 |
| **C11 accepted (D46):** `asox-metrics`, written by n8n from its TheHive writeback and C4 events, read by Grafana | MTTD / MTTA / MTTR need nothing built in TheHive; its `resolution` field is TheHive's resolution status, so closing cases consistently (TRIAGE.md) matters | T5.5 closed, T4.2 |
| **C9 designed (D44):** response only through Wazuh's built-in `firewall-drop`, `host-deny`, `disable-account` (Phase 2) | `containment-action` values `host-isolated` / `file-removed` stay manual-only until custom active-response scripts exist (X-21) | T3.7 |
| **D49:** Suricata replaces Snort | `ids-network-alert` and the routing use Suricata (rule 86601, groups `suricata` / `ids`) | T3.6 |
| **D-N1:** dedup by `sourceRef` = Wazuh alert ID | Agreed in principle; formal when T2.4 is ticked | T2.4 |
| **D-N2:** routing key = Wazuh rule groups + a rule-ID map, kept as data in an n8n `lib-` workflow | TheHive's `caseTemplate` table (ALERT-FORMAT.md §3) is one input of that map (3-way with W1.3) | T2.6 |
| **D-N3:** n8n enriches at intake (C6); analysts re-run by hand (C5) | Agreed by n8n and TheHive; pending the Cortex + MISP owner, due checkpoint 1 | T4.1 |
| **D-N4:** analysts promote by default; n8n auto-promotes only **Critical** alerts of named playbooks | ALERT-FORMAT.md R2 updated to this combination; to confirm by 2026-11-03 | T3.3, T1.3 |
| **D-N5:** approval task "Approve: `<action>`" (close = approve, cancel = reject, 1 h timeout) | Matches T4.3; a channel abstraction lets Slack approve later | T4.3 |
| **D-G4:** Grafana uses the same severity cut-offs (0–6 / 7–9 / 10–11 / ≥ 12) | Consistent with ALERT-FORMAT.md §2 | T2.5 |

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
- [ ] **T0.5** Verify the baseline you own · P1, C5, X-19
  - Done when: `contracts-check.sh --only C5` passes in `cases`; C3 and **C4 against this Community license** checked once in `full` or on the integrator's run. C4 on a Community license: **resolved 2026-09-30** (X-19, Inigo captured 20 real C4 events); left: `contracts-check.sh --only C5` on your machine.
- [ ] **T0.6** Read the contracts and the TheHive chapter · P2
  - Done when: Read PROJECT.md 5, 6.4, 11, `nodes/cases/thehive/README.md`, CONTRIBUTING.md; run `scripts/ci-checks.sh all` once.
  - Files: `PROJECT.md`, `CONTRIBUTING.md`, `nodes/cases/thehive/README.md`
- [ ] **T0.7** Tell the integrator your RAM and Windows version · P3
  - Done when: Inigo has PROJECT.md 16 questions 1 and 3 (64 GB, Windows 11). The license result (X-19) is already recorded in the register.
  - With: Inigo (integrator)
## M1 · Configuration as code and tools (target: 2026-10-09)

Everything built in the UI reaches git, and alerts can be tested without Wazuh.

- [x] **T1.1** Export / import scripts for the UI configuration · P1
  - Done when: `thehive-export.sh` writes custom fields, observable types and case templates to `entities/*.json` (sorted, no IDs); `thehive-import.sh` recreates them by name, never deletes, and a second run says *unchanged*. Round trip tested on the real instance.
  - Files: `nodes/cases/thehive/scripts/`, `nodes/cases/thehive/entities/`
- [x] **T1.2** Test alert generator · P1, C3
  - Done when: `thehive-test-alert.sh [SCENARIO...|all] [--critical-asset] [--promote]` creates realistic Wazuh-style alerts through n8n's own account, one scenario per template (ssh, malware, ids, generic, login, sudo, newuser, ioc, portscan); `--promote` turns each into a case as n8n would; `--cleanup` deletes test alerts and test cases; `shellcheck` clean.
  - Files: `nodes/cases/thehive/scripts/thehive-test-alert.sh`
- [ ] **T1.3** Run the starter configuration on the real instance · P1, X-03, X-15
  - Done when: `thehive-import.sh` creates 9 fields, 1 observable type, 12 templates; `thehive-test-alert.sh all --promote` creates 12 alerts and promotes each **with n8n's key** (`POST /api/v1/alert/<id>/case`, D-N4's auto-promotion: X-15), each case getting its template's tasks; `thehive-export.sh` then shows no diff. Tell Inigo, so X-03 and X-15 can be marked provided.
  - Status (2026-10-06): **done on the build instance**: Inigo ran `thehive-import.sh` (after `backup.sh cases --with-secrets`): 9 fields, 9 templates, `user-account`; `caseTemplate` and custom fields now kept on n8n's alerts. Left: the same run on your own machine, then tick.
  - Earlier (2026-09-30): Inigo measured that the **build instance** had no `entities/` loaded (templates and fields silently dropped, `user-account` alerts refused). Run `thehive-import.sh` there too, before 2026-10-20. n8n's account promoting an alert (HTTP 201) is already confirmed by him.
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
- [x] **T2.4** Agree the alert format with the n8n owner (by 2026-10-20) · P1, C3, X-02
  - **Done 2026-10-14:** ALERT-FORMAT §1, §4, §5 agreed with n8n (TheHive PR #19, n8n PR #23; X-02); status line says agreed; D-N1 formal.
  - Done when: `docs/ALERT-FORMAT.md` §1, 4, 5 accepted by Inigo (fields, tags, custom fields, observables, `source` = `wazuh`, `sourceRef` = Wazuh alert ID); its status line changed from proposal to agreed. Ticking this makes D-N1 (dedup by `sourceRef`, already agreed in principle) formal.
  - Files: `nodes/cases/thehive/docs/ALERT-FORMAT.md`
  - Status (2026-10-14): **agreed**, ALERT-FORMAT status line changed (n8n PR #23 applied A, F; G revised with Diego's warninglist-description proposal; `Ignored` = false positive confirmed for C11). Tick after the checkpoint merge.
  - Earlier (2026-10-08): Inigo reviewed §1–§5 on 2026-10-06 and n8n follows them; his questions A–E answered in the doc (Time row, optional `full_log`, all routing rows active, `playbook` = playbook that ran, `pfsense` = firewall, MISP hit = suspicious and `ioc: false`). Syslog host rule (`predecoder.hostname` when `agent.id` = `000`) added from Daniel's fields review. Left: Inigo accepts A–E, then status → agreed.
  - With: Inigo (n8n owner)
- [x] **T2.5** Agree the severity / TLP / PAP mapping (by 2026-10-20) · P1, X-02, X-08
  - **Done 2026-10-14:** §2 accepted by n8n as written (`ALERT-TO-THEHIVE.md` §7); the cut-offs 0–6 / 7–9 / 10–11 / 12+ are shared with Wazuh (W2.1) and Grafana (D-G4); TLP/PAP 2 matches the analyzers' `max_tlp` / `max_pap` (X-08, still to be written in Diego's policy).
  - Done when: `docs/ALERT-FORMAT.md` §2 accepted: level 12–15 Critical, 10–11 High, 7–9 Medium, +1 for critical assets; TLP / PAP AMBER. Already consistent with Grafana's buckets (D-G4), Cortex's analyzer defaults (`max_tlp` / `max_pap` 2, X-08) and Daniel's Suricata mapping (W3.5: severity 1 → 12, 2 → 10); still needs Daniel's level policy (W2.1) and Inigo's agreement.
  - With: Inigo, Daniel (W2.1), Diego (X-08)
- [x] **T2.6** Agree the template routing (by 2026-10-20) · P1, X-04
  - **Done 2026-10-15:** §3 = n8n's `lib-config` routing row for row, rules confirmed by Wazuh (X-04); every row active (`ioc-match` since C14 went live).
  - Done when: `docs/ALERT-FORMAT.md` §3 matches Daniel's rule-ID plan and rule groups (W1.3, W2.5), including Suricata's `suricata` / `ids` groups (D49), and Inigo's routing map (D-N2, data in an n8n `lib-` workflow) sets `caseTemplate` from it.
  - Status (2026-10-14, later): **agreed and merged** (TheHive PR #19, n8n PR #23): n8n's routing matches §3 row for row; ALERT-FORMAT marked agreed. `ioc-match` active since 2026-10-15 (C14 live): all routing rows active.
  - Earlier (2026-10-14): proposal for Inigo's question on rule 103011 (OPNsense login brute force): `ssh-bruteforce` requires `sshd`, new `login-bruteforce` template and row for other T1110 alerts; to agree in the checkpoint PR.
  - Earlier (2026-10-13): §3 matches n8n's table of 2026-10-09 (adds rule 5404 and `T1136` clauses; `ioc-match` / `network-scan` proposed in n8n until their rules exist).
  - Earlier (2026-10-08): §3 rewritten from Daniel's live alerts (answers A1–A6) and rules of 2026-10-08: `ioc-match` first (`misp_ioc`, 108xxx), `suspicious-login` before `ssh-bruteforce` on rule IDs 40112 / 100200, `privilege-escalation` on `T1548`, `account-change` on `adduser` only, `network-scan` on `pfsense` + `T1046` (103xxx). Left: Inigo's `lib-config` rows match it; Daniel's W4.3 / C14 rule IDs when built.
  - With: Inigo (router), Daniel (rule groups)
- [x] **T2.7** Checkpoint 1 pull request (by 2026-10-20) · P1, C3, C4, C5
  - **Done 2026-10-14:** checkpoint PR #19 (`thehive` → `main`) merged by the integrator; later answers go in the next PR.
  - Done when: `git pull --no-rebase --no-edit origin main`, `healthcheck.sh` green, `contracts-check.sh --only C5` passes (C3, C4 in `full`), `ci-checks.sh all` passes, pull request `thehive` → `main` opened and merged by the integrator.
  - With: Inigo (review and merge)

## M3 · Triage and case workflow (target: 2026-11-03)

Analysts can work every alert type from queue to closed case.

- [x] **T3.1** Triage procedure · P1
  - Done when: `docs/TRIAGE.md`: alert queue, triage step by step, working and closing a case.
  - Files: `nodes/cases/thehive/docs/TRIAGE.md`
- [x] **T3.2** Users and roles under the 2-user license · P1, X-15
  - Done when: `docs/TRIAGE.md` lists every account and profile; second seat reserved for the shared instance; optional read-only viewer.
- [x] **T3.3** Agree the alert-to-case rules (by 2026-11-03) · P1, X-13
  - **Done 2026-10-21:** D-N4 accepted (ALERT-FORMAT §6 R2 written out: only routes with a named playbook other than `pb-generic`, Critical only, analyst takes the case within 15 min; status line says agreed). Unblocks N8N-5.1, GRAF-3.2/3.3, D-G5 (X-13).
  - Done when: `docs/ALERT-FORMAT.md` §6 accepted with D-N4: analysts promote by default; n8n auto-promotes only **Critical** alerts of named playbooks; merge same agent + template within 24 h; triage targets.
  - With: Inigo (n8n owner)
- [ ] **T3.4** Walk every test alert through the procedure · P1
  - Done when: For each scenario of `thehive-test-alert.sh`: triage, promote or merge or ignore, work the tasks, close with a summary and resolution status. Screenshots kept for the delivery; gaps fixed in the templates or TRIAGE.md.
  - How: step by step in `docs/DEMO.md`, "Practice run (T3.4)".
  - Also (2026-10-08): with `full` mode, real Wazuh alerts are available from `nodes/lab/trigger.sh --scenario NAME` (ssh-bruteforce, ssh-success-after-fail, sudo-fail, new-user, root-login, ioc-ip), which go Wazuh → n8n → TheHive end to end; use them after the `thehive-test-alert.sh` round.
- [ ] **T3.5** Templates for the new detections · P2, X-12
  - Done when: A template (or a documented choice of `wazuh-generic`) for each detection Daniel adds: login success after failures, sudo failure / privilege escalation, new user, IOC match (W6.4), pfSense port scan (W4.3). Exported, and routed in ALERT-FORMAT.md §3.
  - Files: `nodes/cases/thehive/entities/case-templates.json`, `nodes/cases/thehive/docs/ALERT-FORMAT.md`
  - Status (2026-10-20): + `web-attack` (groups `web` + `attack`: 31103, 31152) and `file-integrity` (group `syscheck`: 550, 553, 554, 100302) for Daniel's new `web-attack` and `fim-tamper` scenarios, proposed until n8n checks them against the fixtures (X-44); test scenarios `web` and `fim`.
  - Earlier (2026-10-14): + `login-bruteforce` (non-SSH brute force: 103011, 40111, 2502), agreed and routed by n8n; `fwlogin` test scenario passes on the real instance. Test IOC is now `101.99.75.184` (X-36); `ioc` uses rule 108000, `portscan` 103000.
  - Earlier (2026-10-08): 5 templates written, loaded on the build instance, and routed in §3 with Daniel's confirmed groups and rules (all rows active). Descriptions name the real rules (40112, 100200, 5404, 5901/5902, 100211/100212; ranges 103xxx, 108xxx). Left: import + export on your machine; `ioc-match` and `network-scan` get real rules with C14 and W4.3.
  - With: Daniel (W2.2, W4.3, W6.4)
- [x] **T3.6** Adapt `ids-network-alert` to Suricata · P2, X-34
  - **Done 2026-10-08:** template and `ids` scenario name Suricata (86601); imported on the real instance.
  - Done when: ALERT-FORMAT.md §3 routes `suricata` / `ids` (done 2026-09-30); the template's description and tasks name Suricata (rule 86601, `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port`), exported; the `ids` test alert uses rule 86601 and those fields.
  - Files: `nodes/cases/thehive/entities/case-templates.json`, `nodes/cases/thehive/scripts/thehive-test-alert.sh`
  - Status (2026-09-30): template and `ids` scenario done; left: import + export on the real instance.
  - With: Daniel (W3.7)
- [x] **T3.7** Align `containment-action` with C9's action catalog · P2, X-21
  - **Done 2026-10-08:** `containment-action` description and ALERT-FORMAT §4 / TRIAGE.md say which values n8n can set and which stay manual-only; imported on the real instance.
  - Done when: ALERT-FORMAT.md §4 and TRIAGE.md say which values an n8n playbook can set (`ip-blocked` ← `firewall-drop` / `host-deny`, `user-disabled` ← `disable-account`) and which stay manual-only (`host-isolated`, `file-removed`) until Wazuh has custom active-response scripts (docs done 2026-09-30); the field's description in `entities/custom-fields.json` says the same, imported and exported.
  - Files: `nodes/cases/thehive/entities/custom-fields.json`, `nodes/cases/thehive/docs/`
  - Status (2026-09-30): description updated in `custom-fields.json`; left: import + export on the real instance.
  - With: Daniel (C9, Phase 2)
## M4 · Interface with n8n (target: 2026-11-10)

TheHive and n8n work together without loops, duplicates or unapproved actions.

- [x] **T4.1** Confirm who runs enrichment (due checkpoint 1, 2026-10-20) · P1, C5, C6, X-17
  - **Done 2026-09-30 / 10-06:** D-N3 confirmed by Diego (X-17 decided); n8n enriches at intake with MISP_2_1, analysts re-run by hand (TRIAGE.md step 3).
  - Done when: Diego confirms D-N3 (already agreed by n8n and TheHive): n8n enriches automatically at intake (C6); analysts re-run analyzers by hand from TheHive (C5).
  - Status (2026-09-30): Diego's backlog confirms D-N3 (per Inigo's note); left: X-17 marked agreed in the register.
  - With: Diego (Cortex + MISP), Inigo
- [x] **T4.2** Check C4 end to end and loop prevention · P1, C4, X-14, X-19
  - **Done 2026-10-14:** C4 passes on `main` with the Community license (X-19 resolved); n8n drops events by `n8n@asox.local` and ignores deletes (N8N-1.5, X-14 matched). Re-checked end to end in TD.3.
  - Done when: In `full` (or the integrator's run): C4 passes with a **Community** license; n8n ignores events caused by `n8n@asox.local`; the "n8n (C4)" rule and `n8n` endpoint untouched. C11's `t_ack`, `t_case`, `t_closed` (X-28) and the approval flow depend on it.
  - Status (2026-09-30): Inigo captured 20 real C4 events on the Community license (X-19 closed) and n8n drops events by `n8n@asox.local`. Open: delete events carry no object (N8N-1.5), and deleting a case reopens its alert with no event (TRIAGE.md now says: never delete a real case).
  - With: Inigo (integrator)
- [x] **T4.3** Approval design in TheHive · P2, X-16
  - **Done 2026-09-30:** D-N5 written in TRIAGE.md ("Approving a response action"); X-16 matched by n8n. Built with C9 (T7.4).
  - Done when: D-N5 written in TRIAGE.md: the playbook adds a task "Approve: <action>" (group `Approval`); closing it approves, cancelling rejects (with a comment); C4 carries the task update; no answer in 1 h → n8n cancels it. Slack can be added later behind n8n's channel abstraction.
  - Status (2026-09-30): written in TRIAGE.md, "Approving a response action"; left: Inigo's review.
  - With: Inigo (n8n owner)
- [ ] **T4.4** False-positive report for Wazuh tuning · P2, X-11
  - Done when: `scripts/thehive-fp-report.sh` lists cases and alerts closed as False positive / Ignored, grouped by `wazuh-rule-id` with counts and reasons; Daniel uses it for W2.4. Grafana gets the same rate from C11's `resolution` field.
  - Files: `nodes/cases/thehive/scripts/`
  - Status (2026-09-30): `thehive-fp-report.sh [--days N] [--out FILE]` written (read-only, Markdown, test objects left out); left: run it on the real instance after T3.4, send it to Daniel.
  - With: Daniel (W2.4)
- [x] **T4.5** Review n8n's checkpoint pull request (`n8n` → `main`) · P1, C3, C4
  - **Done 2026-10-14:** n8n's alert output reviewed line by line through `ALERT-TO-THEHIVE.md` §8–§9 and answers A–G (`docs/reply-n8n-2026-10-14.md`); n8n PR #23 applied them. Later n8n PRs: check them the same way before the freeze (TD.1).
  - Done when: As second owner of C3 and C4, checked that what n8n writes to TheHive matches ALERT-FORMAT.md (fields, tags, `customFields` array, observables, writeback comment `[asox-n8n writeback] …`) and that its C4 router ignores its own events; comments left on the PR before Inigo merges.
  - With: Inigo (n8n owner)
- [x] ~~**T4.6** Answer n8n's ALERT-FORMAT questions~~ · closed 2026-09-30
  - Answered in ALERT-FORMAT.md: `rule.mitre_techniques` fallback and prefix match (§3), non-atomic dedup (§1), `customFields` as an array and `rule.id` cast (§4), `data.hostname` → `fqdn` / `ip` / `hostname` and `range:` tags (§5); TRIAGE.md: never delete a real case.
- [ ] **T4.7** Jev (AI triage judge) fields in TheHive · P3, C16 (proposed), X-39, X-41
  - Done when: Once C16 is accepted (after C11): the custom fields `jev-verdict`, `jev-p-fp`, `jev-confidence`, `jev-decision`, `jev-mode` are in `entities/custom-fields.json` and created with `thehive-import.sh` (TheHive's part per `docs/jev-implementation.md` §18); ALERT-FORMAT §4–§5 list them and the `jev:` tags; Q6 answered (severity threshold 3).
  - Status (2026-10-13): proposal only (Jev v0.2, branch `n8n`); C16 waits for C11. Q6 answered: yes, 3 (High) fits ALERT-FORMAT §2.
  - With: Inigo (n8n owner)
## M5 · Intel and metrics (target: 2026-11-17)

The direct Wazuh ↔ TheHive links were decided on 2026-09-30: link A rejected (C12), link B replaced by C13. What remains here are the intel flows.

- [x] ~~**T5.1** Decide the direct links as new contracts~~ · closed 2026-09-30
  - Decided by the integrator: link A = C12, **rejected** (D47: contradicts D12 and reintroduces the dedup problem); link B = C13 (T5.3). README "Design discussion" records it.
- [x] ~~**T5.2** Link A, TheHive side~~ · closed 2026-09-30, rejected (C12, D47)
  - Nothing to build; the Service account request (R-12) is closed.
- [ ] **T5.3** Use the "seen before in Wazuh?" analyzer from cases · P3, C13, X-26
  - Done when: Once Diego's C13 analyzer is enabled (needs R-10, R-15, R-16), running it from a case on an `ip`, `hostname` or `user-account` observable returns the Wazuh history (count, first / last seen, rules, agents); TRIAGE.md step 3 mentions it. Nothing to build in TheHive.
  - With: Diego (analyzer), Inigo (`wazuh-lookup` webhook)
- [ ] **T5.4** IOC export to MISP · P3, X-25
  - Done when: Confirmed IOCs of a closed case reach MISP (analyst-triggered, allowed by D12; through TheHive's MISP connector, which uses the license's single MISP-server slot, or a Cortex responder).
  - With: Diego (MISP)
- [x] ~~**T5.5** Case data for Grafana (MTTD / MTTR)~~ · closed 2026-09-30, satisfied by C11 (D46)
  - n8n writes `asox-metrics` from its TheHive writeback and C4 events; TheHive builds nothing. TheHive's part is using resolution statuses consistently (TRIAGE.md, "Closing") and C4 working (T4.2).
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
  - Files: `nodes/cases/thehive/README.md`, `nodes/cases/thehive/docs/DEMO.md`
  - Status (2026-10-21): checklist of what to capture in `docs/DEMO.md` ("Evidence"); captures left.
- [ ] **TD.5** Rehearse the demo (by 2026-11-30) · P1
  - Done when: Attack scenario → Wazuh → n8n → TheHive alert → case → Cortex / MISP enrichment → closed, start to finish without surprises.
  - Status (2026-10-21): TheHive's part of the demo written in `docs/DEMO.md` (fits Daniel's `demo.sh` / `DEMO.md`, WD.5); rehearsal left.
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
  - Done when: T4.3's approval task drives real Wazuh active response through n8n as the separate user `n8n-response` (D44; Daniel's W7.1–W7.2), and the playbook sets `containment-action`.
  - With: Inigo, Daniel
- [ ] **T7.5** Storage hardening: Cassandra authentication and a dedicated Elasticsearch user · P3, A52
  - Done when: Cassandra runs with `PasswordAuthenticator` and a `thehive` role; TheHive uses an Elasticsearch user limited to `thehive*` indexes instead of `elastic`; `config/application.conf` reads both passwords from the environment; backup taken first, license and data kept, C3–C5 pass.
  - Files: `nodes/cases/thehive/config/application.conf`, `nodes/cases/thehive/compose.yml`
  - With: Inigo (`storage.yml`, `.env.example`, `bootstrap.sh`), Diego (Cortex's own user)

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
  - Done when: README, this backlog and TheHive's rows of `docs/integration-backlog.md` (X-nn, and section G) reflect what you changed; requests for shared files go to Inigo as new R-nn rows (TheHive has none open: R-12 closed).
  - With: Inigo (register)
- [ ] **TO.5** Re-check local patches on any TheHive upgrade · P3, C3, C4, C5
  - Done when: Each row of the README's local patches table re-checked; export / import and test alerts still work.
  - With: Inigo
