# Integration backlog (cross-component register)

Owner: the integrator (Inigo, @poinsot). Lives in `docs/`, a folder only the integrator changes.

This is **not** a merged backlog. Each owner keeps their own `BACKLOG.md`. This file lists only the items that **cross a component boundary**, so gaps and mismatches are visible in one place.

## Status of this draft

**Comparison session done (2026-09-30).** All five owners' backlogs are in: `nodes/core/n8n/BACKLOG.md`, `nodes/core/wazuh/BACKLOG.md`, `nodes/core/grafana/BACKLOG.md`, `nodes/cases/thehive/BACKLOG.md`, `nodes/cases/cortex/BACKLOG.md` + `nodes/intel/misp/BACKLOG.md` (Diego owns both, one branch `cortex-misp`). Every row below is now cross-checked against all six files, not just n8n's. Three things changed from the pre-filled draft:

1. **Every owner independently targets delivery 2026-12-01 with feature freeze 2026-11-24** (Wazuh, TheHive state it explicitly; n8n, Grafana, Cortex+MISP don't state a date yet — flagged in section F).
2. **X-19 (TheHive license) is resolved on Park's own instance**: Community license active, valid until 2027-09-29, `healthcheck.sh` shows no webhook-capability warning (TheHive T0.4). This is good evidence for PROJECT.md 16 Q6, but it answers it for Park's dev instance, **not** for the integrator's build/shared instance, whose trial still ends 2026-10-11 (docs/handoff.md) — see the note under X-19.
3. **A contract-numbering collision**: MISP's backlog explicitly proposes a new contract it calls **"C10"** (warninglist check). TheHive's backlog separately proposes direct Wazuh↔TheHive links and tentatively calls them **"C10, C11"** too. Nobody has actually reserved a number yet — see "New contract proposals" below for a recommended assignment, which still needs the integrator's decision.

## Legend

| Status | Meaning |
|---|---|
| **one-sided** | Only one owner lists it |
| **seeded** | The other owner's README backlog mentions something similar, not yet confirmed in their full backlog |
| **matched** | Both backlogs list it and Needs and Provides agree (may still be an open decision — see the Decision column) |
| **contract change** | Needs both owners' agreement, then PROJECT.md 5 and `contracts-check.sh` updated at a checkpoint |
| **open decision** | A choice both sides must make; now scheduled if a target date exists |
| **decided** | Agreed, with date and where it is recorded |
| **resolved** | The blocking condition is gone (e.g. the license is active) |
| **rejected** | Not doing it, with the reason |

References use the ID prefixes `WZ`/`W`, `N8N`, `GRAF`, `TH`/`T`, `CX`. `N8N-x.y`, `Wx.y`, `GRAF-x.y`, `Tx.y` refer to item numbers in each owner's `BACKLOG.md`.

## A. Data agreements (what the data looks like)

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-01 | Stable set of Wazuh alert fields that playbooks rely on | N8N | WZ | N8N-0.3, W2.5 | **matched** | C1 (payload unchanged, fields documented) | Target 2026-10-20 (Wazuh W2.5, checkpoint 1) |
| X-02 | Alert to TheHive mapping: severity, TLP/PAP, tags, custom fields, `sourceRef` | N8N | TH | N8N-0.4, T2.4, T2.5 | **matched, open decision** | none | Target 2026-10-20 (TheHive T2.4/T2.5, `docs/ALERT-FORMAT.md` §1/§2/§4/§5) |
| X-03 | Custom fields in TheHive for rule id, agent, MITRE technique, playbook, n8n execution id | N8N | TH | N8N-0.4, N8N-2.2, T2.1 | **matched — provided** | none | TheHive's 9 fields already built (T2.1 done); n8n to confirm coverage against N8N-0.4/2.2 |
| X-04 | Routing key for the router: rule groups plus a rule-id map | N8N | WZ, TH | N8N-1.3, W1.3, T2.6 | **matched, open decision (3-way)** | none | Target 2026-10-20; TheHive's `caseTemplate` routing (T2.6) must agree with Wazuh's rule-ID plan (W1.3) and n8n's router (N8N-1.3) at the same time |
| X-05 | Test fixtures for each rule type (extra `trigger.sh` variants; `nodes/lab/` is Wazuh's folder) | N8N | WZ | N8N-0.2, W1.5 | **matched** | none | Wazuh W1.5 adds `trigger.sh --scenario <name>` (ssh-bruteforce, sudo-fail, ioc-ip, …), target 2026-10-09 |
| X-06 | Analyzer list per observable type, with names, versions and expected run time | N8N | CX | N8N-2.4, CX (analyzers.json) | **matched, in progress** | C6 (none expected) | Cortex has defined AbuseIPDB, OTXQuery, URLhaus, MalwareBazaar, VirusTotal_GetReport, MISPWarningLists in `analyzers.json`; keys pending. `n8n-enrichment.md` (in progress) is the deliverable n8n needs |
| X-07 | Cortex report and taxonomy format that n8n reduces to a verdict | N8N | CX | N8N-2.4, CX (n8n-enrichment.md) | **matched, in progress** | none | Same deliverable as X-06 |
| X-08 | TLP/PAP policy: which observables may go to online analyzers (n8n must enforce it before running them) | N8N | CX | N8N-2.4, N8N-2.6, CX (defaults), T2.5 | **matched, defaults set** | none | Cortex defaults: `max_tlp`/`max_pap` = 2 (AMBER), job cache 10 min; TheHive defaults new alerts to TLP/PAP AMBER (T2.5) so the MISP analyzer can run. A written policy doc is still Cortex's "Next" item |
| X-09 | Alert level threshold and flood tuning (`WAZUH_ALERT_MIN_LEVEL`); the lab agent already sends many level 7+ alerts | N8N | WZ | N8N-1.4, W2.1 | **matched** | none | Wazuh W2.1 "agree the forwarding threshold with n8n owner", target 2026-10-20; default stays 7 |
| X-10 | C1 delivery is fire-and-forget (10 s timeout, no retries): should Wazuh retry or queue, or does n8n accept the risk? | N8N | WZ | N8N-1.1, W-TBD | one-sided | C1 (behaviour) if Wazuh changes it | n8n's stated position: accept the risk, answer fast (N8N-1.1) and rely on TheHive/dedup for recovery. Wazuh's backlog doesn't address it — raise at checkpoint 1 |
| X-11 | False-positive feedback: a case closed as false positive produces a tuning list for Wazuh | WZ | N8N, TH | N8N-5.3, W2.4, T4.4 | **matched** | none | TheHive T4.4 builds `thehive-fp-report.sh` (grouped by `wazuh-rule-id`) for Daniel's W2.4 tuning pass. Target: M4 (2026-11-10) |
| X-12 | Case templates and tasks per playbook | N8N | TH | N8N-5.2, T2.2, T3.5 | **matched — base provided** | none | 4 templates built (ssh-bruteforce, malware-detection, ids-network-alert, wazuh-generic; T2.2 done); T3.5 adds templates as Wazuh ships new detections |
| X-13 | Who creates cases: analyst promotes, or n8n auto-creates for named playbooks (D-N4) | N8N | TH | N8N-5.1, T3.3 | **matched, open decision** | none | TheHive T3.3, target M3 (2026-11-03): analysts promote by default, n8n may auto-promote Critical only — matches n8n's D-N4 recommendation |
| X-14 | TheHive event filtering and loop prevention: n8n ignores events caused by `n8n@asox.local`; TheHive keeps the "n8n (C4)" rule and endpoint | N8N | TH | N8N-1.5, T4.2 | **matched** | C4 (none expected) | TheHive T4.2 explicitly re-verifies this end to end at M4 (2026-11-10) |
| X-15 | Is the `analyst` profile of the n8n Service account enough for custom fields, templates and writeback? | N8N | TH | N8N-2.1, N8N-2.2, T1.3, T3.2 | **matched, in progress** | C3 if the profile changes | TheHive T1.3 confirms this by running the starter configuration on the real instance |
| X-16 | Approval design in TheHive: approval task and comment, who approves, expiry | N8N | TH | N8N-7.1, T4.3 | **matched** | none | TheHive T4.3: task "Approve: `<action>`" (group `Approval`), close = approve, cancel = reject with comment, 1 h timeout = n8n cancels. Depends on X-19 |
| X-17 | Who runs enrichment: n8n through C6, or TheHive's native connector through C5 (D-N3) | N8N, TH | CX | N8N-5.4, T4.1 | **matched, open decision (3-way)** | none | n8n's D-N3 recommendation (n8n auto-enriches at intake via C6; analysts may re-run manually via C5) matches TheHive T4.1's plan. Needs Diego to confirm and close as `decided` |
| X-18 | Rate limits and quotas of online analyzers (e.g. VirusTotal), so n8n can throttle | N8N | CX | N8N-2.4, CX (defaults) | **matched — provided** | none | Cortex has real numbers: AbuseIPDB 1000/day, VirusTotal 500/day + 4/min (shared key, "severe path only") |

## B. Behaviour and flows (what happens when)

*(carried over unchanged from A above; behaviour-specific items only)*

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-19 | Does the TheHive Community license include `notification.webhook`? Also: activate the license on the build instance before 2026-10-11 | N8N, TH | Integrator | N8N-0.1, T0.4, PROJECT.md 16 Q6 | **partially resolved** | C4 if it fails | Park's own `cases` instance (T0.4): Community license active, valid until **2027-09-29**, `healthcheck.sh` shows **no** webhook-capability warning — good evidence the Community license does include `notification.webhook`. **Still open:** the integrator's build/shared instance is unlicensed and its trial ends **2026-10-11** (docs/handoff.md); that instance still needs its own activation + `backup.sh cases --with-secrets` before then |
| X-20 | C9: response actions through Wazuh active response. Proposal: a separate Wazuh user and role (`n8n-response`, active-response only) and `n8n-api` stays read-only | N8N | WZ | N8N-8.1, W7.1 | **matched, contract change (Phase 2 / M7)** | C9 (and C2 check assertion) | Wazuh's M7 (after 2026-12-01 delivery) plans the same design session with the n8n owner; not before the December delivery |
| X-21 | Action catalog: active-response commands available per agent OS, and their timeouts | N8N | WZ | N8N-8.2, W7.1, W7.2 | **matched, Phase 2** | C9 | Wazuh names concrete commands: `firewall-drop`, `host-deny`, `disable-account`, with a protected-host whitelist |
| X-22 | C9 check workflow and `contracts-check.sh` update | WZ, N8N | Integrator | N8N-8.5, W7.1 | one-sided (integrator work, Phase 2) | C9 | |
| X-23 | Decoders and field names for pfSense and Snort alerts, so `pb-ids-alert` can be written | N8N | WZ | N8N-4.4, W4.1–W4.5 | **matched** | none | **Wazuh replaced Snort with Suricata (W3.1)** — see X-34, a change n8n's backlog (written before this) doesn't yet reflect; `pb-ids-alert` should target Suricata fields, not Snort. Target M4, 2026-11-10 |
| X-32 | Attack-start marker convention for Grafana annotations: `ASOX_ATTACK_START scenario=<x> id=<uuid>` in the lab trigger, a dedicated low-noise rule catches it | GRAF | WZ | GRAF-2.2 | one-sided | none | Grafana needs a Wazuh rule owner (Daniel) to pick this up; not in Wazuh's backlog yet — raise at checkpoint 1 |
| X-34 | Suricata replaces Snort for network IDS (Wazuh M3, decided 2026-09-29); rule groups `suricata`/`ids`, rule 86601, fields `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port` | GRAF, N8N, TH | WZ | W3.1–W3.7, T3.6, GRAF-2.3 | **matched, needs propagation** | none | Wazuh already decided this (W3.1) and asked Jesus + Inigo directly (W3.7); TheHive has already adjusted (T3.6, `ids-network-alert` template → Suricata fields). **n8n's own backlog (N8N-4.4, X-23) still says "Snort/pfSense decoders"** — n8n should update N8N-4.4 to Suricata before M4 |

## C. Blocking risks and contract changes

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-24 | MISP IOCs pushed into Wazuh CDB lists: who moves the data (a script of Cortex + MISP, or an n8n scheduled workflow)? | WZ | CX (and possibly N8N) | W6.1–W6.5, CX (later) | **matched, scheduled** | new: MISP → Wazuh CDB sync | Wazuh W6.1: "agree the design as a new contract **by 2026-10-16**" with Diego (attributes, refresh cadence, a read-only MISP key for `core` as a new `__from:intel__` value). This is the earliest cross-owner deadline in the whole plan — flag it to Daniel and Diego now |
| X-25 | Export of confirmed case IOCs from TheHive to MISP (analyst-triggered responder; allowed by D12) | CX | TH | T5.4, CX (later) | **matched, low priority** | none | Both P3/"later"; TheHive's T5.4 targets M5 (2026-11-17), Cortex has no date |
| X-26 | Custom analyzer "seen before in Wazuh?": needs Wazuh data. From Cortex, or as an n8n lib instead? | CX | WZ | CX (later), T5.3, N8N-2.7 | **matched, open decision, low priority** | new: Cortex → Wazuh, unless n8n does it | TheHive's T5.3 ("link B") reframes this as a case-side lookup via a Cortex analyzer + a read-only Wazuh account (P3, M5). Still needs a single owner decided: Cortex analyzer vs. n8n lib vs. TheHive link B are three different implementations of the same idea |
| X-27 | MTTD/MTTR dashboards need TheHive data in Grafana | GRAF | TH | GRAF-0.4, GRAF-3.1–3.3, T5.5 | **matched, open decision** | contract change (new: `asox-metrics`) | See "New contract proposals" below — Grafana's own decision (D-G1) is an n8n-written OpenSearch index, not a direct TheHive read; TheHive's T5.5 phrasing is looser ("how Grafana reads case times") and should be reconciled with D-G1 |
| X-28 | n8n stamps timestamps and custom fields into TheHive so MTTD/MTTR can be computed; n8n execution stats for dashboards | GRAF | N8N, TH | N8N-9.3, GRAF-0.4, GRAF-3.1 | **matched, priority mismatch** | none (part of the `asox-metrics` contract, X-27) | **Conflict:** Grafana's "Desempeño y cumplimiento" dashboard (GRAF-3.1–3.3, **P1**, v1.4 milestone) depends on this, but n8n has it as **N8N-9.3, P2, Phase 3 readiness** — a whole phase later than Grafana expects it. Needs a priority reconciliation between Jesus and Inigo before v1.4 |
| X-29 | Grafana alerting calling an n8n webhook (optional) | GF | N8N | GRAF-5.1 | **matched, low priority both sides** | new: Grafana → n8n webhook | Both P2/optional; no date on either side |
| X-30 | `asox-metrics` contract: new OpenSearch index that n8n writes (`alert_id`, `case_id`, `t_alert`, `t_case`, `t_contained`, `t_closed`, `playbook`, `outcome`) and Grafana reads read-only | GRAF | N8N | GRAF-0.4 | **one-sided, proposal ready** | new contract — see below | Grafana has a full schema proposal (GRAF-0.4) and knows the `grafana-ro`-equivalent role change it needs. n8n hasn't responded yet; **this is the same underlying need as X-27/X-28** — treat as one negotiation, not three |
| X-31 | Proposed contract "C10": n8n → MISP warninglist check. Before enrichment, n8n sends all of an alert's observables to MISP in one call (`POST /warninglists/checkValue`) to learn which are *common* (not *safe* — never auto-clears anything, D12 still applies) | N8N | CX/MISP | MISP backlog §"Proposal: contract C10" | **one-sided, proposal ready, blocked on n8n** | new contract — needs a real number, see below | Diego has fully specified the changes needed on his side (new Read Only user `n8n@asox.local`, its own API key) and the integrator's side (`MISP_N8N_API_KEY=__from:intel__`, credential in `bootstrap.sh`, a check in `contracts-check.sh`). **Blocked purely on Inigo's agreement** — until then n8n can get the same answer per-observable through the MISPWarningLists analyzer via existing C6 |

## New contract proposals — numbering collision

Three different owners have proposed a *new* contract and, in two cases, guessed at a number without checking with anyone else:

- **MISP backlog** explicitly claims **"C10"** for the n8n → MISP warninglist check (X-31).
- **TheHive backlog** (T5.1) tentatively suggests **"C10, C11"** for two different things: Wazuh → TheHive direct alerts (link A) and TheHive → Cortex/Wazuh lookup (link B).
- **Grafana backlog** (GRAF-0.4) doesn't guess a number, but its `asox-metrics` index is also a new contract (X-27/X-28/X-30).

PROJECT.md 5 says a contract change "must be agreed by both owners first" and is "updated by the integrator" — no owner should assign the number themselves. **Recommended assignment**, pending the integrator's decision and each pair of owners' sign-off:

| Proposed # | Contract | Needs sign-off from |
|---|---|---|
| C9 | *(already reserved)* Wazuh active response, Phase 2 | n8n, Wazuh |
| C10 | n8n → MISP warninglist check (X-31) — furthest along, has a full spec already | n8n, Cortex+MISP |
| C11 | Grafana → `asox-metrics` (n8n-written OpenSearch index) (X-27/X-28/X-30) | Grafana, n8n |
| C12 | Wazuh → TheHive direct alert link ("link A", T5.1–T5.2) | Wazuh, TheHive |
| C13 | TheHive → Cortex/Wazuh case-side lookup ("link B", T5.3), same idea as X-26 | TheHive, Cortex, Wazuh |

Until the integrator confirms this table and updates PROJECT.md 5, owners should keep referring to these by their X-numbers, not by C10/C11 guesses, to avoid two different things being called "C10" in commit messages and pull requests.

## D. Flows that involve components other than n8n

*(folded into sections A–C above via X-24 through X-31; kept as a pointer)*

See X-24 (MISP→Wazuh CDB), X-25 (TheHive→MISP export), X-26 (seen-before-in-Wazuh), X-27/X-28/X-30 (Grafana metrics), X-29 (Grafana→n8n alerting).

## E. Requests to the integrator (shared files)

Owners add rows here for anything in shared files (rule 3 of the light rules).

| ID | Request | From | Refs | Status |
|---|---|---|---|---|
| R-01 | New credentials or webhook credentials added to `bootstrap.sh` (as playbooks need them) | N8N | N8N-9.2 | open |
| R-02 | End-to-end check (Wazuh to n8n to TheHive alert exists) in `contracts-check.sh`, and the C9 check | N8N | N8N-0.6, N8N-8.5 | open |
| R-03 | Workflow lint (naming, header note, credentials by ID, no hardcoded hosts or secrets) in `ci-checks.sh` | N8N | N8N-0.7 | open |
| R-04 | n8n self-check (workflows active, alert lag) in `healthcheck.sh` | N8N | N8N-6.4 | open |
| R-05 | `soc.sh` support for `COMPOSE_PROFILES=pg` (if Postgres is chosen) | N8N | N8N-6.7 | open |
| R-06 | New env var for restricted syslog sources (`WAZUH_SYSLOG_ALLOWED_IPS`) in `nodes/core/.env.example` + `render-env.sh` | WZ | W1.1 | open |
| R-07 | Memory variable for Suricata in `nodes/lab/.env.example` + `render-env.sh`; re-check `core` still fits `low` (6 GB) once Suricata is running | WZ | W3.2, W3.6 | open |
| R-08 | New `__from:intel__` value for a read-only MISP key for `core` (CDB sync, X-24) | WZ | W6.1 | open, target 2026-10-16 |
| R-09 | `.gitignore` entry for `nodes/cases/cortex/analyzers/analyzer-keys.env` | CX | Cortex backlog "For the other owners" | open, small, review at checkpoint |
| R-10 | Cortex config/compose change so Cortex also reads custom analyzers from `analyzers/`, not only the online catalog | CX | Cortex backlog "Next" | open |
| R-11 | Grafana `grafana-ro` role change once `asox-metrics` (C11 proposal) is agreed | GRAF | GRAF-0.4 | open, blocked on X-27/X-30 |
| R-12 | TheHive Service account for Wazuh, if link A (C12 proposal) is accepted | TH | T5.2 | open, blocked on X-33/C12 decision |
| R-13 | `MISP_N8N_API_KEY=__from:intel__`, `MISP_URL` for n8n, an n8n credential in `bootstrap.sh`, and a C10 check in `contracts-check.sh`, if the warninglist proposal (X-31) is accepted | CX, N8N | MISP backlog "Proposal: contract C10" | open, blocked on n8n's agreement |
| R-14 | **Known issue, not a request but flag for the memory budget:** `misp-config.sh apply` disables MISP warninglists above 100,000 entries because the 1M-entry Cisco Umbrella list OOM-kills every warninglist check under misp-core's current 900m limit. Affects `main` today (any fresh `intel` node inherits it until this branch merges). Re-measure before raising the limit or re-enabling large lists | CX | MISP backlog "Known issue" | informational, watch at the cortex-misp checkpoint |

## F. Dependency order and delivery alignment

Which cross-boundary items must be settled before each milestone. Adjust after each checkpoint.

**Alignment check (2026-09-30):** Wazuh and TheHive both target **feature freeze 2026-11-24, delivery 2026-12-01**, and their milestone dates line up almost exactly (M0 2026-10-02, checkpoint-1 2026-10-20, M3 2026-11-03, M4 2026-11-10, M5 2026-11-17). **n8n, Grafana and Cortex+MISP haven't stated calendar dates yet** — only priorities and rough milestones (v1.1/v1.2/v1.3). Since n8n's and TheHive's checkpoint-1 items (X-01 through X-04, X-09) share the same 2026-10-20 target, the integrator should ask Inigo (n8n), Jesus (Grafana) and Diego (Cortex+MISP) to confirm they can hit 2026-10-20 too, or the checkpoint slips for everyone.

| Milestone | Must be decided or delivered first | Because | Target date |
|---|---|---|---|
| Checkpoint 1 / `v1.1-detections` first slice (alert to enriched TheHive alert) | X-19 (build instance license), X-01, X-02, X-03, X-04, X-09, X-17, X-06 | n8n cannot build `pb-generic` without the license answer, the field list, the mapping, the routing key and the enrichment ownership | **2026-10-20** (Wazuh W2.6, TheHive T2.7 both name this date) |
| Before checkpoint 1 | X-24 design agreement (Wazuh + Diego) | Wazuh's own deadline, earlier than checkpoint 1 | **2026-10-16** (Wazuh W6.1) |
| `v1.2` playbooks | X-05, X-08, X-12, X-13, X-23/X-34 (now Suricata, not Snort) | Test data, TLP/PAP policy, templates and the policy on what may leave the lab | Wazuh M3–M4 (2026-11-03 to 2026-11-10) |
| `v1.3` approval | X-16, X-19 (build-instance license activated) | Approval lives in TheHive and relies on C4 | Before TheHive M4 (2026-11-10) |
| `v1.4` Grafana "Desempeño y cumplimiento" | X-27, X-28, X-30 (the `asox-metrics` / proposed-C11 contract) | Grafana's own dashboard is an "empty shell" (Grafana's stated risk 1) without it; **currently blocked by the N8N-9.3 priority mismatch** (X-28) | Grafana has no date; flag against the 2026-12-01 delivery |
| Phase 2 | X-20, X-21, X-22, X-31 (proposed C10), R-13 | C9 and the MISP warninglist contract need both owners and a contract update | Wazuh M7 (after 2026-12-01) |
| Phase 3 | X-28 (as currently scoped), X-29 | Depends on the shape of earlier work | No date |

## Comparison session checklist

1. ~~Collect every owner's `BACKLOG.md`~~ — **done 2026-09-30**, all six files linked at the top of this file.
2. ~~Add their Needs and Provides as rows in sections A to D~~ — **done this session.**
3. ~~For every row, set the status~~ — **done this session**, including three new proposals (X-30, X-31, and the folded-in Wazuh/TheHive link items) and one priority mismatch (X-28) surfaced.
4. **Next (integrator, before checkpoint 1 on 2026-10-20):**
   - Take X-10 (C1 retries) to Daniel — currently only n8n has a position.
   - Take X-32 (attack-start marker rule) to Daniel — Grafana needs a rule owner.
   - Resolve the C10/C11/C12/C13 numbering collision (see "New contract proposals") and update PROJECT.md 5 once each pair agrees.
   - Reconcile X-28's priority mismatch between Jesus and Inigo (Grafana P1/v1.4 vs. n8n P2/Phase 3).
   - Ask Inigo, Jesus and Diego whether they can commit to the shared 2026-10-20 / 2026-11-24 / 2026-12-01 dates Wazuh and TheHive have already set.
   - Confirm the build/shared instance's TheHive license is activated before **2026-10-11** (X-19 remaining half) — separate from Park's already-resolved dev instance.
5. Record design decisions in `docs/decisions.md` with the date, and contract changes in PROJECT.md 5 at a checkpoint.
6. Re-read section F and adjust milestones after each checkpoint.
7. After each checkpoint pull request, update this file.
