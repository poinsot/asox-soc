# Integration backlog (cross-component register)

Owner: the integrator (Inigo, @poinsot). Lives in `docs/`, a folder only the integrator changes.

This is **not** a merged backlog. Each owner keeps their own `BACKLOG.md`. This file lists only the items that **cross a component boundary**, so gaps and mismatches are visible in one place.

## Status of this draft

Pre-filled from the **n8n backlog only**. Every row marked `one-sided` still needs the other owner's response. Rows marked `seeded` mean the other component's README backlog already mentions something similar, but their full backlog hasn't been read yet. Update this file after each owner submits their `BACKLOG.md`.

## Legend

| Status | Meaning |
|---|---|
| **one-sided** | Only one owner lists it |
| **seeded** | The other owner's README backlog mentions it, not yet confirmed in their full backlog |
| **matched** | Both backlogs list it and Needs and Provides agree |
| **contract change** | Needs both owners' agreement, then PROJECT.md 5 and `contracts-check.sh` updated at a checkpoint |
| **open decision** | A choice both sides must make |
| **decided** | Agreed, with date and where it is recorded |
| **rejected** | Not doing it, with the reason |

References use the ID prefixes `WZ`, `N8N`, `GF`, `TH`, `CX`. Refs written `TBD` are to be filled after the owner's backlog arrives. `N8N-x.y` refers to the item numbers in `n8n-backlog.md`.

## A. Data agreements (what the data looks like)

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-01 | Stable set of Wazuh alert fields that playbooks rely on | N8N | WZ | N8N-0.3, WZ-TBD | one-sided | C1 (payload unchanged, fields documented) | |
| X-02 | Alert to TheHive mapping: severity, TLP/PAP, tags, custom fields, `sourceRef` | N8N | TH | N8N-0.4, TH-TBD | seeded (TheHive README: severity/TLP/PAP mapping, custom fields) | none | |
| X-03 | Custom fields in TheHive for rule id, agent, MITRE technique, playbook, n8n execution id | N8N | TH | N8N-0.4, N8N-2.2, TH-TBD | seeded | none | |
| X-04 | Routing key for the router: rule groups plus a rule-id map | N8N | WZ | N8N-1.3, WZ-TBD | one-sided | none | |
| X-05 | Test fixtures for each rule type (extra `trigger.sh` variants; `nodes/lab/` is Wazuh's folder) | N8N | WZ | N8N-0.2, WZ-TBD | one-sided | none | |
| X-06 | Analyzer list per observable type, with names, versions and expected run time | N8N | CX | N8N-2.4, CX-TBD | one-sided | C6 (none expected) | |
| X-07 | Cortex report and taxonomy format that n8n reduces to a verdict | N8N | CX | N8N-2.4, CX-TBD | one-sided | none | |
| X-08 | TLP/PAP policy: which observables may go to online analyzers (n8n must enforce it before running them) | N8N | CX | N8N-2.4, N8N-2.6, CX-TBD | seeded (Cortex + MISP README: TLP/PAP policy) | none | |

## B. Behaviour and flows (what happens when)

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-09 | Alert level threshold and flood tuning (`WAZUH_ALERT_MIN_LEVEL`); the lab agent already sends many level 7+ alerts | N8N | WZ | N8N-1.4, WZ-TBD | seeded (Wazuh README: alert level threshold) | none | |
| X-10 | C1 delivery is fire-and-forget (10 s timeout, no retries): should Wazuh retry or queue, or does n8n accept the risk? | N8N | WZ | N8N-1.1, WZ-TBD | one-sided | C1 (behaviour) if Wazuh changes it | |
| X-11 | False-positive feedback: a case closed as false positive produces a tuning list for Wazuh | WZ | N8N, TH | N8N-5.3, WZ-TBD, TH-TBD | one-sided | none | |
| X-12 | Case templates and tasks per playbook | N8N | TH | N8N-5.2, TH-TBD | seeded (TheHive README: case templates and tasks) | none | |
| X-13 | Who creates cases: analyst promotes, or n8n auto-creates for named playbooks (D-N4) | N8N | TH | N8N-5.1, TH-TBD | open decision | none | |
| X-14 | TheHive event filtering and loop prevention: n8n ignores events caused by `n8n@asox.local`; TheHive keeps the "n8n (C4)" rule and endpoint | N8N | TH | N8N-1.5, TH-TBD | one-sided (rule is already documented in TheHive README) | C4 (none expected) | |
| X-15 | Is the `analyst` profile of the n8n Service account enough for custom fields, templates and writeback? | N8N | TH | N8N-2.1, N8N-2.2, TH-TBD | one-sided | C3 if the profile changes | |
| X-16 | Approval design in TheHive: approval task and comment, who approves, expiry | N8N | TH | N8N-7.1, TH-TBD | one-sided (depends on X-19) | none | |
| X-17 | Who runs enrichment: n8n through C6, or TheHive's native connector through C5 (D-N3) | N8N, TH | CX | N8N-5.4, TH-TBD, CX-TBD | open decision | none | |
| X-18 | Rate limits and quotas of online analyzers (e.g. VirusTotal), so n8n can throttle | N8N | CX | N8N-2.4, CX-TBD | one-sided | none | |

## C. Blocking risks and contract changes

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-19 | Does the TheHive Community license include `notification.webhook`? Also: activate the license on the build instance before 2026-10-11 | N8N, TH | Integrator | N8N-0.1, PROJECT.md 16 Q6 | open decision (blocking C4 and approval flow) | C4 if it fails | |
| X-20 | C9: response actions through Wazuh active response. Proposal: a separate Wazuh user and role (`n8n-response`, active-response only) and `n8n-api` stays read-only | N8N | WZ | N8N-8.1, WZ-TBD | contract change (Phase 2) | C9 (and C2 check assertion) | |
| X-21 | Action catalog: active-response commands available per agent OS, and their timeouts | N8N | WZ | N8N-8.2, WZ-TBD | one-sided | C9 | |
| X-22 | C9 check workflow and `contracts-check.sh` update | WZ, N8N | Integrator | N8N-8.5 | one-sided | C9 | |
| X-23 | Decoders and field names for pfSense and Snort alerts, so `pb-ids-alert` can be written | N8N | WZ | N8N-4.4, WZ-TBD | seeded (Wazuh README: decoders for pfSense and router logs) | none | |

## D. Flows that involve components other than n8n

Pre-filled from the seeded README backlogs. Owners should confirm or correct these.

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-24 | MISP IOCs pushed into Wazuh CDB lists: who moves the data (a script of Cortex + MISP, or an n8n scheduled workflow)? | WZ | CX (and possibly N8N) | WZ-TBD, CX-TBD | seeded on both sides; mechanism is an open decision | new: MISP to Wazuh CDB sync | |
| X-25 | Export of confirmed case IOCs from TheHive to MISP (analyst-triggered responder; allowed by D12) | CX | TH | TH-TBD, CX-TBD | seeded | none | |
| X-26 | Custom analyzer "seen before in Wazuh?": needs Wazuh data. From Cortex, or as an n8n lib instead? | CX | WZ | CX-TBD, WZ-TBD, N8N-2.7 | open decision | new: Cortex to Wazuh, unless n8n does it | |
| X-27 | MTTD/MTTR dashboards need TheHive data in Grafana | GF | TH | GF-TBD, TH-TBD | seeded (Grafana README: MTTD/MTTR) | contract change (Grafana reads TheHive) | |
| X-28 | n8n stamps timestamps and custom fields into TheHive so MTTD/MTTR can be computed; n8n execution stats for dashboards | GF | N8N, TH | N8N-9.3, GF-TBD | one-sided | none | |
| X-29 | Grafana alerting calling an n8n webhook (optional) | GF | N8N | GF-TBD | one-sided | new: Grafana to n8n webhook | |

## E. Requests to the integrator (shared files)

Owners add rows here for anything in shared files (rule 3 of the light rules). Prefilled with n8n's own requests.

| ID | Request | From | Refs | Status |
|---|---|---|---|---|
| R-01 | New credentials or webhook credentials added to `bootstrap.sh` (as playbooks need them) | N8N | N8N-9.2 | open |
| R-02 | End-to-end check (Wazuh to n8n to TheHive alert exists) in `contracts-check.sh`, and the C9 check | N8N | N8N-0.6, N8N-8.5 | open |
| R-03 | Workflow lint (naming, header note, credentials by ID, no hardcoded hosts or secrets) in `ci-checks.sh` | N8N | N8N-0.7 | open |
| R-04 | n8n self-check (workflows active, alert lag) in `healthcheck.sh` | N8N | N8N-6.4 | open |
| R-05 | `soc.sh` support for `COMPOSE_PROFILES=pg` (if Postgres is chosen) | N8N | N8N-6.7 | open |
| R-06 | | WZ | | |
| R-07 | | GF | | |
| R-08 | | TH | | |
| R-09 | | CX | | |

## F. Dependency order

Which cross-boundary items must be settled before the first slice (`v1.1`). Adjust after the comparison session.

| Milestone | Must be decided or delivered first | Because |
|---|---|---|
| `v1.1` first slice (alert to enriched TheHive alert) | X-19, X-01, X-02, X-03, X-17, X-06 | n8n cannot build `pb-generic` without the license answer, the field list, the mapping and the enrichment ownership |
| `v1.2` playbooks | X-04, X-05, X-09, X-12, X-13, X-08 | Routing, test data, templates and the policy on what may leave the lab |
| `v1.3` approval | X-16, X-19 | Approval lives in TheHive and relies on C4 |
| Phase 2 | X-20, X-21, X-22, X-23 | C9 needs both owners and a contract update |
| Phase 3 | X-28, X-29 | Depends on the shape of earlier work |

## Comparison session checklist

1. Collect every owner's `BACKLOG.md` (link them here).
2. Add their **Needs** and **Provides** as rows in sections A to D, or link them to existing rows.
3. For every row, set the status: matched, one-sided, contract change, open decision.
4. Take one-sided rows to the owner concerned: accepted (they add it to their backlog), rejected (reason recorded), or contract change.
5. Record design decisions in `docs/decisions.md` with the date, and contract changes in PROJECT.md 5 at a checkpoint.
6. Re-read section F and adjust milestones.
7. After each checkpoint PR, update this file.
