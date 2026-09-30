# Integration backlog (cross-component register)

Owner: the integrator (Inigo, @poinsot). Lives in `docs/`, a folder only the integrator changes.

This is **not** a merged backlog. Each owner keeps their own `BACKLOG.md`. This file lists only the items that **cross a component boundary**, so gaps and mismatches are visible in one place.

## Status of this register

**Comparison session done (2026-09-30), then audited the same day.** All five owners' backlogs are in: `nodes/core/n8n/BACKLOG.md`, `nodes/core/wazuh/BACKLOG.md`, `nodes/core/grafana/BACKLOG.md`, `nodes/cases/thehive/BACKLOG.md`, `nodes/cases/cortex/BACKLOG.md` + `nodes/intel/misp/BACKLOG.md` (Diego owns both, one branch `cortex-misp`). Every row below is cross-checked against all six files.

1. **Dates.** Wazuh and TheHive target feature freeze **2026-11-24** and delivery **2026-12-01**, with matching milestones. n8n now proposes the same dates (its backlog, "Suggested milestones"). Cortex + MISP stated theirs (section F). **Grafana hasn't stated dates** (section F).
2. **TheHive license (X-19): resolved 2026-09-30.** The integrator's build instance runs a Community license (valid until 2027-09-28), backed up with `backup.sh cases --with-secrets`, and C4 works on it: 20 C4 events were captured by the n8n E0 session that day (PROJECT.md 16 Q6 answered). Park's own instance also has a Community license (until 2027-09-29, TheHive T0.4).
3. **Contracts (PROJECT.md 5, D44–D48):** C9 designed (separate `n8n-response` user), C10 accepted, C11 accepted, C12 **rejected**, C13 accepted with n8n as the path to the indexer, C14 (MISP → Wazuh CDB lists) numbered and proposed. The audit fixed C13 (the first version couldn't reach Wazuh's data), completed C11's schema and writer credential, and added C10's and C9's prerequisites. **Only C10 has both owners' agreement**; the others need acknowledgements (section "Contracts decided this session").
4. **Suricata replaces Snort (D49).** Wazuh decided it (W3.1); PROJECT.md and n8n's backlog are updated. TheHive (T3.6, ALERT-FORMAT.md §3), Grafana (README, GRAF-2.3) and MISP (README, backlog) still say Snort in their own folders (section G).

## Legend

| Status | Meaning |
|---|---|
| **one-sided** | Only one owner lists it |
| **matched** | Both backlogs list it and Needs and Provides agree (may still be an open decision — see the Decision column) |
| **mismatch** | Both list it, but they don't agree |
| **contract change** | Needs both owners' agreement, then PROJECT.md 5 and `contracts-check.sh` updated at a checkpoint |
| **open decision** | A choice both sides must make; scheduled if a target date exists |
| **decided** | Agreed, with date and where it is recorded |
| **decided, pending ack** | Decided by the integrator; an owner named in it still has to confirm |
| **resolved** | The blocking condition is gone (e.g. the license is active) |
| **rejected** | Not doing it, with the reason |

References use the ID prefixes `W` (Wazuh), `N8N`, `GRAF`, `T` (TheHive), `CX` (Cortex + MISP). `N8N-x.y`, `Wx.y`, `GRAF-x.y`, `Tx.y` refer to item numbers in each owner's `BACKLOG.md`.

## A. Data agreements (what the data looks like)

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-01 | Stable set of Wazuh alert fields that playbooks rely on | N8N | W | N8N-0.3, W2.5 | **matched, draft proposed** | C1 (payload unchanged, fields documented) | Target 2026-10-20 (Wazuh W2.5, checkpoint 1). n8n's draft: `nodes/core/n8n/docs/WAZUH-FIELDS.md` (branch `n8n`, 2026-09-30), verified against real alerts; only rules 100100, 19007, 19004 exist at level ≥ 7, so most `data.*`, `syscheck.*` and `rule.mitre.*` fields are "not seen yet" |
| X-02 | Alert to TheHive mapping: severity, TLP/PAP, tags, custom fields, `sourceRef` | N8N | TH | N8N-0.4, T2.4, T2.5 | **matched, open decision** | none | Target 2026-10-20 (TheHive T2.4/T2.5, `docs/ALERT-FORMAT.md` §1/§2/§4/§5). D-N1 (dedup by `sourceRef`) rides on it |
| X-03 | Custom fields in TheHive for rule id, agent, MITRE technique, playbook, n8n execution id | N8N | TH | N8N-0.4, N8N-2.2, T2.1 | **matched — provided, not loaded** | none | TheHive's 9 fields exist in `entities/` (T2.1) and cover n8n's needs (N8N-0.4, 2026-09-30). **Not loaded on the build instance** (T1.3): no custom fields, case templates or `user-account` type there. Measured 2026-09-30: an unknown `caseTemplate` or unknown custom fields are silently dropped (HTTP 201); an unknown observable type (`user-account`) refuses the whole alert (HTTP 404) |
| X-04 | Routing key for the router: rule groups plus a rule-id map | N8N | W, TH | N8N-1.3, W1.3, T2.6 | **matched, open decision (3-way)** | none | Target 2026-10-20; TheHive's `caseTemplate` routing (T2.6) must agree with Wazuh's rule-ID plan (W1.3) and n8n's router (N8N-1.3, D-N2) at the same time |
| X-05 | Test fixtures for each rule type (extra `trigger.sh` variants; `nodes/lab/` is Wazuh's folder) | N8N | W | N8N-0.2, W1.5 | **matched** | none | Wazuh W1.5 adds `trigger.sh --scenario <name>` (ssh-bruteforce, sudo-fail, ioc-ip, …), target 2026-10-09. n8n's fixtures (`nodes/core/n8n/fixtures/`, branch `n8n`, 2026-09-30) hold the only rules at level ≥ 7 today (100100, 19007, 19004); sshd, sudo, FIM, rootcheck, Suricata and any rule with `rule.mitre` wait for `--scenario` |
| X-06 | Analyzer list per observable type, with names, versions and expected run time | N8N | CX | N8N-2.4, CX (analyzers.json) | **matched, in progress** | C6 (none expected) | Cortex defines AbuseIPDB, OTXQuery, URLhaus, MalwareBazaar, VirusTotal_GetReport, MISPWarningLists in `analyzers.json` (on `cortex-misp`, not merged); keys pending. `n8n-enrichment.md` (in progress) is the deliverable n8n needs |
| X-07 | Cortex report and taxonomy format that n8n reduces to a verdict | N8N | CX | N8N-2.4, CX (n8n-enrichment.md) | **matched, in progress** | none | Same deliverable as X-06 |
| X-08 | TLP/PAP policy: which observables may go to online analyzers (n8n must enforce it before running them) | N8N | CX | N8N-2.4, N8N-2.6, CX (defaults), T2.5 | **matched, defaults set** | none | Cortex defaults: `max_tlp`/`max_pap` = 2 (AMBER), job cache 10 min; TheHive defaults new alerts to TLP/PAP AMBER (T2.5). A written policy is still Cortex's "Next" item |
| X-09 | Alert level threshold and flood tuning (`WAZUH_ALERT_MIN_LEVEL`); the lab agent already sends many level 7+ alerts | N8N | W | N8N-1.4, W2.1 | **matched** | none | Wazuh W2.1 "agree the forwarding threshold with n8n owner", target 2026-10-20; default stays 7. Measured: an agent start's SCA scan sends ~130 level-7 alerts (rule 19007) to n8n; question "should SCA reach n8n at all?" sent to Wazuh 2026-09-30 |
| X-10 | C1 delivery is fire-and-forget (10 s timeout, no retries): should Wazuh retry or queue, or does n8n accept the risk? | N8N | W | N8N-1.1 | one-sided | C1 (behaviour) if Wazuh changes it | n8n's position: accept the risk, answer fast (N8N-1.1) and rely on TheHive/dedup for recovery. Wazuh's backlog doesn't address it — raise before checkpoint 1 |
| X-11 | False-positive feedback: a case closed as false positive produces a tuning list for Wazuh | W | N8N, TH | N8N-5.3, W2.4, T4.4 | **matched** | none | TheHive T4.4 builds `thehive-fp-report.sh` (grouped by `wazuh-rule-id`) for Daniel's W2.4 tuning pass. Target: M4 (2026-11-10). C11's `resolution` field gives Grafana the same rate |
| X-12 | Case templates and tasks per playbook | N8N | TH | N8N-5.2, T2.2, T3.5 | **matched — base provided** | none | 4 templates in `entities/` (ssh-bruteforce, malware-detection, ids-network-alert, wazuh-generic; T2.2); T3.5 adds templates as Wazuh ships new detections |
| X-13 | Who creates cases: analyst promotes, or n8n auto-creates | N8N | TH | N8N-5.1, T3.3 | **open decision, close** | none | TheHive R2: n8n may auto-promote **Critical** only. n8n's D-N4 said "named playbooks". Proposed combination (docs/decisions.md D-N4): auto-promote Critical alerts of named playbooks only. Target TheHive M3 (2026-11-03) |
| X-14 | TheHive event filtering and loop prevention: n8n ignores events caused by `n8n@asox.local`; TheHive keeps the "n8n (C4)" rule and endpoint | N8N | TH | N8N-1.5, T4.2 | **matched** | C4 (none expected) | TheHive T4.2 re-verifies this end to end at M4 (2026-11-10) |
| X-15 | Is the `analyst` profile of the n8n Service account enough for custom fields, templates, promotion and writeback? | N8N | TH | N8N-2.1, N8N-2.2, T1.3, T3.2 | **matched, in progress** | C3 if the profile changes | **Promotion works:** n8n's key got HTTP 201 on `POST /api/v1/alert/<id>/case` (build instance, 2026-09-30); creating, tagging and deleting its own test alerts work too. Custom fields and templates still untested, because `entities/` aren't loaded on the build instance (X-03, T1.3) |
| X-16 | Approval design in TheHive: approval task and comment, who approves, expiry | N8N | TH | N8N-7.1, T4.3 | **matched** | none | TheHive T4.3 / D-N5: task "Approve: `<action>`" (group `Approval`), close = approve, cancel = reject with comment, 1 h timeout = n8n cancels. Depends on C4 (X-19) |
| X-17 | Who runs enrichment: n8n through C6, or TheHive's native connector through C5 (D-N3) | N8N, TH | CX | N8N-5.4, T4.1 | **decided** | none | **2026-09-30:** D-N3 confirmed by all three: n8n auto-enriches at intake via C6; analysts re-run manually via C5 (TheHive T4.1; Cortex + MISP in the Cortex backlog, "D-N3 confirmed"). Recorded in `docs/decisions.md` D-N3 |
| X-18 | Rate limits and quotas of online analyzers (e.g. VirusTotal), so n8n can throttle | N8N | CX | N8N-2.4, CX (defaults) | **matched — provided** | none | AbuseIPDB 1000/day, VirusTotal 500/day + 4/min (shared key, "severe path only"). C10 lets n8n skip quota-limited analyzers for *common* values |

## B. Behaviour and flows (what happens when)

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-19 | Does the TheHive Community license include `notification.webhook`? Also: activate the license on the build instance before 2026-10-11 | N8N, TH | Integrator | N8N-0.1, T0.4, PROJECT.md 16 Q6 | **resolved** | none | **2026-09-30:** the build instance's Community license is active (valid until 2027-09-28) and backed up (`backup.sh cases --with-secrets`); C4 verified on it: 20 C4 events captured by the n8n E0 session (N8N-0.2). Park's instance (T0.4): Community license until 2027-09-29. C11 and the approval flow (X-16) can rely on C4 |
| X-20 | C9: response actions through Wazuh active response, separate user and role `n8n-response`; `n8n-api` stays read-only | N8N | W | N8N-8.1, W7.1 | **decided, pending ack (D44)** | C9 | Wazuh's W7.1 planned to widen `n8n-api` instead; Daniel to acknowledge the separate role and update W7.1 and the README's C9 row. Build after 2026-12-01 (Wazuh M7) |
| X-21 | Action catalog: active-response commands per agent OS, timeouts, protected hosts | N8N | W | N8N-8.2, W7.1, W7.2 | **decided, pending ack (D44)** | C9 | Was a **mismatch**: n8n listed "isolate", TheHive's `containment-action` has `host-isolated` / `file-removed`, Wazuh ships only `firewall-drop`, `host-deny`, `disable-account`. v1 = Wazuh's built-ins with timeouts; protected hosts in n8n's allowlist and Wazuh's `<white_list>`. Isolation/file removal need custom AR scripts (Wazuh, later); TheHive keeps those options for manual actions |
| X-22 | C9 check workflow (`chk-wazuh-response`) and `contracts-check.sh` update | W, N8N | Integrator | N8N-8.5, W7.1 | one-sided (integrator work, Phase 2) | C9 | Check defined in PROJECT.md 5; needs `firewall-drop` in the lab image (W7.2). See R-17 |
| X-23 | Decoders and field names for pfSense and network-IDS alerts, so `pb-ids-alert` can be written | N8N | W | N8N-4.4, W3.x, W4.1–W4.5 | **matched** | none | Suricata fields from Wazuh M3 (2026-11-03), pfSense from M4 (2026-11-10). `pb-ids-alert` targets Suricata (rule 86601, `data.alert.*`) |
| X-32 | Attack-start marker for Grafana annotations and C11's `t_attack_start`: `ASOX_ATTACK_START scenario=<x> id=<uuid>` in the lab trigger, a dedicated low-noise rule catches it | GRAF, N8N | W | GRAF-2.2, D-G3 | one-sided | none | Not in Wazuh's backlog yet; fits W1.5 (`trigger.sh --scenario`). Raise with Daniel before checkpoint 1. Without it, C11 has no MTTD |
| X-34 | Suricata replaces Snort; rule groups `suricata`/`ids`, rule 86601, fields `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port` | GRAF, N8N, TH | W | W3.1–W3.7, T3.6, GRAF-2.3 | **decided (D49)** | none | PROJECT.md and n8n's backlog updated 2026-09-30. Still to do in owners' folders: TheHive T3.6 + ALERT-FORMAT.md §3 (open), Grafana README/GRAF-2.3, MISP README/backlog (section G) |

## C. Blocking risks and contract changes

| ID | Item | Needs (who) | Provides (who) | Refs | Status | Contract | Decision / date |
|---|---|---|---|---|---|---|---|
| X-24 | MISP IOCs pushed into Wazuh CDB lists: who moves the data (a script with its own MISP key, or an n8n scheduled workflow reusing C10's key)? | W | CX (and possibly N8N) | W6.1–W6.5 | **open decision → C14** | C14: MISP → Wazuh CDB lists | Numbered C14 (PROJECT.md 5, proposed). Wazuh W6.1: design agreed with Diego **by 2026-10-16**, the earliest cross-owner deadline. If n8n runs the sync, the CDB lists still live in Wazuh's folder and R-08 is dropped |
| X-25 | Export of confirmed case IOCs from TheHive to MISP (analyst-triggered responder; allowed by D12) | CX | TH | T5.4, CX (later) | **matched, low priority** | none | Both "later"; TheHive T5.4 targets M5 (2026-11-17), Cortex has no date. Uses the license's single MISP-server slot if done through TheHive's connector |
| X-26 | "Seen before in Wazuh?" lookup | CX, TH, N8N | W (fields), N8N (webhook) | CX (later), T5.3 | **decided, pending ack (D48) → C13** | C13: Cortex → n8n → indexer | A Cortex analyzer calls n8n's read-only `wazuh-lookup` webhook (own token `N8N_LOOKUP_TOKEN`); n8n queries the indexer as `n8n-indexer`. The first version (analyzer with a Wazuh API credential) couldn't work: alerts aren't in the Wazuh API and the indexer isn't reachable from `cases`. Replaces TheHive's link B (T5.3). n8n's `lib-wazuh-context` (N8N-2.7) is a different function and stays. Depends on R-10 (custom analyzers) and R-15/R-16 |
| X-27 | MTTD/MTTA/MTTR dashboards need case data in Grafana | GRAF | N8N, TH | GRAF-0.4, GRAF-3.1–3.3, T5.5 | **decided, pending ack (D46) → C11** | C11: n8n → indexer → Grafana | Grafana's own design (D-G1). Schema and definitions in PROJECT.md 5 (adds `t_event`, `t_ack`, `severity`, `resolution`). TheHive's T5.5 is satisfied by n8n's writeback; TheHive has nothing to build |
| X-28 | n8n stamps timestamps into TheHive and writes `asox-metrics` | GRAF | N8N, TH | N8N-2.9, GRAF-0.4, GRAF-3.1 | **decided** | part of C11 | Moved from N8N-9.3 (Phase 3) into n8n's E2 as N8N-2.9 on 2026-09-30. Depends on C4 (X-19) for `t_ack`, `t_case`, `t_closed` |
| X-29 | Grafana alerting calling an n8n webhook (optional) | GRAF | N8N | GRAF-5.1 | **matched, low priority both sides** | new if built: Grafana → n8n webhook | Both optional; no date; not decided |
| X-31 | C10: n8n → MISP warninglist check | N8N | CX | MISP backlog "Proposal: contract C10" | **decided (D45) → C10** | C10: n8n → MISP | Both owners agree. Before it goes live: R-14's size cap merged and misp-core re-measured; confirm the Read Only role may call `checkValue`. See R-13 |
| X-33 | C12: direct Wazuh → TheHive alert link, bypassing n8n ("link A") | TH | W | T5.1, T5.2 | **rejected (D47)** | none — will not be built | Contradicts D12 and reintroduces the dedup problem (T5.2). Park to close T5.1 (link A) and T5.2; Daniel and Park to be told |

## Contracts decided this session (2026-09-30)

PROJECT.md 5 carries the full text; reasons in PROJECT.md 15 (D44–D49). PROJECT.md 5 was updated directly, ahead of a checkpoint, so every owner designs against one text; rule 5 (both owners agree) is completed by the acknowledgements below.

| # | Contract | Verdict | Owners | Acknowledged by |
|---|---|---|---|---|
| C9 | n8n → endpoints, Wazuh active response (Phase 2) | designed: separate `n8n-response` user, built-in commands only | n8n, Wazuh | n8n ✅ · Wazuh ⏳ (W7.1 planned to widen `n8n-api`) |
| C10 | n8n → MISP warninglist check | accepted | n8n, Cortex + MISP | n8n ✅ · Cortex + MISP ✅ (Diego proposed it) |
| C11 | n8n → indexer → Grafana, `asox-metrics` | accepted, schema completed | n8n, Grafana, Wazuh (indexer) | n8n ✅ · Grafana ⏳ (schema grew) · Wazuh ⏳ |
| C12 | Wazuh → TheHive direct alert link | **rejected** | Wazuh, TheHive | to be told: Wazuh ⏳ · TheHive ⏳ |
| C13 | Cortex → n8n → indexer, "seen before in Wazuh?" | accepted, via n8n webhook | Cortex + MISP, n8n, Wazuh (field names) | n8n ✅ · Cortex + MISP ✅ (Cortex backlog, 2026-09-30) · Wazuh ⏳ |
| C14 | MISP → Wazuh CDB lists | proposed, design due 2026-10-16 | Wazuh, Cortex + MISP | design owed by Daniel and Diego |

Owners refer to these by their C-number (not X-number) in commit messages and pull requests. C12's number stays unused.

## D. Flows that involve components other than n8n

See X-24 (→ C14), X-25 (TheHive → MISP export), X-26 (→ C13), X-27/X-28 (→ C11), X-29 (Grafana → n8n alerting), X-31 (→ C10), X-33 (C12, rejected).

## E. Requests to the integrator (shared files)

Owners add rows here for anything in shared files (rule 3 of the light rules).

| ID | Request | From | Refs | Status |
|---|---|---|---|---|
| R-01 | New credentials or webhook credentials added to `bootstrap.sh` (as playbooks need them) | N8N | N8N-9.2 | open |
| R-02 | End-to-end check (Wazuh to n8n to TheHive alert exists) in `contracts-check.sh`, and the C9 check. Planned (2026-09-30): once `pb-generic` exists, replay `nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json` with a fresh `id`, expect a TheHive alert with that `sourceRef`, then delete it (can reuse `nodes/core/n8n/fixtures/replay.sh`) | N8N | N8N-0.6, N8N-8.5 | open. Part done 2026-09-30: C1 deletes the TheHive alert (`source` `asox-test`, `sourceRef` = the C1 test alert id) that `pb-generic` creates, found by `sourceRef` through TheHive's API; INFO line when there is none. The end-to-end check itself is still to do |
| R-03 | Workflow lint (naming, header note, credentials by ID, no hardcoded hosts or secrets) in `ci-checks.sh`. Optional extra: fail if any `nodes/core/n8n/fixtures/**.json` contains a token header (`x-asox-token`) or `authorization` | N8N | N8N-0.7 | open |
| R-04 | n8n self-check (workflows active, alert lag) in `healthcheck.sh` | N8N | N8N-6.4 | open |
| R-05 | `soc.sh` support for `COMPOSE_PROFILES=pg` (if Postgres is chosen) | N8N | N8N-6.7 | open (D-N6: SQLite for now) |
| R-06 | New env var for restricted syslog sources (`WAZUH_SYSLOG_ALLOWED_IPS`) in `nodes/core/.env.example` + `render-env.sh` | W | W1.1 | open, needed by 2026-10-09; **waiting on Daniel:** list format (comma or space separated IPv4/CIDR) and default; per-machine value planned as an optional `SYSLOG_ALLOWED_IPS` in `topology.env` |
| R-07 | Memory variable for Suricata in `nodes/lab/.env.example` + `render-env.sh`; re-check `core` still fits `low` (6 GB) with Suricata (D39, D49) | W | W3.2, W3.6 | open |
| R-08 | New `__from:intel__` value for a read-only MISP key for `core` (CDB sync, C14) | W | W6.1 | open, depends on the C14 design (2026-10-16); dropped if n8n runs the sync with C10's key |
| R-09 | `.gitignore` entry for `nodes/cases/cortex/analyzers/analyzer-keys.env` | CX | Cortex backlog "For the other owners" | open, small, review at checkpoint |
| R-10 | Cortex config/compose change so Cortex also reads custom analyzers from `analyzers/`, not only the online catalog | CX | Cortex backlog "Next" | open; **needed by C13** |
| R-11 | `grafana-ro` (`asox_grafana_ro` in `scripts/lib/wazuh.sh`) gains read on `asox-metrics`; the `asox-metrics` datasource itself is Grafana's provisioning file | GRAF | GRAF-0.4, C11 | open — decision made 2026-09-30 |
| R-12 | ~~TheHive Service account for Wazuh (link A)~~ | TH | T5.2 | **closed — C12 rejected 2026-09-30** |
| R-13 | C10: `MISP_N8N_API_KEY=__from:intel__` and `MISP_URL` in `nodes/core/.env.example`, `render-env.sh`; MISP user `n8n@asox.local` in `bootstrap.sh intel`; n8n credential "MISP API (n8n)" (fixed ID, certificate check off) in `bootstrap.sh core`; `chk-misp-api` + C10 in `contracts-check.sh` | CX, N8N | MISP backlog "Proposal: contract C10" | open — after R-14's fix is merged |
| R-14 | **Known issue (memory budget):** the 1M-entry Cisco Umbrella warninglist makes every warninglist check run out of memory under misp-core's 900m limit; `misp-config.sh apply` (on `cortex-misp`) disables lists above 100,000 entries. Affects `main` today. Re-measure before raising the limit or re-enabling large lists; **blocks C10** | CX | MISP backlog "Known issue" | informational, watch at the cortex-misp checkpoint |
| R-15 | C13: `N8N_LOOKUP_TOKEN` (`__secret__` of core, `__from:core__` in cases); n8n Header Auth credential for `recv-wazuh-lookup`; `bootstrap.sh cases` configures the analyzer (webhook URL from `N8N_WEBHOOK_URL`, token); C13 in `contracts-check.sh` | CX, N8N | X-26, D48 | open — after R-10 and R-16 |
| R-16 | Indexer user `n8n-indexer` (role: write on `asox-metrics`, read on `wazuh-alerts-*`), password a `__secret__` of core, created by `bootstrap.sh core`; `asox-metrics` index template; n8n credential for the indexer; root CA mounted into n8n with `NODE_EXTRA_CA_CERTS`; `chk-metrics` + C11 in `contracts-check.sh` | N8N, GRAF | C11, C13, D46 | open — first piece of C11/C13 |
| R-17 | C9 (Phase 2): Wazuh user and role `n8n-response` in `scripts/lib/wazuh.sh`, password a `__secret__` of core, n8n credential "Wazuh API (n8n-response)"; `chk-wazuh-response` + C9 in `contracts-check.sh` | N8N, W | C9, D44, X-22 | open, after 2026-12-01 |
| R-18 | `THEHIVE_ENABLED` (non-secret) in `nodes/core/.env.example`, rendered `true` when `THEHIVE_N8N_API_KEY` is non-empty; `bootstrap.sh core` recreates n8n when its environment changed | N8N | N8N-2.1, N8N-4.1 | **done 2026-09-30** (A79) |

## F. Dependency order and delivery alignment

Which cross-boundary items must be settled before each milestone. Adjust after each checkpoint.

**Alignment (2026-09-30):** Wazuh and TheHive target feature freeze **2026-11-24** and delivery **2026-12-01** with matching milestones (M0 2026-10-02, checkpoint 1 2026-10-20, M3 2026-11-03, M4 2026-11-10, M5 2026-11-17). n8n's backlog now proposes the same dates. **Cortex + MISP (Diego) aligned** (Cortex and MISP backlogs, "Dates"): analyzers as code + online analyzers, `n8n-enrichment.md` (X-06, X-07) and R-14's fix by **2026-10-20**; written TLP/PAP policy (X-08) and C10 live by **2026-11-10**; the C13 analyzer by **2026-11-17** (if R-10, R-15 and R-16 are in); C14 design by 2026-10-16. **Grafana (Jesus) must still confirm he can hit 2026-10-20 / 2026-11-24 / 2026-12-01**, or checkpoint 1 slips for everyone.

| Milestone | Must be decided or delivered first | Because | Target date |
|---|---|---|---|
| License | ~~X-19 (build instance license activated and backed up)~~ **Done 2026-09-30** (Community license until 2027-09-28, backed up, C4 verified) | Build instance turns read-only; C3, C4 and every playbook fail | ~~2026-10-11~~ |
| Before checkpoint 1 | C14 design (X-24, Wazuh + Diego); owner acknowledgements of C9, C11, C13; C12 rejection communicated | Wazuh's own deadline; rule 5 | **2026-10-16** |
| Checkpoint 1 / `v1.1-detections` first slice (alert to enriched TheHive alert) | X-01, X-02, X-03, X-04, X-09, ~~X-17~~ (decided), X-06 (Diego: 2026-10-20) | n8n cannot build `pb-generic` without the field list, the mapping, the routing key and the enrichment ownership | **2026-10-20** (Wazuh W2.6, TheHive T2.7) |
| `v1.2` playbooks | X-05, X-08 (Diego: 2026-11-10), X-12, X-13, X-23/X-34 (Suricata) | Test data, TLP/PAP policy, templates, case-creation policy | 2026-11-03 to 2026-11-10 |
| `v1.3` approval | X-16, ~~X-19 (C4 confirmed on a Community license)~~ met: C4 verified on a Community license, 2026-09-30 | Approval lives in TheHive and relies on C4 | Before TheHive M4 (2026-11-10) |
| C11 / Grafana "Desempeño y cumplimiento" | R-16, R-11, X-28 (N8N-2.9), X-19 (C4), X-32 (for MTTD) | Grafana's dashboard is an empty shell without it | Grafana has no date; flag against 2026-12-01 |
| C10 | R-14 merged, misp-core re-measured, R-13 | Warninglist checks run out of memory today | R-14 by 2026-10-20, C10 live by **2026-11-10** (Diego) |
| C13 | R-10, R-16, R-15; the Cortex analyzer | Custom analyzers must load; n8n needs the indexer credential | Analyzer by **2026-11-17** (Diego), if R-10, R-15 and R-16 are in |
| Phase 2 | X-20, X-21 (C9), X-22, R-17 | C9 needs real endpoints to be useful | Wazuh M7 (after 2026-12-01) |
| Not building | C12 (X-33) | Rejected 2026-09-30 | — |
| Phase 3 | X-29 | Depends on the shape of earlier work | No date |

## G. Follow-ups in owners' folders

`main` carries the decisions; these edits are in folders that belong to other owners (rule 3), so each owner makes them on their own branch and they arrive at the next checkpoint. The integrator made the n8n ones on `main` on 2026-09-30.

| Owner | Edit |
|---|---|
| Wazuh (Daniel) | W7.1: design `n8n-response` as a separate user (D44), not new permissions on `n8n-api`; README's C9 row likewise. Add the attack-start marker (X-32) to W1.5 or a new item. Answer X-10 (C1 retries). Add C13's field map check (PROJECT.md 5) to W2.5. C14 design by 2026-10-16 |
| TheHive (Park) | Close T5.1 (link A) and T5.2 as rejected (C12, D47); T5.3 → C13 (Diego's analyzer, nothing to build in TheHive); T5.5 → satisfied by C11. README "Design discussion": mark decided. T3.6 + ALERT-FORMAT.md §3: Suricata. `containment-action`: note that `host-isolated` / `file-removed` are manual-only until custom AR scripts exist (X-21). TO.4 cites `R-08`, which is Wazuh's request |
| Grafana (Jesus) | GRAF-0.4 → accepted as C11; review the completed schema and acknowledge. GRAF-2.3 and README: Suricata instead of Snort. State dates |
| Cortex + MISP (Diego) | ~~Cortex backlog: "seen before in Wazuh?" is C13 (calls n8n's webhook, no Wazuh credential); confirm D-N3 (X-17).~~ Done (C13 acknowledged, D-N3 confirmed). ~~MISP backlog: C10 accepted (no longer ⛔)~~ done; check `checkValue` with the Read Only role (MISP backlog "Next"); README/backlog: Suricata instead of Snort. ~~State dates~~ done (section F) |

## Comparison session checklist

1. ~~Collect every owner's `BACKLOG.md`~~ — done 2026-09-30.
2. ~~Add their Needs and Provides as rows in sections A to D~~ — done.
3. ~~Set a status for every row~~ — done, including new proposals (C10/X-31, C11/X-27, C13/X-26, the direct Wazuh/TheHive links X-33) and one priority mismatch (X-28).
4. ~~Decide contracts C9–C13~~ — done 2026-09-30 (PROJECT.md 5 and 15, D44–D48), then audited the same day: C13 re-routed through n8n, C11 schema and writer completed, C10 and C9 prerequisites added, C14 numbered, D49 (Suricata) recorded.
5. ~~Record owner design decisions~~ — D-N1–N6 and D-G1–G4 in `docs/decisions.md` ("Owner design decisions").
6. **Still open (integrator, before checkpoint 1 on 2026-10-20):**
   - ~~Activate the build instance's TheHive license before **2026-10-11**, back up `cases`, run C4 (X-19).~~ Done 2026-09-30.
   - Collect the acknowledgements in "Contracts decided this session" and tell Park and Daniel about C12.
   - Take X-10 (C1 retries) and X-32 (attack-start marker) to Daniel.
   - Ask Jesus to commit to the shared dates (Diego's are in section F).
   - Send each owner their row of section G.
7. Re-read section F and adjust milestones after each checkpoint.
8. After each checkpoint pull request, update this file.
