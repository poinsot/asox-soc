# n8n (SOAR) backlog: base draft

IDs use the prefix `N8N-` so other backlogs and `docs/integration-backlog.md` can reference them.

Owner: Inigo (@poinsot), also the integrator. Branch: `n8n`. Node: `core`. Run mode: `core-cases`.

Based on PROJECT.md (v2.1), docs/decisions.md, docs/handoff.md (2026-09-26), CHECKLIST.md, CONTRIBUTING.md and the component READMEs. Compared against the other owners' backlogs on 2026-09-30 (`docs/integration-backlog.md`) and updated with the contract decisions of that day (PROJECT.md 5, D44–D49): C9 (N8N-8.x), C10 (N8N-2.11), C11 (N8N-2.9), C13 (N8N-2.10), Suricata (N8N-4.4).

**Caveats**
- The docs may lag behind the repo; teammates may already have pushed changes.
- Sizes are rough guesses: S ≤ 1 day, M 2–4 days, L > 4 days.
- Anything depending on n8n 2.40.7 features not described in the docs (e.g. Data Tables) must be verified before use.

## Two risks to check first

1. **TheHive trial ends 2026-10-11.** After that, C3, C4 and every playbook fail. Activate the Community license, run `scripts/backup.sh cases --with-secrets`, and confirm the license includes `notification.webhook` (PROJECT.md section 16, Q6). The TheHive owner's Community license shows no webhook-capability warning (strong evidence, X-19), but C4 hasn't run on one yet. If it fails, C4 needs a redesign (for example n8n polling TheHive), which affects epics 1, 5 and 7 and C11.
2. **C1 has no retries.** `custom-n8n` uses a 10 s timeout and never retries (A48). If n8n is down or slow, alerts are lost. This shapes item N8N-1.1 and the reliability epic.

## Item format

`ID | Item | Priority | Size | Meets with / depends on`. Contract impact is stated explicitly where it exists.

## E0: Foundations and decisions

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-0.1 | License activation, backup, and the C4 capability check (see risk 1) | P0 | S | TheHive |
| N8N-0.2 | Capture real payload fixtures (Wazuh alerts of several rule types; TheHive alert, case, task and status events) into `nodes/core/n8n/fixtures/` | P0 | S | Wazuh, TheHive |
| N8N-0.3 | Agree the alert field set n8n relies on (`id`, `timestamp`, `rule.id/level/groups/mitre`, `agent.*`, `data.srcip`, `syscheck.*`, `full_log`). C1's payload shape doesn't change, but the fields become a documented promise | P0 | S | Wazuh |
| N8N-0.4 | Alert → TheHive mapping spec: severity, TLP/PAP, tags, custom fields, `sourceRef`, observable types | P0 | M | TheHive |
| N8N-0.5 | ~~Record decisions D-N1…N6 (below) in `docs/decisions.md`~~ Done 2026-09-30 ("Owner design decisions"); close each as its partner agrees | P0 | S | All |
| N8N-0.6 | Test strategy: fixture replay script (POST with token), per-playbook test cases, and which checks go into `contracts-check.sh` versus a new end-to-end check | P1 | M | Integrator |
| N8N-0.7 | CI lint for workflows: naming, header note present, credentials by ID, no hardcoded hosts or secrets (extends `ci-checks.sh`) | P1 | M | Integrator |

## E1: Ingestion and Router de Playbooks

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-1.1 | `recv-wazuh-alert` answers 200 immediately and processes asynchronously (10 s timeout, no retries) | P0 | S | Wazuh |
| N8N-1.2 | `lib-normalize-wazuh-alert`: canonical alert object, validation, malformed payloads parked and not silently dropped | P0 | M | Wazuh (N8N-0.3) |
| N8N-1.3 | Router: routing table (rule id, group and level → `pb-*`), `pb-generic` fallback, chosen playbook recorded on the execution and in TheHive | P0 | M | Wazuh (routing key) |
| N8N-1.4 | Flood protection: aggregation window, per-agent or per-rule throttle, concurrency cap (the lab agent already sends many level 7+ alerts) | P1 | M | Wazuh (threshold tuning) |
| N8N-1.5 | `recv-thehive-event` router: filter by event type, route to handlers, **loop prevention** (ignore events caused by `n8n@asox.local`, since n8n writes to TheHive and TheHive's every-event webhook calls n8n back) | P0 | M | TheHive |
| N8N-1.6 | Keep the 403-without-token behaviour intact through every refactor (C1 and C4 checks) | P0 | S | Wazuh, TheHive |

## E2: Shared `lib-` workflows

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-2.1 | `lib-thehive-upsert-alert`: create or update by `sourceRef` (idempotent) | P0 | M | TheHive |
| N8N-2.2 | `lib-thehive-writeback`: comment or task log with the actions taken, Wazuh alert ID and n8n execution ID | P0 | S | TheHive |
| N8N-2.3 | `lib-extract-observables`: IP, hash, domain, URL, user; defang; allowlist for internal and documentation ranges | P0 | M | Wazuh, Cortex |
| N8N-2.4 | `lib-enrich-observable`: choose analyzers by dataType, run through C6 with polling and timeouts, handle cache versus `force`, partial failures, reduce reports to a verdict | P0 | L | Cortex + MISP |
| N8N-2.5 | `lib-error`: classify errors, decide retry or park, write to TheHive | P0 | M | none |
| N8N-2.6 | `lib-config`: severity, TLP/PAP mapping and allowlists in one place | P1 | S | TheHive |
| N8N-2.7 | `lib-wazuh-context`: agent info through C2 (OS, group, last keepalive). Not the "seen before in Wazuh?" lookup, which is C13 (N8N-2.10) | P2 | M | Wazuh |
| N8N-2.8 | Document each lib's input and output schema (needed later so ASOX can call them as tools) | P1 | S | none |
| N8N-2.9 | **C11:** `lib-metrics-upsert`, called from `lib-thehive-writeback` and the C4 event handlers: one `asox-metrics` document per Wazuh alert (ID = Wazuh alert ID), fields and times as in PROJECT.md 5 (`t_event`, `t_alert`, `t_ack`, `t_case`, `t_contained`, `t_closed`, `severity`, `resolution`, `outcome`, …). Moved here from N8N-9.3 (X-28). Needs R-16 (indexer user `n8n-indexer`) | P1 | M | Grafana, Wazuh (indexer), integrator |
| N8N-2.10 | **C13:** `recv-wazuh-lookup` webhook for the Cortex "seen before in Wazuh?" analyzer: token `N8N_LOOKUP_TOKEN`, query `wazuh-alerts-*` as `n8n-indexer` with the field map of PROJECT.md 5, synchronous answer (count, first/last seen, top rules, agents, ≤ 10 alert IDs); read-only | P2 | M | Cortex + MISP, Wazuh, integrator (R-15, R-16) |
| N8N-2.11 | **C10:** `lib-misp-warninglist`: one `POST /warninglists/checkValue` for all of an alert's observables; matches tag the observable and may skip quota-limited analyzers, never close, suppress or downgrade anything (D12); MISP unreachable = continue. Only after R-14's size cap is on `main` (R-13) | P1 | S | Cortex + MISP, integrator |

## E3: Deduplication and correlation

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-3.1 | Dedup key and rule: the same alert twice creates no duplicate TheHive record | P0 | M | TheHive |
| N8N-3.2 | Merge repeats into the existing alert or case (counter, new observables, comment) | P1 | M | TheHive |
| N8N-3.3 | Idempotency test: replay each fixture twice, and double-post C1 | P0 | S | none |
| N8N-3.4 | Correlation across alerts (same source IP within a window) | P2 | L | Wazuh, TheHive |

## E4: Playbooks

Each playbook needs the header note (trigger, inputs, actions taken, systems changed, approval, owner), a fixture, a test and a README catalog entry. Any `auto_approve` marking is justified in the checkpoint PR.

| ID | Playbook | P | Size | Notes |
|---|---|---|---|---|
| N8N-4.1 | `pb-generic` (normalize → dedup → TheHive alert with observables → enrich → writeback; no system changes) | P0 | M | First vertical slice |
| N8N-4.2 | `pb-ssh-bruteforce` (aggregate by source IP, enrich, escalate on success after failures) | P1 | M | Needs Wazuh rules and Cortex analyzers; response step waits for C9 |
| N8N-4.3 | `pb-malware-hash` (FIM/syscheck hash → file analyzers and MISP → verdict) | P1 | M | Cortex + MISP |
| N8N-4.4 | `pb-ids-alert` on Suricata alerts (D49): rule groups `suricata`/`ids`, rule 86601, `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port`; pfSense later | P2 | L | Wazuh (Suricata from M3, 2026-11-03; pfSense M4) |
| N8N-4.5 | Further playbooks, chosen once Wazuh's rule set exists | P2 | – | Wazuh |

## E5: TheHive and Cortex flows

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-5.1 | Case-creation policy: analyst promotes by default; n8n auto-creates only for named playbooks | P1 | M | TheHive |
| N8N-5.2 | Apply case templates and tasks per playbook | P1 | M | TheHive |
| N8N-5.3 | React to C4 events: alert promoted, case created, case closed. Closing as false positive feeds a tuning list back to the Wazuh owner | P1 | M | TheHive, Wazuh |
| N8N-5.4 | Decide who runs enrichment, n8n (C6) or TheHive's connector (C5), to avoid double analysis. D-N3 agreed with TheHive (T4.1); waiting for Cortex + MISP (X-17) | P0 (decision) | S | TheHive, Cortex |
| N8N-5.5 | Analyst-initiated n8n actions from TheHive (task or tag convention that triggers a workflow) | P2 | M | TheHive |

## E6: Reliability and operations

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-6.1 | Global error workflow | P0 | S | none |
| N8N-6.2 | Retry with backoff and timeouts per integration (TheHive read-only or down, Cortex slow) | P0 | M | TheHive, Cortex |
| N8N-6.3 | Dead-letter store and replay workflow for failed alerts | P1 | M | none |
| N8N-6.4 | Self-check: workflows active, alert-to-TheHive lag, added to `healthcheck.sh` (integrator) | P1 | S | Integrator |
| N8N-6.5 | Execution data hygiene: executions store webhook headers including the token (handoff gotcha) | P1 | S | none |
| N8N-6.6 | Memory re-measurement with real playbooks (D40; n8n limit is 750m / 650m), and re-tune execution pruning | P1 | M | Integrator |
| N8N-6.7 | Postgres go/no-go, decided by measurement; `soc.sh` still doesn't manage `COMPOSE_PROFILES=pg` | P1 | S | Integrator |
| N8N-6.8 | Track the n8n 2.x deprecations (internal task runner, changing defaults) | P2 | S | none |
| N8N-6.9 | Restore of `core` is untested; keep workflows-as-code as the recovery path | P2 | S | Integrator |

## E7: Approval flow

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-7.1 | Design in TheHive first: approval as a task and comment, who may approve, expiry. Depends on the C4 capability (N8N-0.1) | P1 | M | TheHive |
| N8N-7.2 | `lib-approval-request` and `lib-approval-wait` (resume via C4 event or a Wait node's resume URL; timeout means deny) | P1 | L | TheHive |
| N8N-7.3 | Audit: who approved, when, and what exactly, written to TheHive | P1 | S | TheHive |
| N8N-7.4 | `pb-approval-demo` with a no-op action, so the flow is testable before C9 exists | P1 | S | none |
| N8N-7.5 | Channel abstraction so Slack (Phase 3) plugs in without touching playbooks | P2 | S | none |

## E8: Response actions, C9 (Phase 2)

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-8.1 | C9 design: a separate Wazuh user and role `n8n-response` (active-response command + agent read, actionable agent groups only); `n8n-api` stays read-only, so `chk-wazuh-api`'s "active response is refused" assertion stays valid. **Decided (D44), pending the Wazuh owner's acknowledgement** (W7.1 planned to widen `n8n-api`) | P1 | M | Wazuh (contract change) |
| N8N-8.2 | Action catalog and parameter schema. v1 = Wazuh's built-in commands only (D44, X-21): `firewall-drop` (block/unblock IP), `host-deny`, `disable-account`, each with a timeout. Host isolation and file removal wait for custom AR scripts from the Wazuh owner | P1 | M | Wazuh |
| N8N-8.3 | Guardrails: protected-IP allowlist (gateway, DNS, manager, analyst), mirrored in Wazuh's `<white_list>`; dry-run mode, global kill switch, rate cap, TTL auto-revert, rollback playbook | P1 | M | Wazuh |
| N8N-8.4 | `lib-wazuh-active-response` with result verification | P1 | M | Wazuh |
| N8N-8.5 | C9 check workflow `chk-wazuh-response` (defined in PROJECT.md 5) and `contracts-check.sh` (R-17) | P1 | M | Wazuh |
| N8N-8.6 | Audit trail: every action recorded in TheHive with the execution ID | P1 | S | TheHive |

## E9: Phase 3 readiness

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-9.1 | Playbooks and libs callable as tools by ASOX: stable schemas, idempotent, dry-run support | P2 | M | Everyone |
| N8N-9.2 | Authentication scheme for ASOX and the Slack bot calling n8n (new webhook credentials, added to `bootstrap.sh`) | P2 | S | Integrator |
| N8N-9.3 | ~~Expose n8n stats and stamp timestamps so Grafana can compute MTTD/MTTR~~ Moved to N8N-2.9 (C11, X-28) | – | – | – |

## Where n8n meets the other owners

| Owner | What n8n needs from them | What n8n gives them | Contract impact |
|---|---|---|---|
| **Wazuh (Daniel)** | Stable alert fields (N8N-0.3). Routing key: recommended rule groups plus a rule-id map. Threshold tuning. Fixtures per rule type. Attack-start marker (X-32, for C11's MTTD). Later: AR commands, timeouts, `n8n-response` (C9). Suricata and pfSense field names | Playbook list and the fields each one uses. False-positive feedback from closed cases. The C13 lookup webhook | C1: none, but fields documented. C9: new user. C11/C13: indexer user `n8n-indexer` |
| **TheHive (Park)** | Mapping spec (N8N-0.4). Custom fields (rule id, agent, MITRE, playbook, execution ID). Templates per playbook. Who owns alert-to-case rules. Approval task design. Keep the "n8n (C4)" rule. Confirm the `analyst` profile is enough for n8n | Alert format, writeback comments, approval requests, dedup by `sourceRef` | C3/C4 unchanged unless the license blocks webhooks |
| **Cortex + MISP (Diego)** | Analyzer list by dataType. Report and taxonomy format. Job duration and external API quotas. TLP/PAP policy that n8n must enforce before sending data to online analyzers. MISP user for C10. The C13 analyzer. Who moves MISP IOCs to Wazuh CDB lists (C14: n8n scheduled sync or a script) | Enrichment requests through C6. Verdicts attached to TheHive. The `wazuh-lookup` webhook (C13) | C6: none. C10, C13 new. C14 proposed |
| **Grafana (Jesus)** | Acknowledge C11's schema | `asox-metrics` for MTTD/MTTA/MTTR (C11, N8N-2.9). Possible Grafana alert → n8n webhook | C11 new; another only if Grafana alerting should call n8n |
| **Integrator** | Shared-file changes on `main`: `bootstrap.sh` credentials, `contracts-check.sh`, `ci-checks.sh`, `healthcheck.sh`, `soc.sh` for the pg profile | n/a | Updates at checkpoints |

## Decisions to make before building

Recorded with their status in `docs/decisions.md` ("Owner design decisions").

| # | Decision | Recommendation | Status |
|---|---|---|---|
| D-N1 | Dedup source of truth | TheHive `sourceRef` = Wazuh alert ID, plus an aggregation key for floods | Agreed in principle with TheHive (X-02) |
| D-N2 | Routing key | Rule groups plus a rule-id map, kept as data in a lib workflow (versioned through export) | Open, 3-way (X-04), 2026-10-20 |
| D-N3 | Who runs enrichment | n8n runs pre-triage enrichment (C6). Analysts can still run analyzers manually through TheHive (C5) | TheHive agrees; Cortex + MISP pending (X-17) |
| D-N4 | Alert to case | Analyst promotes by default; n8n auto-promotes only Critical alerts of named playbooks | Proposed to TheHive (X-13), 2026-11-03 |
| D-N5 | Approval mechanism | TheHive task-based, behind a channel abstraction | Matches TheHive T4.3 (X-16) |
| D-N6 | SQLite or Postgres | Stay on SQLite until measurement (N8N-6.6, N8N-6.7) says otherwise | Decided |

## Suggested milestones

Proposed dates, aligned with Wazuh and TheHive (feature freeze 2026-11-24, delivery 2026-12-01):

- **v1.1 first slice, checkpoint 1 (2026-10-20):** all of E0, N8N-1.1 to 1.3, 1.5, 1.6, 2.1 to 2.5, 3.1, 3.3, 4.1, 6.1, 6.2. Result: a Wazuh alert becomes a deduplicated, enriched TheHive alert with writeback.
- **v1.2 playbooks (2026-11-10):** N8N-1.4, 2.9 (C11), 2.11 (C10), 3.2, 4.2, 4.3, 4.4 (Suricata), E5, 6.3 to 6.7.
- **v1.3 approval (2026-11-17):** E7, N8N-2.10 (C13) if there is room.
- **Feature freeze 2026-11-24, delivery 2026-12-01.**
- **Phase 2 (after the delivery):** E8 (C9).
