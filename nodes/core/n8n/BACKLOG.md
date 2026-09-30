# n8n (SOAR) backlog: base draft

IDs use the prefix `N8N-` so other backlogs and `docs/integration-backlog.md` can reference them.

Owner: Inigo (@poinsot), also the integrator. Branch: `n8n`. Node: `core`. Run mode: `core-cases`.

Based on PROJECT.md (v2.1), docs/decisions.md, docs/handoff.md (2026-09-26), CHECKLIST.md, CONTRIBUTING.md and the component READMEs. This is a base draft to refine, and to compare against the other owners' backlogs (Wazuh, Grafana, TheHive, Cortex + MISP).

**Caveats**
- The docs may lag behind the repo; teammates may already have pushed changes.
- Sizes are rough guesses: S ≤ 1 day, M 2–4 days, L > 4 days.
- Anything depending on n8n 2.40.7 features not described in the docs (e.g. Data Tables) must be verified before use.

## Two risks to check first

1. **TheHive trial ends 2026-10-11.** After that, C3, C4 and every playbook fail. Activate the Community license, run `scripts/backup.sh cases --with-secrets`, and confirm the license includes `notification.webhook` (PROJECT.md section 16, Q6). If it doesn't, C4 needs a redesign (for example n8n polling TheHive), which affects epics 1, 5 and 7.
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
| N8N-0.5 | Record decisions D-N1…N6 (below) in `docs/decisions.md` | P0 | S | All |
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
| N8N-2.7 | `lib-wazuh-context`: agent info through C2 (OS, group, last keepalive) | P2 | M | Wazuh |
| N8N-2.8 | Document each lib's input and output schema (needed later so ASOX can call them as tools) | P1 | S | none |

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
| N8N-4.4 | `pb-ids-alert` | P2 | L | Phase 2, needs Snort/pfSense decoders |
| N8N-4.5 | Further playbooks, chosen once Wazuh's rule set exists | P2 | – | Wazuh |

## E5: TheHive and Cortex flows

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-5.1 | Case-creation policy: analyst promotes by default; n8n auto-creates only for named playbooks | P1 | M | TheHive |
| N8N-5.2 | Apply case templates and tasks per playbook | P1 | M | TheHive |
| N8N-5.3 | React to C4 events: alert promoted, case created, case closed. Closing as false positive feeds a tuning list back to the Wazuh owner | P1 | M | TheHive, Wazuh |
| N8N-5.4 | Decide who runs enrichment, n8n (C6) or TheHive's connector (C5), to avoid double analysis | P0 (decision) | S | TheHive, Cortex |
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
| N8N-8.1 | C9 proposal to Wazuh. **Recommendation:** a separate Wazuh user and role (`n8n-response`, active-response only) instead of widening `n8n-api`. Least privilege, and `chk-wazuh-api`'s "active response is refused" assertion stays valid. Otherwise that assertion flips | P1 | M | Wazuh (contract change) |
| N8N-8.2 | Action catalog and parameter schema (block IP, unblock, isolate, disable account) against the active-response commands each agent OS supports | P1 | M | Wazuh |
| N8N-8.3 | Guardrails: protected-IP allowlist (gateway, DNS, manager, analyst), dry-run mode, global kill switch, rate cap, TTL auto-revert, rollback playbook | P1 | M | Wazuh |
| N8N-8.4 | `lib-wazuh-active-response` with result verification | P1 | M | Wazuh |
| N8N-8.5 | C9 check workflow, plus `contracts-check.sh` and PROJECT.md section 5 updates (integrator, at a checkpoint) | P1 | M | Wazuh |
| N8N-8.6 | Audit trail: every action recorded in TheHive with the execution ID | P1 | S | TheHive |

## E9: Phase 3 readiness

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-9.1 | Playbooks and libs callable as tools by ASOX: stable schemas, idempotent, dry-run support | P2 | M | Everyone |
| N8N-9.2 | Authentication scheme for ASOX and the Slack bot calling n8n (new webhook credentials, added to `bootstrap.sh`) | P2 | S | Integrator |
| N8N-9.3 | Expose n8n stats and stamp timestamps into TheHive so Grafana can compute MTTD/MTTR | P2 | M | Grafana, TheHive |

## Where n8n meets the other owners

| Owner | What n8n needs from them | What n8n gives them | Contract impact |
|---|---|---|---|
| **Wazuh (Daniel)** | Stable alert fields (N8N-0.3). Routing key: recommended rule groups plus a rule-id map. Threshold tuning. Fixtures per rule type. Later: AR commands, timeouts, role (C9). Decoders for pfSense and Snort field names | Playbook list and the fields each one uses. False-positive feedback from closed cases | C1: none, but fields documented. C9: change |
| **TheHive (Park)** | Mapping spec (N8N-0.4). Custom fields (rule id, agent, MITRE, playbook, execution ID). Templates per playbook. Who owns alert-to-case rules. Approval task design. Keep the "n8n (C4)" rule. Confirm the `analyst` profile is enough for n8n | Alert format, writeback comments, approval requests, dedup by `sourceRef` | C3/C4 unchanged unless the license blocks webhooks |
| **Cortex + MISP (Diego)** | Analyzer list by dataType. Report and taxonomy format. Job duration and external API quotas. TLP/PAP policy that n8n must enforce before sending data to online analyzers. Who moves MISP IOCs to Wazuh CDB lists (n8n scheduled sync or Diego's script) | Enrichment requests through C6. Verdicts attached to TheHive | C6: none. The CDB sync would be a new contract |
| **Grafana (Jesus)** | Nothing blocking | Timestamps and custom fields for MTTD/MTTR (N8N-9.3). Possible Grafana alert → n8n webhook | New contract only if Grafana alerting should call n8n |
| **Integrator** | Shared-file changes on `main`: `bootstrap.sh` credentials, `contracts-check.sh`, `ci-checks.sh`, `healthcheck.sh`, `soc.sh` for the pg profile | n/a | Updates at checkpoints |

## Decisions to make before building

| # | Decision | Recommendation |
|---|---|---|
| D-N1 | Dedup source of truth | TheHive `sourceRef` = Wazuh alert ID, plus an aggregation key for floods |
| D-N2 | Routing key | Rule groups plus a rule-id map, kept as data in a lib workflow (versioned through export) |
| D-N3 | Who runs enrichment | n8n runs pre-triage enrichment (C6). Analysts can still run analyzers manually through TheHive (C5) |
| D-N4 | Alert to case | Analyst promotes at first; auto-create only for named playbooks |
| D-N5 | Approval mechanism | TheHive task-based, behind a channel abstraction |
| D-N6 | SQLite or Postgres | Stay on SQLite until measurement (N8N-6.6, N8N-6.7) says otherwise |

## Suggested milestones

- **v1.1 first slice (~2 weeks):** all of E0, N8N-1.1 to 1.3, 1.5, 1.6, 2.1 to 2.5, 3.1, 3.3, 4.1, 6.1, 6.2. Result: a Wazuh alert becomes a deduplicated, enriched TheHive alert with writeback.
- **v1.2 playbooks:** N8N-1.4, 3.2, 4.2, 4.3, E5, 6.3 to 6.7.
- **v1.3 approval:** E7.
- **Phase 2:** E8 and N8N-4.4.
