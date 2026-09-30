# n8n (SOAR) backlog: base draft

IDs use the prefix `N8N-` so other backlogs and `docs/integration-backlog.md` can reference them.

Owner: Inigo (@poinsot), also the integrator. Branch: `n8n`. Node: `core`. Run mode: `core-cases`.

Based on PROJECT.md (v2.2), docs/decisions.md, docs/handoff.md (2026-09-30), CHECKLIST.md, CONTRIBUTING.md and the component READMEs. Compared against the other owners' backlogs on 2026-09-30 (`docs/integration-backlog.md`) and updated with the contract decisions of that day (PROJECT.md 5, D44–D49): C9 (N8N-8.x), C10 (N8N-2.11), C11 (N8N-2.9), C13 (N8N-2.10), Suricata (N8N-4.4).

**Caveats**
- The docs may lag behind the repo; teammates may already have pushed changes.
- Sizes are rough guesses: S ≤ 1 day, M 2–4 days, L > 4 days.
- Anything depending on n8n 2.40.7 features not described in the docs (e.g. Data Tables) must be verified before use.

## Two risks to check first

1. ~~**TheHive trial ends 2026-10-11.**~~ **Resolved 2026-09-30** (N8N-0.1): Community license activated, backed up, C4 verified. Original risk: after that, C3, C4 and every playbook fail. Activate the Community license, run `scripts/backup.sh cases --with-secrets`, and confirm the license includes `notification.webhook` (PROJECT.md section 16, Q6). The TheHive owner's Community license shows no webhook-capability warning (strong evidence, X-19), but C4 hasn't run on one yet. If it fails, C4 needs a redesign (for example n8n polling TheHive), which affects epics 1, 5 and 7 and C11.
2. **C1 has no retries.** `custom-n8n` uses a 10 s timeout and never retries (A48). If n8n is down or slow, alerts are lost. This shapes item N8N-1.1 and the reliability epic.

## Temporary items (remove when their ticket closes)

| What | Where | Waits on |
|---|---|---|
| Observable type `user-account` disabled (TheHive would refuse the whole alert) | `lib-config` `observable_types` | T1.3: TheHive `entities/` loaded on the build instance |
| SCA intake exclusion: rule group `sca` recorded as `skipped: sca (X-09)` in `recv-wazuh-alert`, never reaches TheHive | `lib-config` `intake_exclusions` | X-09 (Wazuh: should SCA reach n8n?) |
| MITRE from `rule.mitre.id` only, no `rule.mitre_techniques` fallback | `lib-normalize-wazuh-alert` | ALERT-TO-THEHIVE §7 Q2 (TheHive) |
| `customFields` array form sent without proof it's the form TheHive fills; `caseTemplate` and custom fields are dropped today (writeback warns) | `lib-thehive-upsert-alert` | T1.3 |
| Parked items live 168 h as failed `lib-error` executions | `lib-error` | N8N-6.3 |
| `THEHIVE_ENABLED` defaults to `true` (TheHive expected everywhere, the old behaviour); a core-only machine must set it to `false` by hand until it is rendered | `compose.yml` | R-18 (integrator: `render-env.sh` derives it from `THEHIVE_N8N_API_KEY`; `bootstrap.sh core` runs `docker compose up -d --wait n8n` after its render) |

## Item format

`ID | Item | Priority | Size | Meets with / depends on`. Contract impact is stated explicitly where it exists.

## E0: Foundations and decisions

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-0.1 | ~~License activation, backup, and the C4 capability check (see risk 1)~~ Done 2026-09-30: Community license activated on the build instance (valid until 2027-09-28), backed up (`backup.sh cases --with-secrets` → `backups/cases-20260930-133649/`), C4 verified on it, and again after a TheHive container restart (2026-09-30, first-slice session) | P0 | S | TheHive |
| N8N-0.2 | ~~Capture real payload fixtures (Wazuh alerts of several rule types; TheHive alert, case, task and status events) into `nodes/core/n8n/fixtures/`~~ Done 2026-09-30 (`fixtures/README.md`): 4 Wazuh rule types (all that exist at level ≥ 7, plus one level-3 sample) and 20 TheHive events. **Missing, from Wazuh (X-05):** sshd, sudo, FIM, rootcheck, Suricata, any rule with `rule.mitre`; add them as `trigger.sh --scenario` lands | P0 | S | Wazuh, TheHive |
| N8N-0.3 | ~~Agree the alert field set n8n relies on (`id`, `timestamp`, `rule.id/level/groups/mitre`, `agent.*`, `data.srcip`, `syscheck.*`, `full_log`). C1's payload shape doesn't change, but the fields become a documented promise~~ Draft done 2026-09-30 (`docs/WAZUH-FIELDS.md`, verified against the fixtures); agreement with Wazuh pending (X-01, W2.5, 2026-10-20) | P0 | S | Wazuh |
| N8N-0.4 | ~~Alert → TheHive mapping spec: severity, TLP/PAP, tags, custom fields, `sourceRef`, observable types~~ n8n side done 2026-09-30 (`docs/ALERT-TO-THEHIVE.md`: paths, gaps, duplicate handling, questions for ALERT-FORMAT §7); agreement with TheHive pending (X-02, T2.4/T2.5, 2026-10-20) | P0 | M | TheHive |
| N8N-0.5 | ~~Record decisions D-N1…N6 (below) in `docs/decisions.md`~~ Done 2026-09-30 ("Owner design decisions"); close each as its partner agrees | P0 | S | All |
| N8N-0.6 | Test strategy: ~~fixture replay script (POST with token)~~, per-playbook test cases, and which checks go into `contracts-check.sh` versus a new end-to-end check. **Partial:** replay done 2026-09-30 (`fixtures/replay.sh`); per-playbook tests and contracts-check changes pending (R-02). `replay.sh` gained `--fresh-id` and `--delay` (2026-09-30); the first slice's tests are listed in the README (`pb-generic`) | P1 | M | Integrator |
| N8N-0.7 | CI lint for workflows: naming, header note present, credentials by ID, no hardcoded hosts or secrets (extends `ci-checks.sh`) | P1 | M | Integrator |

## E1: Ingestion and Router de Playbooks

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-1.1 | ~~`recv-wazuh-alert` answers 200 immediately and processes asynchronously (10 s timeout, no retries)~~ Done 2026-09-30: 200 on receipt, full alert kept in the execution (C1 check unchanged), level filter on `WAZUH_ALERT_MIN_LEVEL` (now in n8n's environment), intake exclusions from `lib-config`, then `pb-generic` without waiting (single call site for N8N-1.3). A body that isn't valid JSON gets HTTP 422 from n8n before any workflow runs, so n8n can't park it (only Wazuh's `integrations.log` shows it) | P0 | S | Wazuh |
| N8N-1.2 | ~~`lib-normalize-wazuh-alert`: canonical alert object, validation, malformed payloads parked and not silently dropped~~ Done 2026-09-30 (required set of `docs/WAZUH-FIELDS.md`; id kept as a string; malformed → `lib-error`). **Open:** MITRE reads `rule.mitre.id` only; the `rule.mitre_techniques` fallback waits for TheHive's answer (ALERT-TO-THEHIVE §7 Q2); required set still to agree with Wazuh (X-01) | P0 | M | Wazuh (N8N-0.3) |
| N8N-1.3 | Router: routing table (rule id, group and level → `pb-*`), `pb-generic` fallback, chosen playbook recorded on the execution and in TheHive | P0 | M | Wazuh (routing key) |
| N8N-1.4 | Flood protection: aggregation window, per-agent or per-rule throttle, concurrency cap (the lab agent already sends many level 7+ alerts) | P1 | M | Wazuh (threshold tuning) |
| N8N-1.5 | ~~`recv-thehive-event` router: filter by event type, route to handlers, **loop prevention** (ignore events caused by `n8n@asox.local`, since n8n writes to TheHive and TheHive's every-event webhook calls n8n back)~~ Done 2026-09-30: summary of every event recorded (operation, object type/ID, actor = top-level `_createdBy`, request ID, source, sourceRef); actor from `lib-config` → ignored; routes to labelled no-op stubs (alert promoted, alert status, case created, case status/closed, analyst activity) where N8N-5.3 and N8N-2.9 attach; all 20 fixtures route as designed; the C4 check's execution ends at loop prevention. **Open question (deletes, not decided):** delete events have no `object` and no useful `details` (a deleted alert's `sourceRef` isn't in the payload), so they are recorded and ignored. Either keep ignoring them, or correlate by `objectId` (or `requestId`) with an ID n8n recorded earlier (e.g. `thehive_alert_id` in `asox-metrics`, C11), which also covers the case delete that silently reopens its alert (ALERT-TO-THEHIVE §6). Decide with N8N-2.9 | P0 | M | TheHive |
| N8N-1.6 | Keep the 403-without-token behaviour intact through every refactor (C1 and C4 checks). Standing rule; verified after the N8N-1.1 refactor on 2026-09-30 (`replay.sh --no-token` 403, `contracts-check.sh --only C1,C3,C4` pass) | P0 | S | Wazuh, TheHive |

## E2: Shared `lib-` workflows

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-2.1 | ~~`lib-thehive-upsert-alert`: create or update by `sourceRef` (idempotent)~~ Done 2026-09-30 (TheHive-not-configured guard added the same day: `THEHIVE_ENABLED=false` → `skipped: TheHive not configured`, no park; R-18): ALERT-FORMAT §1–§5; 400 CreateError "already exists" → lookup, `duplicate: true`; other failures parked. Create only: updating an existing alert with new information is N8N-3.2. **Open:** `customFields` shape unverified (no fields on the build instance, T1.3; the array form is sent) | P0 | M | TheHive |
| N8N-2.2 | ~~`lib-thehive-writeback`: comment or task log with the actions taken, Wazuh alert ID and n8n execution ID~~ Done 2026-09-30: comment on the alert, first line `[asox-n8n writeback] wazuh-alert-id=<id>`; written only if no comment by `n8n@asox.local` starts with that line | P0 | S | TheHive |
| N8N-2.3 | ~~`lib-extract-observables`: IP, hash, domain, URL, user; defang; allowlist for internal and documentation ranges~~ Done 2026-09-30: ALERT-FORMAT §5 + C13 field map; refang, validation (invalid → `skipped` with the reason), duplicates merged within the alert; internal (RFC 1918, loopback, link-local, IPv6 equivalents) and documentation ranges (RFC 5737, `2001:db8::/32`) kept, tagged `range:internal` / `range:documentation`, flagged in `asox.range` for N8N-2.4 (no enrichment policy decided here); `data.hostname` → `ip`, `fqdn` (dot) or `hostname`; ranges and type switches in `lib-config`; `user-account` still off (T1.3). Only `100100` fixtures and `trigger.sh` alerts exercise it live (agent IP, `range:internal`); the other paths are covered by a harness run of the same code (not committed) | P0 | M | Wazuh, Cortex |
| N8N-2.4 | `lib-enrich-observable`: choose analyzers by dataType, run through C6 with polling and timeouts, handle cache versus `force`, partial failures, reduce reports to a verdict | P0 | L | Cortex + MISP |
| N8N-2.5 | ~~`lib-error`: classify errors, decide retry or park, write to TheHive~~ Done 2026-09-30: classes `malformed_input`, `thehive_unreachable` (connection error or 5xx), `thehive_4xx`, `unknown`; records the Wazuh alert ID, failing workflow and payload; comments on the TheHive alert when one exists; always parks; since N8N-6.2 the calling lib retries TheHive first and `lib-error` records `attempts` and `retry_exhausted` (`retryable` stays the hint for N8N-6.3) | P0 | M | none |
| N8N-2.6 | `lib-config`: severity, TLP/PAP mapping and allowlists in one place. **Partial:** seed done 2026-09-30 (severity, TLP/PAP, asset criticality, test sources, case templates, observable types, intake exclusions, writeback marker); ~~allowlists come with N8N-2.3~~ observable ranges added 2026-09-30, plus `thehive_http` (N8N-6.2), `thehive.enabled` and n8n's TheHive account (N8N-1.5) | P1 | S | TheHive |
| N8N-2.7 | `lib-wazuh-context`: agent info through C2 (OS, group, last keepalive). Not the "seen before in Wazuh?" lookup, which is C13 (N8N-2.10) | P2 | M | Wazuh |
| N8N-2.8 | Document each lib's input and output schema (needed later so ASOX can call them as tools) | P1 | S | none |
| N8N-2.9 | **C11:** `lib-metrics-upsert`, called from `lib-thehive-writeback` and the C4 event handlers: one `asox-metrics` document per Wazuh alert (ID = Wazuh alert ID), fields and times as in PROJECT.md 5 (`t_event`, `t_alert`, `t_ack`, `t_case`, `t_contained`, `t_closed`, `severity`, `resolution`, `outcome`, …). Moved here from N8N-9.3 (X-28). Needs R-16 (indexer user `n8n-indexer`) | P1 | M | Grafana, Wazuh (indexer), integrator |
| N8N-2.10 | **C13:** `recv-wazuh-lookup` webhook for the Cortex "seen before in Wazuh?" analyzer: token `N8N_LOOKUP_TOKEN`, query `wazuh-alerts-*` as `n8n-indexer` with the field map of PROJECT.md 5, synchronous answer (count, first/last seen, top rules, agents, ≤ 10 alert IDs); read-only | P2 | M | Cortex + MISP, Wazuh, integrator (R-15, R-16) |
| N8N-2.11 | **C10:** `lib-misp-warninglist`: one `POST /warninglists/checkValue` for all of an alert's observables; matches tag the observable and may skip quota-limited analyzers, never close, suppress or downgrade anything (D12); MISP unreachable = continue. Only after R-14's size cap is on `main` (R-13) | P1 | S | Cortex + MISP, integrator |

## E3: Deduplication and correlation

| ID | Item | P | Size | Meets with |
|---|---|---|---|---|
| N8N-3.1 | ~~Dedup key and rule: the same alert twice creates no duplicate TheHive record~~ Done 2026-09-30 for sequential copies (`type`+`source`+`sourceRef`, D-N1). **Known limitation, accepted:** TheHive's uniqueness isn't enforced under concurrent creates, so simultaneous copies of one alert can create duplicates (measured: two concurrent POSTs → two 201s). C1 can't produce them (`custom-n8n` sends once, no retries, A48); only tests and replays can. Asked of TheHive (ALERT-TO-THEHIVE §7 Q9) | P0 | M | TheHive |
| N8N-3.2 | Merge repeats into the existing alert or case (counter, new observables, comment) | P1 | M | TheHive |
| N8N-3.3 | ~~Idempotency test: replay each fixture twice, and double-post C1~~ Done 2026-09-30 sequentially: `replay.sh --fresh-id --times 2 --delay 5` → one TheHive alert, one writeback, second run `duplicate`. Back-to-back (no delay) → two alerts: recorded, not fixed (N8N-3.1). The other fixtures create nothing (sca skipped, 503 filtered) | P0 | S | none |
| N8N-3.4 | Correlation across alerts (same source IP within a window) | P2 | L | Wazuh, TheHive |
| N8N-3.5 | Scheduled duplicate report: list TheHive alerts sharing `type`+`source`+`sourceRef` (possible after concurrent copies, N8N-3.1) and comment on them; **never delete** | P2 | S | TheHive |

## E4: Playbooks

Each playbook needs the header note (trigger, inputs, actions taken, systems changed, approval, owner), a fixture, a test and a README catalog entry. Any `auto_approve` marking is justified in the checkpoint PR.

| ID | Playbook | P | Size | Notes |
|---|---|---|---|---|
| N8N-4.1 | ~~`pb-generic` (normalize → dedup → TheHive alert with observables → enrich → writeback; no system changes)~~ Done 2026-09-30 except enrichment: normalize → extract observables (N8N-2.3) → upsert (dedup) → **enrichment stub** (no-op until N8N-2.4) → writeback; outcomes `created`, `duplicate`, `parked`, `skipped` (TheHive not configured); catalog entry in the README | P0 | M | First vertical slice |
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
| N8N-6.1 | ~~Global error workflow~~ Done 2026-09-30: `recv-n8n-error` (Error Trigger → `lib-error`), set as the error workflow of `recv-wazuh-alert` and `pb-generic` only: n8n fires it for the failing sub-workflow **and** its waiting caller, so setting it on the libs would park each error twice; a workflow containing an Error Trigger is its own error workflow, hence not inside `lib-error` | P0 | S | none |
| N8N-6.2 | Retry with backoff and timeouts per integration (TheHive read-only or down, Cortex slow). **Partial:** TheHive done 2026-09-30: timeout on every call (`lib-config` `thehive_http.timeout_ms`), retry only on connection error / timeout / 5xx, never 4xx, 3 calls with 2 s and 5 s waits, then parked with `attempts`; a retried comment post re-lists first; outage-tested (container stopped → 3 calls, parked after ~9 s, C4 passes after restart). Built-in node retry wasn't usable (constant wait ≤ 5 s, retries 4xx). Cortex comes with N8N-2.4, same pattern | P0 | M | TheHive, Cortex |
| N8N-6.3 | Dead-letter store and replay workflow for failed alerts. **Until then (stopgap, 2026-09-30):** a parked item is a failed `lib-error` execution, kept only 168 h by execution pruning; that is **not** a dead-letter store. **Constraint:** the replay workflow processes items one at a time and checks by `sourceRef` before creating (TheHive's duplicate refusal isn't atomic, N8N-3.1) | P1 | M | none |
| N8N-6.4 | Self-check: workflows active, alert-to-TheHive lag, added to `healthcheck.sh` (integrator) | P1 | S | Integrator |
| N8N-6.5 | ~~Execution data hygiene: executions store webhook headers including the token (handoff gotcha)~~ Done 2026-09-30: `lib-*` save failed executions only. The token in saved `recv-*` executions **can't be removed cleanly** on 2.40.7 Community (redaction is Enterprise-only and read-time; C1/C4 need the recv executions): documented in the README as a limitation (who can read it, 168 h retention, core backups contain it, rotation) | P1 | S | none |
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
