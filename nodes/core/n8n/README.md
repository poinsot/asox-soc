# n8n — SOAR, "Orchestrador"

Owner: Inigo (@poinsot), also the integrator. Branch: `n8n`. Node: `core`. Run mode: `core-cases` (`core` is enough for C1/C2 work).

n8n is the platform's SOAR and integration hub, and the **only** component that executes automated actions that change systems (PROJECT.md 6.2, D12).

**Start here:** [CONTRIBUTING.md](../../../CONTRIBUTING.md) (light rules, exporting changes, onboarding), then this file. First time: `./scripts/soc.sh init core-cases`; then `soc.sh up core-cases` / `soc.sh down`. Test loop: edit a playbook → `nodes/lab/trigger.sh` → check the execution and the TheHive alert → `scripts/n8n-export.sh` (`core-cases` is best effort on 8 GB machines: use a 16 GB+ machine or the shared instance). Details: [PROJECT.md](../../../PROJECT.md) 6.2.

`core-cases` includes TheHive, which turns read-only after a 14-day trial: request and activate your Community license, then back it up right away ([TheHive README](../../cases/thehive/README.md#license-important)).

| Folder / file | What it is |
|---|---|
| `compose.yml` | `n8n` (SQLite in the `n8n-data` volume); `n8n-postgres` under the optional profile `pg` |
| `workflows/*.json` | Workflows as code, one file per workflow (exported by `scripts/n8n-export.sh`) |
| `fixtures/` | Real payloads for tests (N8N-0.2): Wazuh alerts (`wazuh/`) and TheHive webhook events (`thehive/`), described in `fixtures/README.md` with the list of missing rule types |
| `fixtures/replay.sh` | POSTs fixtures to `wazuh-alert` / `thehive-event` with the right token header; `--all`, `--times N` with `--delay S` (idempotency), `--fresh-id` (new Wazuh alert id, so a replay is a new alert), `--no-token` (must get 403) (N8N-0.6) |
| `docs/WAZUH-FIELDS.md` | Wazuh alert fields n8n relies on, with types and which are optional, verified against the fixtures (N8N-0.3; draft to agree with Wazuh, X-01) |
| `docs/ALERT-TO-THEHIVE.md` | n8n's side of `nodes/cases/thehive/docs/ALERT-FORMAT.md`: the Wazuh path behind each TheHive field, gaps, duplicate `sourceRef` handling, C4 event shapes, questions for TheHive (N8N-0.4) |

Workflows:

| Workflow | Trigger | Purpose |
|---|---|---|
| `recv-wazuh-alert` | `POST /webhook/wazuh-alert` (Wazuh `custom-n8n` integration, C1) | Answers 200 on receipt and keeps the full alert in its execution (the C1 check looks there). Reads `lib-config`, records `filtered: level N < M` below `WAZUH_ALERT_MIN_LEVEL` and `skipped: sca (X-09)` for the temporary SCA exclusion, routes every other alert with `lib-route-alert` (Router de Playbooks, N8N-1.3) and calls the chosen playbook by ID without waiting, passing the route. The route is recorded on this execution (node `Playbook input`: `routed: <route_id> -> <playbook>`). A broken routing table parks the alert with its id (`lib-error`, stage `route`). |
| `pb-generic` | Called by `recv-wazuh-alert` (every route today) | First playbook: see the catalog below. |
| `lib-route-alert` | Called by `recv-wazuh-alert` | Router de Playbooks (N8N-1.3, D-N2): pure, no external calls. Picks the route from `lib-config` `routing` and returns `{route_id, playbook, playbook_id, case_template, matched_by, fallback, proposed_match, routing_version}`. See "Routing" below. |
| `lib-config` | Called by workflows | Data only: severity table, TLP/PAP, asset criticality, test sources (`100100` → `asox-test`), the routing table (`routing`) and playbook IDs (`playbooks`), enabled observable types, observable ranges (`range:internal` / `range:documentation`), intake exclusions, writeback marker, n8n's TheHive account (loop prevention), TheHive and Cortex call timeouts and retry waits (`thehive_http`, `cortex_http`), the enrichment policy (`enrichment`, N8N-2.4: see "Enrichment policy"), and `thehive.enabled` from `THEHIVE_ENABLED` (N8N-2.6). Temporary entries name their ticket. |
| `lib-extract-observables` | Called by playbooks | TheHive observables from the canonical alert (ALERT-FORMAT §5, C13 field map): refanged, validated, duplicates merged; IPs in internal or documentation ranges are **kept**, tagged `range:internal` / `range:documentation` and flagged (`asox.range`, n8n-only) for `lib-enrich-observable` (N8N-2.4); invalid values and disabled types are listed in `skipped` (N8N-2.3). `data.hostname`: an IP → `ip`, with a dot → `fqdn`, else `hostname`. `data.srcuser` / `data.dstuser` → `user-account` (tags `src` / `target`), which needs TheHive's `entities/` loaded (T1.3), or TheHive refuses the whole alert (HTTP 404). |
| `lib-normalize-wazuh-alert` | Called by playbooks | Canonical alert per `docs/WAZUH-FIELDS.md`; the alert id stays a string; MITRE techniques from `rule.mitre.id`, else `rule.mitre_techniques` (`mitre_ids`, `mitre_source`). Malformed alerts go to `lib-error` (N8N-1.2). |
| `lib-thehive-upsert-alert` | Called by playbooks | Creates the TheHive alert (ALERT-FORMAT) with `lib-extract-observables`' observables and the route's case template (the routing default without a route); "already exists" → returns the existing one with `duplicate: true` (N8N-2.1, 3.1), plus `after_retry: true` when a retried create found it. Returns `skipped: TheHive not configured` without any call when `THEHIVE_ENABLED=false`. |
| `lib-enrich-observable` | Called by playbooks (`pb-generic`, created alerts only) | Enrichment through Cortex (C6, N8N-2.4): C10 hook (no-op until N8N-2.11) → plan from `lib-config` `enrichment` (see "Enrichment policy") → analyzer IDs from `GET /api/analyzer` → each job through `lib-cortex-job`, one after another → verdict per observable (worst taxonomy level wins) → tags and IOC flag on the TheHive observables through `lib-thehive-tag-observable`. Returns per observable `enriched` (verdict, analyzer, job ID, tagged or not), `skipped` (reasons) or `failed` (class, attempts). **Never parks** and never lowers severity, closes or suppresses anything (D12). |
| `lib-cortex-job` | Called by `lib-enrich-observable` (one job per call) | One analyzer on one value: `POST /api/analyzer/<id>/run` (`data`, `dataType`, `tlp`, `pap`, `force`, `message` with the Wazuh and TheHive alert IDs), then `GET /api/job/<id>/waitreport?atMost=<timeout_s>seconds`. Classes `cortex_unreachable`, `cortex_4xx`, `job_failure`, `timeout`, `cortex_error`. |
| `lib-thehive-tag-observable` | Called by `lib-enrich-observable` (one observable per call) | `PATCH /api/v1/observable/<id>` with `addTags` (added, never replacing) and `ioc: true` only for a malicious verdict (never set back to false). TheHive retry pattern, but failures are returned, not parked. |
| `lib-thehive-writeback` | Called by playbooks | Comment on the TheHive alert starting `[asox-n8n writeback] wazuh-alert-id=<id>`; written once (N8N-2.2). A failed post is retried through a new comment listing, so a post that timed out but was written isn't written twice. |
| `lib-error` | Called by workflows (not waited for) | Classifies (`malformed_input`, `thehive_unreachable`, `thehive_4xx`, `unknown`), records alert id, failing workflow and payload, comments on the TheHive alert if any, and the number of TheHive calls made (`attempts`, `retry_exhausted`), then parks: the execution ends in error (N8N-2.5). Parked items = failed `lib-error` executions, kept 168 h, until N8N-6.3. |
| `recv-n8n-error` | n8n Error Trigger | Global error workflow of `recv-wazuh-alert`, `recv-thehive-event` and `pb-generic`: hands n8n's unhandled errors to `lib-error` (N8N-6.1). |
| `recv-thehive-event` | `POST /webhook/thehive-event` (TheHive webhook, C4: every event of the SOC organisation) | Router (N8N-1.5): records a summary of every event (operation, object type and ID, actor = top-level `_createdBy`, request ID, source, sourceRef), then routes it, first match wins: (1) actor `n8n@asox.local` → ignored (loop prevention; the C4 check's test alert ends here); (2) delete → ignored (open question, BACKLOG N8N-1.5); (3) alert update with `caseId` → alert promoted; (4) alert update with `status` → alert status; (5) case create; (6) case update with `status`/`stage` → case status or closed; (7) Task / Log / Comment → analyst activity; (8) anything else → recorded, no handler. Routes 3–7 end in labelled **no-op stubs** where N8N-5.3 and C11 (N8N-2.9) attach. |
| `chk-wazuh-api` | `POST /webhook/chk-wazuh-api` (`scripts/contracts-check.sh`) | Contract check C2: logs in with the n8n-api credential, lists agents, and verifies that active response is refused. Don't change it without the integrator. |
| `chk-thehive-api` | `POST /webhook/chk-thehive-api` (`scripts/contracts-check.sh`) | Contract check C3: creates a test alert (`source: contract-check`) with the TheHive credential and reads it back; a second call deletes it (only alerts whose source is `contract-check`). Don't change it without the integrator. |
| `chk-cortex-api` | `POST /webhook/chk-cortex-api` (`scripts/contracts-check.sh`) | Contract check C6: lists Cortex's enabled analyzers with the Cortex credential. Don't change it without the integrator. |

## Playbook conventions (every workflow author follows them)

- **Naming:** `pb-<use-case>` for playbooks (e.g. `pb-ssh-bruteforce`), `recv-<source>` for entry points, `lib-<function>` for reusable sub-workflows (e.g. `lib-enrich-observable`), `chk-<what>` for contract checks.
- **Header note:** a sticky note in every playbook declares **trigger**, **inputs**, **actions taken**, **systems changed** (none / which), **approval** (`required` / `auto_approve`) and **owner** (see the stubs).
- **Traceability:** every execution carries the Wazuh alert ID and, once created, the TheHive alert or case ID, and writes a summary of its actions back to the TheHive record.
- **Approval by default:** a playbook that changes systems requires analyst approval unless it is explicitly marked `auto_approve`; justify that marking in the checkpoint pull request.
- **Idempotent and safe to re-run:** the same alert processed twice must not create duplicate TheHive records or repeat actions.

### Playbook catalog

**`pb-generic`** (N8N-4.1). *Trigger:* `recv-wazuh-alert`, for every alert at or above the threshold that isn't excluded: every routing row names it today, and it is the routing fallback for a row whose playbook isn't built yet. *Input:* the alert, `lib-config` and the route; `caseTemplate` comes from the route, the custom field `playbook` is `pb-generic` (the playbook that ran), and the writeback lists the route (`Route: <route_id> (<matched by>) …`, plus any playbook fallback and proposed matches) after its fixed first line. *Steps:* `lib-normalize-wazuh-alert` → `lib-extract-observables` → `lib-thehive-upsert-alert` → only when the outcome is `created` (a duplicate is not re-enriched): `lib-enrich-observable` (N8N-2.4, Execute Workflow with **On Error = continue**: an unexpected failure is recorded as `enrichment: failed`, never parks and never blocks the writeback) → `lib-thehive-writeback`. The writeback's first line and marker are unchanged; after the route it lists the enrichment: counts (enriched / skipped / failed, analyzer runs planned, answered from Cortex's cache), then one line per observable: `Enriched: <type> <value>: verdict <v> (<analyzer>: <verdict>, <taxonomies>, job <id>); tagged …`, `Not enriched: … <reasons>`, `Enrichment failed: … <analyzer>: <class> after N call(s)`; a duplicate says `Enrichment: not run (duplicate …)`. *Systems changed:* TheHive only (alert, comment, observable tags and IOC flag); Cortex runs read-only lookups. *Approval:* not needed. *Result:* `outcome` = `created`, `duplicate` (the same Wazuh alert again: nothing new is created or written) `parked` (see `lib-error`; a TheHive outage is retried first, N8N-6.2), or `skipped` (`skipped: TheHive not configured` when `THEHIVE_ENABLED=false`: no park, no writeback); the result also carries `enrichment` (counts, `not run (duplicate)` or `failed`). *Test:* `fixtures/replay.sh --fresh-id --times 2 --delay 5 --file fixtures/wazuh/100100-asox-test-c1.json` → route `wazuh-generic` on the recv execution, one `asox-test` alert (severity 3, `caseTemplate` `wazuh-generic`, custom fields filled once TheHive's `entities/` are loaded, observables `ip` of the agent tagged `agent`, `range:internal`, and `hostname` tagged `agent`) with one writeback comment; `19007` → skipped, `503` → filtered, `invalid/100100-no-id.json` → parked; delete the `asox-test` alerts afterwards. Outage: stop only the `thehive` container (`docker stop`), replay → parked `thehive_unreachable` with `attempts: 3`; start it, wait for healthy, re-run `contracts-check.sh --only C4`. *Enrichment tests* (`full` mode: MISP is needed): `fixtures/replay.sh --fresh-id --file fixtures/synthetic/100100-misp-hit.json` → `203.0.113.66` enriched by `MISP_2_1`, verdict `suspicious` (MISP's taxonomy for a hit), tags `asox:verdict=suspicious`, `analyzer:MISP_2_1`, `ioc` stays false, the agent's IP and hostname skipped, all listed in the writeback; `--times 2 --delay 30` on it → the second is `duplicate`, no new Cortex job; plain `100100-asox-test-c1.json` → `nothing eligible`, no Cortex call. Outage: `docker stop` only the `cortex` container, replay the MISP fixture with `--fresh-id` → alert created, `Enrichment failed: … MISP_2_1: cortex_unreachable after 3 call(s)`, writeback written, nothing parked (~9 s); `docker start` it and wait for healthy. Measured 2026-10-06: a new MISP job took ~11 s end to end; a second alert on the same IOC within 10 min reused the cached job. Not configured: recreate n8n with `THEHIVE_ENABLED=false` in the shell (`compose core up -d n8n`), replay → `skipped`, then recreate it without the override. **Known limitation:** two copies of one alert arriving at the same moment create two TheHive alerts, because TheHive's duplicate refusal isn't atomic (`docs/ALERT-TO-THEHIVE.md` §2). C1 never sends copies; tests and replays can.

### Routing (N8N-1.3)

`recv-wazuh-alert` → `lib-route-alert` → the chosen playbook. The table is **data** in `lib-config` (`routing`), seeded from ALERT-FORMAT §3 (TheHive) on 2026-10-06; order and matches fixed on 2026-10-09 with the Wazuh owner's answers from live alerts (A1–A6 in `nodes/core/wazuh/docs/integrator-requests-2026-10-06.md`) and his rules 100200/100211/100212 (W2.2). Routing key per D-N2: **rule groups first, then a short rule-ID map** where a group is too broad (e.g. `suspicious-login`), plus MITRE techniques and level. Wazuh rules carry Wazuh's standard groups, never a playbook group (no `pb_*`): which playbook handles what stays n8n data.

| # | Row (= case template) | Status | Matches (any clause) |
|---|---|---|---|
| 1 | `ioc-match` | proposed | group `misp_ioc` (C14 rules 108xxx, M6). First, so an IOC match wins: those rules keep the source's groups (e.g. `sshd`) |
| 2 | `suspicious-login` | active | rules 40112 (failures then success, level 12) and 100200 (SSH login as root). Above `ssh-bruteforce`, because 40112 also carries T1110. Not on T1078: every normal login (5715) carries it |
| 3 | `ssh-bruteforce` | active | `sshd` + one of `authentication_failures` / `authentication_failed` / `invalid_login`; or T1110 (5712, 5763) |
| 4 | `malware-detection` | active | one of `virustotal`, `rootcheck`, `yara`, `clamd`, `malware` |
| 5 | `ids-network-alert` | active | `suricata` or `ids` (86601, M3) |
| 6 | `privilege-escalation` | active | rule 5404 (sudo, 3 wrong passwords: groups `syslog,sudo` only); or T1548 (5404 carries T1548.003) |
| 7 | `account-change` | active | group `adduser` (5901 new group, which has no MITRE; 5902, 5904, 100211, 100212); or T1136 |
| 8 | `network-scan` | proposed | `pfsense` + `recon`, or `pfsense` + T1046 (pfSense scan rules 103xxx, M4: IDs to come) |
| 9 | `wazuh-generic` | default | everything else, including test alerts (100100) |

The two proposed rows wait only for their Wazuh rules to exist (ALERT-FORMAT §3: proposed rows wait for the Wazuh owner's confirmation). The attack-start marker (rule 100101, group `attack_start`, W1.6) is level 3, below `WAZUH_ALERT_MIN_LEVEL`, so it never reaches n8n and needs no row or exclusion; if its level is ever raised to 7 or more, add an intake exclusion for `attack_start` (C11 reads it from the indexer, N8N-2.9).

- **Rows are ordered; the first `active` match wins.** A `proposed` row that matches is recorded in `proposed_match` (and in the writeback) and evaluation goes on, so its alerts get the default until the row is confirmed (with the Wazuh owner, W1.3, X-04) and switched to `active`. The last row is the default (`wazuh-generic`), and it must stay last.
- **A row:** `{ id, status: 'active' | 'proposed', match: [clause, ...], playbook, case_template, note }`. The row matches when **any** clause matches. A clause matches when **every** key it has matches: `groups_all` (all of these `rule.groups`), `groups_any` (one of them), `rule_ids` (`rule.id`, as strings), `mitre_prefix` (`T1110` matches `T1110` and `T1110.001`, not `T11100`; techniques from `rule.mitre.id`, else `rule.mitre_techniques`), `min_level` (`rule.level` ≥). A clause with no keys never matches.
- **Playbooks:** `playbooks` maps a playbook name to its workflow ID (Execute Workflow by ID). A row naming a playbook that isn't there (not built yet) runs `routing.fallback_playbook` (`pb-generic`) and records `fallback: {wanted, reason}`; it never fails.
- **Defensive:** routing reads the raw alert; a missing or mistyped `rule.groups`, `rule.id` or MITRE field only means "no match", and a malformed alert still reaches the playbook's normalizer, which parks it with its id. Test alerts (rule `100100`, `asox-test`) match no row and take the default.

**How to add or change a row**
1. Edit `routing.rows` in `lib-config`'s `Config` node (UI or file): put the row **before** the default row, in priority order; use `status: 'proposed'` until the rule IDs and groups are agreed with Wazuh (and the template exists in TheHive's `entities/`). Bump `routing.version`.
2. A new playbook: build `pb-<use-case>` with a fixed ID, `"active": true` and the header note, add it to `playbooks`, then point the row's `playbook` at it.
3. Test: replay a fixture (`fixtures/wazuh/` has a real alert for each active row except malware and IDS; or a variant of one with the groups/technique you route on), or run the Wazuh owner's lab scenario (`nodes/lab/trigger.sh --scenario <name>`, list in `fixtures/README.md`), and check the recv execution's `Playbook input` (`route`), the TheHive alert's `caseTemplate`, and the writeback's `Route:` line. TheHive silently drops an unknown template (the playbook's writeback warns).
4. `scripts/n8n-export.sh`, review the diff, commit.

### Enrichment policy (N8N-2.4)

What `lib-enrich-observable` does with each observable is **data** in `lib-config` `enrichment`, so the Cortex + MISP owner's `n8n-enrichment.md` (X-06, X-07) and the written TLP/PAP policy (X-08) only change that table:

- **Never enriched:** the agent's own observables (tag `agent`) and internal ranges (`range:internal`): `skip.never_tags`. **Local analyzers only:** documentation ranges (`range:documentation`, e.g. the MISP seed IOC): `skip.local_only_tags`. Observables are taken in extraction order, at most `max_observables_per_alert` (10).
- **Analyzers** (`analyzers`, by their Cortex name): `kind` (`local`: no data leaves the lab / `online`), `enabled`, `data_types`, `max_tlp` / `max_pap` (n8n refuses to send an alert above them; Cortex checks again), `timeout_s` (the `waitreport` wait), `quota_note`. Seeded: `MISP_2_1` (local, enabled) and the five online analyzers of `nodes/cases/cortex/analyzers/analyzers.json`, **disabled** until they have keys and `n8n-enrichment.md` confirms their data types and quotas. Jobs run one after another (`concurrency: 1`, the only value supported); `force: false` lets Cortex answer from its job cache.
- **Verdict:** each taxonomy level (`info`, `safe`, `suspicious`, `malicious`) through `verdict.levels`, then `verdict.overrides[<analyzer>]`; the worst wins per analyzer and per observable; no taxonomy = `info`. `ioc: true` only for `ioc_verdicts` (`malicious`, ALERT-FORMAT §5), never set back to false. Each enriched observable gets `asox:verdict=<verdict>` and `analyzer:<name>` tags.
- **Open:** `MISP_2_1` reports a hit as `suspicious`, so a MISP hit is **not** an IOC today, although ALERT-FORMAT §5 gives "an IP found in MISP" as an IOC example. Question sent to Cortex + MISP and TheHive; switching is one override line (`overrides: { MISP_2_1: { suspicious: 'malicious' } }`).
- **Failure semantics:** enrichment never parks the alert, never blocks the writeback and never lowers severity, closes or suppresses anything (D12). Per observable: `enriched`, `skipped` (reasons), `failed` (class, attempts). Cortex down → the analyzer list fails after 3 calls and every job is `cortex_unreachable` (one retried call per alert, not per job).
- **Plugging in `n8n-enrichment.md`:** for each analyzer it lists, set `enabled`, `data_types`, `kind`, `timeout_s`, `quota_note`; put per-analyzer level changes in `verdict.overrides`; bump `config_version`; replay the fixtures above.
- **C10 hook:** `lib-enrich-observable` has a labelled no-op node before the plan, where `lib-misp-warninglist` (N8N-2.11) goes; a warninglist tag could then go into `skip` for online analyzers.

### Sub-workflows and error handling

- **Reference sub-workflows by ID** (Execute Workflow node, source "Database", "By ID"). Workflow IDs survive import on every machine: `bootstrap.sh` and `n8n-import.sh` import the files with their own `id`. The SOAR's IDs are fixed and readable (`asoxLibConfig001`, `asoxPbGeneric001`, `asoxLibRouteAlrt`, …), 16 characters like n8n's own. A playbook can also be called by an ID chosen at run time (`recv-wazuh-alert`'s `Playbook (by route)`: `={{ $json.route.playbook_id }}`).
- **Sub-workflows must be active (published):** n8n 2.40.7 runs the published version of a called workflow and fails with "Workflow is not active" otherwise; an inactive error workflow is skipped with only a log line. Every `lib-`/`pb-` file keeps `"active": true`.
- **Error workflow:** `recv-n8n-error` on entry workflows (`recv-`, `pb-`), not on `lib-` workflows: n8n fires the error workflow for a failing sub-workflow **and** for its waiting caller, so setting it on both reports each error twice. Handle expected failures (TheHive HTTP errors, malformed input) explicitly with `lib-error`, which keeps the Wazuh alert id; n8n's Error Trigger has no input data.
- **TheHive calls: timeout and retries (N8N-6.2).** Every TheHive HTTP call has `lib-config`'s `thehive_http.timeout_ms` (10 s). A connection error, a timeout or HTTP 5xx is retried after `thehive_http.retry_waits_s` (2 s, then 5 s: 3 calls in total); a 4xx is never retried. Pattern (copy it for new calls): HTTP node with `neverError` and the error output → `Assess: <call>` (Code; the call count is its `$runIndex`) → `Retry: <call>?` → `Wait before retry: <call>` → the call again; otherwise `Answered: <call>?` → the interpreting node or `Error input`. After the last call the alert is parked by `lib-error` with `attempts` and `retry_exhausted`. A create that timed out may have succeeded: the retry then gets "already exists" and returns the existing alert (`after_retry: true`). Measured 2026-09-30 with the `thehive` container stopped: 3 calls, parked `thehive_unreachable` after ~9 s, alert id and payload kept.
- **Cortex calls (N8N-6.2, C6):** the same pattern with `lib-config` `cortex_http` (10 s, retries after 2 s and 5 s), one call per execution (`lib-cortex-job`, so `$runIndex` counts that call's attempts). `waitreport` is Cortex 4.1's blocking wait for a job (`atMost`, as C7 uses it): one call instead of a polling loop; its HTTP timeout is `timeout_s` + 5 s, and a client timeout there is not retried (it already waited the job's budget) but ends as `timeout`. Retrying the run call is safe with `force: false`: an accepted run comes back from the job cache as the same job. Loops over jobs and observables use **Loop Over Items** + Execute Workflow (n8n 2.40.7 marks the "run once for each item" mode deprecated).
- **TheHive not configured (`THEHIVE_ENABLED=false`).** On a machine running `core` without the cases node, every alert would otherwise be parked as `thehive_unreachable`: a stopped TheHive and one that was never deployed give the same `ENOTFOUND`, and the TheHive credential exists with an empty key either way. So n8n reads `THEHIVE_ENABLED` (non-secret): `false` → `pb-generic` records `skipped: TheHive not configured`, nothing is parked; unset or anything else → TheHive is expected, and an outage is retried, then parked. `render-env.sh` renders it into `nodes/core/.env` (R-18, A79: `true` when `THEHIVE_N8N_API_KEY` is non-empty); `compose.yml` defaults it to `true` when unset.

## Webhooks are authenticated

Every webhook uses **Header Auth** with the shared token `N8N_WEBHOOK_TOKEN` (from `nodes/core/.env`); without it n8n answers 403 (PROJECT.md D36). There are two credentials for it, because TheHive's webhooks can't send custom headers (D43):

- **"ASOX webhook token"**: callers send `X-ASOX-Token: <token>`. Wazuh (C1) and the contract checks use it. Use it on any new webhook that another system calls.
- **"ASOX webhook token (Bearer)"**: callers send `Authorization: Bearer <token>`. Only for webhooks TheHive calls (`recv-thehive-event`).

## Credentials, URLs and secrets

- **Credentials are created by `scripts/bootstrap.sh core`** from `nodes/core/.env`, with fixed IDs, so the credential references inside exported workflows work on every machine:

  | Credential | Type | Used for |
  |---|---|---|
  | `ASOX webhook token` (`asoxWebhookToken`) | Header Auth | Webhook authentication |
  | `ASOX webhook token (Bearer)` (`asoxWebhookBear1`) | Header Auth (`Authorization: Bearer ...`) | Webhooks called by TheHive (C4) |
  | `Wazuh API (n8n-api)` (`asoxWazuhApiRo01`) | Basic Auth | Wazuh API login (`POST ${WAZUH_API_URL}/security/user/authenticate?raw=true`, then `Authorization: Bearer <token>`); read-only role (C2) |
  | `TheHive API (n8n)` (`asoxTheHiveApi01`) | The Hive 5 API | TheHive nodes, or HTTP Request nodes with "Predefined credential type" → The Hive 5 API and URLs from `$env.THEHIVE_URL`; Service account `n8n@asox.local`, profile `analyst` (C3). Its key is `THEHIVE_N8N_API_KEY` in `nodes/core/.env`, copied from the cases node |
  | `Cortex API (n8n)` (`asoxCortexApi001`) | Cortex API | Cortex nodes, or HTTP Request nodes with `$env.CORTEX_URL`; Cortex user `n8n`, roles read + analyze (C6). Its key is `CORTEX_N8N_API_KEY` in `nodes/core/.env`, copied from the cases node |

  The TheHive and Cortex keys arrive through `__from:cases__` (PROJECT.md section 4): `soc.sh init` bootstraps cases before core. After `soc.sh reset cases` (new keys), run `scripts/render-env.sh && scripts/bootstrap.sh core`. A workflow that needs a **new** credential: ask the integrator to add it to `bootstrap.sh` (a credential created only in your UI gets a random ID and breaks on teammates' machines).
- **Service URLs** are available to workflows as environment variables: `{{ $env.WAZUH_API_URL }}`, `{{ $env.THEHIVE_URL }}`, `{{ $env.CORTEX_URL }}`, `{{ $env.N8N_WEBHOOK_URL }}`, plus the C1 threshold `{{ $env.WAZUH_ALERT_MIN_LEVEL }}` (default 7) and `{{ $env.THEHIVE_ENABLED }}` (is TheHive deployed for this core; see "TheHive not configured" below). Never hardcode a host or IP (PROJECT.md section 4).
- **Rule: never put secrets in the n8n container's environment** (`environment:` in `compose.yml`), because every workflow can read it (`$env`). Secrets go in n8n credentials or in secret files (Compose secrets, read through `*_FILE` variables, like the encryption key; docs/decisions.md A42).
- The Wazuh API and the Wazuh indexer use self-signed/internal certificates in the lab: enable "Ignore SSL issues" on HTTP Request nodes that call them (PROJECT.md 4.1).

## Keeping workflows as code

```bash
scripts/n8n-export.sh            # UI -> workflows/*.json (all, or given workflow IDs)
git diff nodes/core/n8n/         # review, then commit
scripts/n8n-import.sh            # workflows/*.json -> n8n (after git pull); OVERWRITES same-ID workflows
```

- One owner per workflow file: n8n JSON merges badly.
- Export first, then pull and import, or your UI changes are overwritten.
- `bootstrap.sh` (run by `soc.sh init`) only imports workflows n8n doesn't have yet; it never overwrites.
- Exported files keep credential references (ID and name), never credential data, and drop pinned test data and volatile fields.

## Operations

- **UI:** `http://localhost:5678`, login from `scripts/soc.sh info`.
- **Executions** are pruned after `N8N_EXECUTIONS_MAX_AGE_HOURS` (168 h) or beyond `N8N_EXECUTIONS_MAX_COUNT` (10,000): the lab agent alone forwards many level 7+ alerts. `recv-*`, `pb-*` and `chk-*` save every execution; `lib-*` save only failed ones (N8N-6.5): the calling playbook's execution holds each lib's result.
- **Saved executions contain the webhook token (N8N-6.5, known limitation).** A `recv-*` execution stores the webhook request as received, headers included: `x-asox-token` (C1, `recv-wazuh-alert`) and `authorization: Bearer …` (C4, `recv-thehive-event`), in clear. There is no clean way to keep them out (checked on 2.40.7, 2026-09-30): the Webhook node's output is saved as is and later nodes can't rewrite it; recv executions must be saved because the C1 and C4 checks look for their test alert there; n8n's execution redaction is an Enterprise feature (off on Community) and only masks data when it is read, not in the database; and the Webhook node's own "sensitive fields" list names `authorization` but not `x-asox-token`, and wasn't applied here either (both tokens came back in clear through the API).
  - **Anyone who can read executions can read the token**, and with it post alerts to n8n. Today that is the n8n owner account (UI) and the scripts' API key (`N8N_API_KEY`, scope `execution:read`), which lives in `nodes/core/.env` next to the token itself. Treat execution access as secret: don't create other n8n users with access to the SOAR's workflows, and don't share execution screenshots or exports of `recv-*` executions.
  - **Retention:** up to 168 h / 10,000 executions, in the `n8n-data` volume. `scripts/backup.sh core` archives that volume, so **core backups contain the token: treat them as secret** (like `--with-secrets` backups).
  - **If it leaks, rotate it:** remove `N8N_WEBHOOK_TOKEN` from `nodes/core/.env`, run `scripts/render-env.sh` (new secret), `scripts/bootstrap.sh core` (n8n credentials), `scripts/bootstrap.sh cases` (TheHive's webhook, C4), and recreate the Wazuh manager so `custom-n8n` gets the new value (C1). Distributed mode: paste the new value into `nodes/cases/.env` first.
- **Memory:** n8n 2.x peaks at ~500–560 MB of anonymous memory while it starts, then settles at ~300–350 MB. The Node.js heap is set by `N8N_HEAP` (384 MB standard / 320 MB low) and the container limit by `N8N_MEM` (750m / 650m), with swap capped at the limit (PROJECT.md D38, D40). If n8n logs `JavaScript heap out of memory`, the heap is too small, not the container.
- **PostgreSQL** (optional, profile `pg`): export all workflows, uncomment the `DB_*` lines in `compose.yml`, and ask the integrator to enable the profile (`COMPOSE_PROFILES=pg` in the core `.env`, which `soc.sh` doesn't manage yet); then restart core and re-run `bootstrap.sh core` and `n8n-import.sh`. Switching is the n8n owner's decision.
- Scripts use n8n's public API with `N8N_API_KEY` (limited scopes, created by `bootstrap.sh`), because the UI login is rate-limited to 5 attempts per window.

## Contracts

| Contract | Role | Status at `v1.0-baseline` |
|---|---|---|
| C1 Wazuh → n8n | Receives alerts on `recv-wazuh-alert` (token required) | Passes |
| C2 n8n → Wazuh API | Credential "Wazuh API (n8n-api)", checked by `chk-wazuh-api` | Passes |
| C3 n8n → TheHive | Credential "TheHive API (n8n)" (Service account `n8n@asox.local`), checked by `chk-thehive-api` | Passes |
| C4 TheHive → n8n | Receives TheHive events on `recv-thehive-event` (token as `Authorization: Bearer`) | Passes |
| C6 n8n → Cortex | Credential "Cortex API (n8n)" (user `n8n`), checked by `chk-cortex-api`; used by `lib-enrich-observable` / `lib-cortex-job` (N8N-2.4) | Passes |
| C9 n8n → endpoints (Phase 2) | Response actions through Wazuh active response | Planned |

Check: `scripts/contracts-check.sh --only C1,C2,C3,C4,C6` (enrichment: add C7, in `full`). Exporting changes: section "Keeping workflows as code". Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Pinned: `n8nio/n8n` 2.40.7 (`postgres` 16.15 for the optional `pg` profile). On every version bump, re-check each item and update this list.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| Explicit Node.js heap (`NODE_OPTIONS=--max-old-space-size=${N8N_HEAP}`) | Node's default heap, derived from the container limit, is too small for n8n 2.x's startup (A43, D38) | Measure start-up memory again (5 cold starts, anon peak from `memory.stat`; D40); watch for `heap out of memory` |
| Internal task runner (`N8N_RUNNERS_MODE` unset = internal) | **Deprecated upstream** (warning at start); external mode needs a separate runner container (A43) | Still supported? If removed, add the runner container (memory!) |
| Python task runner missing | The image has no Python; n8n warns at every start (harmless: JavaScript Code nodes only) | Nothing unless Python Code nodes are needed |
| Defaults announced to change (warnings in 2.40.7 logs) | `N8N_UNVERIFIED_PACKAGES_ENABLED` → `false`, `N8N_RUNNERS_TASK_TIMEOUT` 300 → 60 s, `N8N_COMPRESSION_NODE_MAX_DECOMPRESSED_SIZE_BYTES` 2 GiB → 256 MiB, `N8N_COMPRESSION_NODE_MAX_ZIP_ENTRIES` 5000 → 1000 | Decide whether a playbook needs the old value, and set it explicitly in `compose.yml` |
| Internal REST API used by `bootstrap.sh` / `scripts/lib/n8n.sh`: `/rest/settings`, `/rest/owner/setup`, `/rest/login`, `/rest/api-keys` | Owner setup and API key creation have no public API (A45, A46) | `soc.sh reset core` + `soc.sh init core` on a scratch instance (`SOC_INSTANCE=test`) |
| CLI `import:credentials` / `import:workflow` in a one-off container, then activation through the public API | `--activeState=fromJson` only works in queue mode; activation must go through the running server (A44) | `bootstrap.sh core` on a fresh instance; `n8n-import.sh` round trip |
| `N8N_WEBHOOK_URL` as the webhook base URL | The older `WEBHOOK_URL` is deprecated and not used (A42) | Webhook URLs shown in the UI still use `N8N_WEBHOOK_URL` |
| Credentials with fixed IDs (`asoxWebhookToken`, `asoxWebhookBear1`, `asoxWazuhApiRo01`, `asoxTheHiveApi01`, `asoxCortexApi001`) and types `httpHeaderAuth` / `httpBasicAuth` / `theHiveProjectApi` / `cortexApi` | Exported workflows reference credentials by ID (A44) | Credential types still exist (fields `ApiKey`, `url`; `cortexApiKey`, `host`); C1–C4 and C6 pass |
| `recv-thehive-event` authenticates `Authorization: Bearer` instead of `X-ASOX-Token` | TheHive's webhook endpoints can't send custom headers (A64, D43) | If a TheHive upgrade supports headers, C4 could move back to `X-ASOX-Token` (contract change) |
| Secrets as Compose secret files (`N8N_ENCRYPTION_KEY_FILE`, `DB_POSTGRESDB_PASSWORD_FILE`) | Workflows can read the whole environment (D37, A42) | The `*_FILE` variables are still supported |

## Backlog (PROJECT.md 11.3)

Pick from this list; Phase 1 only built the baseline.

- ~~**Router de Playbooks** on `recv-wazuh-alert`~~ (N8N-1.3, 2026-10-06, see "Routing") and `recv-thehive-event` (N8N-1.5).
- Playbooks per alert type (e.g. SSH brute force, malware hash, IDS alert, generic), following the conventions above.
- ~~`lib-` sub-workflows for enrichment (Cortex)~~ (N8N-2.4, 2026-10-06, MISP only until the online analyzers have keys) and TheHive updates.
- Alert deduplication before TheHive; error handling and retries.
- Analyst approval flow (in TheHive first, Slack in Phase 3).
- Response actions via C9 (Phase 2, with the Wazuh owner).
