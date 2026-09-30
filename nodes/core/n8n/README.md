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
| `recv-wazuh-alert` | `POST /webhook/wazuh-alert` (Wazuh `custom-n8n` integration, C1) | Answers 200 on receipt and keeps the full alert in its execution (the C1 check looks there). Reads `lib-config`, records `filtered: level N < M` below `WAZUH_ALERT_MIN_LEVEL` and `skipped: sca (X-09)` for the temporary SCA exclusion, and hands every other alert to `pb-generic` without waiting. That call is where the Router de Playbooks goes (N8N-1.3). |
| `pb-generic` | Called by `recv-wazuh-alert` | First playbook: see the catalog below. |
| `lib-config` | Called by workflows | Data only: severity table, TLP/PAP, asset criticality, test sources (`100100` → `asox-test`), case templates, enabled observable types, intake exclusions, writeback marker (N8N-2.6 seed). Temporary entries name their ticket. |
| `lib-normalize-wazuh-alert` | Called by playbooks | Canonical alert per `docs/WAZUH-FIELDS.md`; the alert id stays a string. Malformed alerts go to `lib-error` (N8N-1.2). |
| `lib-thehive-upsert-alert` | Called by playbooks | Creates the TheHive alert (ALERT-FORMAT); "already exists" → returns the existing one with `duplicate: true` (N8N-2.1, 3.1). |
| `lib-thehive-writeback` | Called by playbooks | Comment on the TheHive alert starting `[asox-n8n writeback] wazuh-alert-id=<id>`; written once (N8N-2.2). |
| `lib-error` | Called by workflows (not waited for) | Classifies (`malformed_input`, `thehive_unreachable`, `thehive_4xx`, `unknown`), records alert id, failing workflow and payload, comments on the TheHive alert if any, then parks: the execution ends in error (N8N-2.5). Parked items = failed `lib-error` executions, kept 168 h, until N8N-6.3. |
| `recv-n8n-error` | n8n Error Trigger | Global error workflow of `recv-wazuh-alert` and `pb-generic`: hands n8n's unhandled errors to `lib-error` (N8N-6.1). |
| `recv-thehive-event` | `POST /webhook/thehive-event` (TheHive webhook, C4: every event of the SOC organisation) | Stub: records a summary of each TheHive event (operation, object type and ID, source). |
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

**`pb-generic`** (N8N-4.1). *Trigger:* `recv-wazuh-alert`, for every alert at or above the threshold that isn't excluded. *Steps:* `lib-normalize-wazuh-alert` → `lib-thehive-upsert-alert` → **enrichment stub** (a no-op node; `lib-enrich-observable` goes there, N8N-2.3/2.4) → `lib-thehive-writeback`. *Systems changed:* TheHive only (alert and comment). *Approval:* not needed. *Result:* `outcome` = `created`, `duplicate` (the same Wazuh alert again: nothing new is created or written) or `parked` (see `lib-error`). *Test:* `fixtures/replay.sh --fresh-id --times 2 --delay 5 --file fixtures/wazuh/100100-asox-test-c1.json` → one `asox-test` alert (severity 3, observables `ip` and `hostname` of the agent) with one writeback comment; `19007` → skipped, `503` → filtered, `invalid/100100-no-id.json` → parked; delete the `asox-test` alerts afterwards. **Known limitation:** two copies of one alert arriving at the same moment create two TheHive alerts, because TheHive's duplicate refusal isn't atomic (`docs/ALERT-TO-THEHIVE.md` §2). C1 never sends copies; tests and replays can.

### Sub-workflows and error handling

- **Reference sub-workflows by ID** (Execute Workflow node, source "Database", "By ID"). Workflow IDs survive import on every machine: `bootstrap.sh` and `n8n-import.sh` import the files with their own `id`. The SOAR's IDs are fixed and readable (`asoxLibConfig001`, `asoxPbGeneric001`, …).
- **Sub-workflows must be active (published):** n8n 2.40.7 runs the published version of a called workflow and fails with "Workflow is not active" otherwise; an inactive error workflow is skipped with only a log line. Every `lib-`/`pb-` file keeps `"active": true`.
- **Error workflow:** `recv-n8n-error` on entry workflows (`recv-`, `pb-`), not on `lib-` workflows: n8n fires the error workflow for a failing sub-workflow **and** for its waiting caller, so setting it on both reports each error twice. Handle expected failures (TheHive HTTP errors, malformed input) explicitly with `lib-error`, which keeps the Wazuh alert id; n8n's Error Trigger has no input data.

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
- **Service URLs** are available to workflows as environment variables: `{{ $env.WAZUH_API_URL }}`, `{{ $env.THEHIVE_URL }}`, `{{ $env.CORTEX_URL }}`, `{{ $env.N8N_WEBHOOK_URL }}`, plus the C1 threshold `{{ $env.WAZUH_ALERT_MIN_LEVEL }}` (default 7). Never hardcode a host or IP (PROJECT.md section 4).
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
| C6 n8n → Cortex | Credential "Cortex API (n8n)" (user `n8n`), checked by `chk-cortex-api` | Passes |
| C9 n8n → endpoints (Phase 2) | Response actions through Wazuh active response | Planned |

Check: `scripts/contracts-check.sh --only C1,C2,C3,C4,C6`. Exporting changes: section "Keeping workflows as code". Changing a contract needs the other owner's agreement first (PROJECT.md 5).

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

- **Router de Playbooks** on `recv-wazuh-alert` (and `recv-thehive-event`).
- Playbooks per alert type (e.g. SSH brute force, malware hash, IDS alert, generic), following the conventions above.
- `lib-` sub-workflows for enrichment (Cortex) and TheHive updates.
- Alert deduplication before TheHive; error handling and retries.
- Analyst approval flow (in TheHive first, Slack in Phase 3).
- Response actions via C9 (Phase 2, with the Wazuh owner).
