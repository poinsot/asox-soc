# n8n — SOAR, "Orchestrador"

Owner: n8n owner. Node: `core`. Run mode: `core-cases` (`core` is enough for C1/C2 work).

n8n is the platform's SOAR and integration hub, and the **only** component that executes automated actions that change systems (PROJECT.md 6.2, D12). The full component README (contracts, backlog) is completed at the end of Phase 1; this file already has the conventions and operations.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `n8n` (SQLite in the `n8n-data` volume); `n8n-postgres` under the optional profile `pg` |
| `workflows/*.json` | Workflows as code, one file per workflow (exported by `scripts/n8n-export.sh`) |

Baseline workflows:

| Workflow | Trigger | Purpose |
|---|---|---|
| `recv-wazuh-alert` | `POST /webhook/wazuh-alert` (Wazuh `custom-n8n` integration, C1) | Stub: records a summary of each alert (level >= `WAZUH_ALERT_MIN_LEVEL`). The Router de Playbooks attaches here. |
| `recv-thehive-event` | `POST /webhook/thehive-event` (TheHive webhook, C4, wired in step 1.7) | Stub: records a summary of each TheHive event. |
| `chk-wazuh-api` | `POST /webhook/chk-wazuh-api` (`scripts/contracts-check.sh`) | Contract check C2: logs in with the n8n-api credential, lists agents, and verifies that active response is refused. Don't change it without the integrator. |

## Playbook conventions (every workflow author follows them)

- **Naming:** `pb-<use-case>` for playbooks (e.g. `pb-ssh-bruteforce`), `recv-<source>` for entry points, `lib-<function>` for reusable sub-workflows (e.g. `lib-enrich-observable`), `chk-<what>` for contract checks.
- **Header note:** a sticky note in every playbook declares **trigger**, **inputs**, **actions taken**, **systems changed** (none / which), **approval** (`required` / `auto_approve`) and **owner** (see the stubs).
- **Traceability:** every execution carries the Wazuh alert ID and, once created, the TheHive alert or case ID, and writes a summary of its actions back to the TheHive record.
- **Approval by default:** a playbook that changes systems requires analyst approval unless it is explicitly marked `auto_approve`; justify that marking in the checkpoint pull request.
- **Idempotent and safe to re-run:** the same alert processed twice must not create duplicate TheHive records or repeat actions.

## Webhooks are authenticated

Every webhook uses **Header Auth** with the credential **"ASOX webhook token"**: callers must send `X-ASOX-Token: <N8N_WEBHOOK_TOKEN>` (from `nodes/core/.env`), otherwise n8n answers 403. Wazuh (C1) and TheHive (C4) send it. Use the same credential on any new webhook that another system calls (PROJECT.md D36).

## Credentials, URLs and secrets

- **Credentials are created by `scripts/bootstrap.sh core`** from `nodes/core/.env`, with fixed IDs, so the credential references inside exported workflows work on every machine:

  | Credential | Type | Used for |
  |---|---|---|
  | `ASOX webhook token` (`asoxWebhookToken`) | Header Auth | Webhook authentication |
  | `Wazuh API (n8n-api)` (`asoxWazuhApiRo01`) | Basic Auth | Wazuh API login (`POST ${WAZUH_API_URL}/security/user/authenticate?raw=true`, then `Authorization: Bearer <token>`); read-only role (C2) |

  TheHive and Cortex credentials are added in step 1.7. A workflow that needs a **new** credential: ask the integrator to add it to `bootstrap.sh` (a credential created only in your UI gets a random ID and breaks on teammates' machines).
- **Service URLs** are available to workflows as environment variables: `{{ $env.WAZUH_API_URL }}`, `{{ $env.THEHIVE_URL }}`, `{{ $env.CORTEX_URL }}`, `{{ $env.N8N_WEBHOOK_URL }}`. Never hardcode a host or IP (PROJECT.md section 4).
- n8n's environment must **never contain secrets**, because every workflow can read it. Secrets live in credentials; the encryption key is passed as a Compose secret file (docs/decisions.md A42).
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
- **Executions** are pruned after `N8N_EXECUTIONS_MAX_AGE_HOURS` (168 h) or beyond `N8N_EXECUTIONS_MAX_COUNT` (10,000): the lab agent alone forwards many level 7+ alerts.
- **Memory:** n8n 2.x peaks at ~730 MB when it starts; the Node.js heap is set by `N8N_HEAP` (384 MB standard / 256 MB low) and the container limit by `N8N_MEM`.
- **PostgreSQL** (optional, profile `pg`): export all workflows, uncomment the `DB_*` lines in `compose.yml`, and ask the integrator to enable the profile (`COMPOSE_PROFILES=pg` in the core `.env`, which `soc.sh` doesn't manage yet); then restart core and re-run `bootstrap.sh core` and `n8n-import.sh`. Switching is the n8n owner's decision.
- Scripts use n8n's public API with `N8N_API_KEY` (limited scopes, created by `bootstrap.sh`), because the UI login is rate-limited to 5 attempts per window.
