# TheHive — "Dashboard operativo"

Owner: Park (@Jinhyuk-P). Node: `cases`. Run mode: `cases`.

Alert triage and case management for analysts. The full component README (contracts, export rules, backlog) is completed at the end of Phase 1; this file already covers the operations below.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `thehive` (TheHive 5, served on port 9000 at the root path) |
| `config/application.conf` | TheHive configuration; secrets come from the environment (`${VAR}`), never from this file |
| `../storage.yml` (integrator-owned) | `cassandra` (TheHive's database) and `elasticsearch` (search index, shared with Cortex) |

## What bootstrap creates

`scripts/bootstrap.sh cases` (run by `soc.sh init`) creates or checks, from `nodes/cases/.env`:

| Object | Details |
|---|---|
| Platform admin `THEHIVE_ADMIN_USER` | The image's default `admin@thehive.local` / `secret`; the default password is replaced with `THEHIVE_ADMIN_PASSWORD` on the first run |
| Organisation `THEHIVE_ORG` (`SOC`) | The one organisation the community license allows |
| Analyst `THEHIVE_ANALYST_USER` | Normal user, profile `analyst`, UI login (`soc.sh info`) |
| n8n API user `THEHIVE_N8N_USER` | **Service** account (API key only, no password), profile `analyst`; its key is `THEHIVE_N8N_API_KEY` (C3) |
| Cortex connector | Server "Cortex" at `CORTEX_URL`, authenticated with the key of Cortex's `thehive` user (C5); rewritten on every run |

Check the connector: `scripts/contracts-check.sh --only C5`.

## License (important)

A fresh TheHive starts on a **14-day Platinum trial**. After it ends, TheHive becomes **read-only** until a license is activated. The free **Community license** is requested on StrangeBee's portal (`portal.apps.strangebee.com`: register with a professional email, wait for validation, then "Request a Community license") and entered in the admin UI. Its quotas: **2 users, 1 organisation, 1 Cortex server, 1 MISP server** (docs/decisions.md A53). Service accounts (like the n8n API user) did not count against the user quota during the trial; check this again once a Community license is active. Each machine's instance has its own trial; `soc.sh reset cases` starts a new one.

## Local patches and deprecations (re-check on upgrade)

Pinned: `strangebee/thehive` 5.7.6, `cassandra` 4.1.12, `elasticsearch` 8.19.21 (StrangeBee's reference pairing with Cortex 4.1). On every version bump, re-check each item and update this list.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| `command: --no-config --no-config-secret` | The image's entrypoint would otherwise generate its own database, index and secret settings; everything lives in `config/application.conf` instead (as in StrangeBee's reference) | Entrypoint options (`/opt/thehive/entrypoint`) unchanged |
| Default admin password replaced through the API (`/api/v1/user/<login>/password/change`) | The image ships `admin@thehive.local` / `secret` | Fresh `soc.sh init cases` |
| Cortex connector set through `PUT /api/v1/admin/config/cortex` | Keeps the Cortex API key out of files; the call needs `statusCheckInterval`, `refreshDelay`, `maxRetryOnError` besides `servers` | C5 passes |
| C5 reads `GET /api/v1/status` → `.connectors.cortex` | Only place TheHive 5.7 reports the Cortex server status (`/api/connector/cortex/status` doesn't exist) | C5 passes |
| n8n API user of type `Service` | Doesn't use one of the 2 Normal user seats (A53) | License quotas in `GET /api/v1/status` → `.license.quotas` |
| TheHive and Cortex use Elasticsearch's built-in `elastic` superuser | As in StrangeBee's reference; dedicated users are hardening for later (A52) | — |
| Cassandra without authentication | Internal to the cases node, never published or on `soc-net` (A52) | — |
| Memory: `THEHIVE_MEM` 1900m / 1300m, swap capped at the limit | Measured need (PROJECT.md D40): TheHive uses ~550 MB beyond its heap | Re-measure the anonymous memory peak (`memory.stat`) through start, bootstrap and some API activity |
