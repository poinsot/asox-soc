# TheHive — "Dashboard operativo"

Owner: Park (@Jinhyuk-P). Branch: `thehive`. Node: `cases`. Run mode: `cases`.

Alert triage and case management for analysts. **Apply your Community license before the 14-day trial ends** (section License).

**Start here:** [CONTRIBUTING.md](../../../CONTRIBUTING.md) (light rules, exporting changes, onboarding), then this file. First time: `./scripts/soc.sh init cases`; then `soc.sh up cases` / `soc.sh down`. Test loop: configure in the UI → create test alerts through the API (Wazuh doesn't run in this mode) → check the alert and case flow. Details: [PROJECT.md](../../../PROJECT.md) 6.4.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `thehive` (TheHive 5, served on port 9000 at the root path) |
| `config/application.conf` | TheHive configuration; secrets come from the environment (`${VAR}`), never from this file |
| `scripts/` | `thehive-export.sh` / `thehive-import.sh` (UI configuration ↔ `entities/`), `thehive-test-alert.sh` (test alerts) and their shared `lib.sh` |
| `entities/` | Exported configuration: 9 custom fields, observable types (+ `user-account`), 12 case templates (JSON, committed) |
| `BACKLOG.md` | TheHive's backlog: milestones M0–M7 to the 2026-12-01 delivery, tasks `T0.1`… with priority, "done when" and links to the integration register (`X-nn`) |
| `docs/` | [ALERT-FORMAT.md](docs/ALERT-FORMAT.md) (alert format, severity / TLP / PAP, template routing, alert-to-case rules), [TRIAGE.md](docs/TRIAGE.md) (triage procedure, users and roles); [DEMO.md](docs/DEMO.md) (practice run, demo script, evidence checklist); `reply-<owner>-<date>.md`: TheHive's replies to other owners' requests, kept as sent |
| `../storage.yml` (integrator-owned) | `cassandra` (TheHive's database) and `elasticsearch` (search index, shared with Cortex) |

UI: `http://localhost:9000`, logins from `scripts/soc.sh info` (the analyst for daily work, `admin@thehive.local` for platform management and the license).

## What bootstrap creates

`scripts/bootstrap.sh cases` (run by `soc.sh init`) creates or checks, from `nodes/cases/.env`:

| Object | Details |
|---|---|
| Platform admin `THEHIVE_ADMIN_USER` | The image's default `admin@thehive.local` / `secret`; the default password is replaced with `THEHIVE_ADMIN_PASSWORD` on the first run |
| Organisation `THEHIVE_ORG` (`SOC`) | The one organisation the community license allows |
| Analyst `THEHIVE_ANALYST_USER` | Normal user, profile **`org-admin`** in `SOC`, UI login (`soc.sh info`). It is the organisation's administrator, so the TheHive owner can manage case templates, custom fields, observable types and the organisation's settings from the UI (PROJECT.md D42). Scripts never use its password |
| n8n API user `THEHIVE_N8N_USER` | **Service** account (API key only, no password), profile `analyst`; its key is `THEHIVE_N8N_API_KEY` (C3) |
| Bootstrap user `THEHIVE_BOOTSTRAP_USER` | **Service** account, profile `org-admin` in `SOC`: `bootstrap.sh`'s own identity for organisation settings the platform admin can't reach. Its API key is created, used and **revoked** on every run, so no key exists between runs (D42) |
| Cortex connector | Server "Cortex" at `CORTEX_URL`, authenticated with the key of Cortex's `thehive` user (C5); rewritten on every run |
| Webhook to n8n (C4) | Global endpoint `n8n` → `${N8N_WEBHOOK_URL}/webhook/thehive-event`, authentication "bearer" with `N8N_WEBHOOK_TOKEN` (TheHive sends `Authorization: Bearer <token>`), and the `SOC` notification rule **"n8n (C4)"**: every event (`AnyEvent`) → that endpoint. Both rewritten on every run |

Check: `scripts/contracts-check.sh --only C3,C4,C5`.

**Don't delete or rename the "n8n (C4)" notification rule or the `n8n` endpoint**: n8n's router depends on them. You can add your own rules next to it; `bootstrap.sh cases` recreates it if it's gone.

## License (important)

A fresh TheHive starts on a **14-day Platinum trial**. After it ends, TheHive becomes **read-only** (no new alerts or cases, so C3 and every n8n playbook fail) until a license is activated. The free **Community license** allows **2 users, 1 organisation, 1 Cortex server, 1 MISP server**. Only Normal accounts with licensed permissions count as users: Service accounts (like the n8n and bootstrap API users) and Admin / Read-only accounts don't. Our instance has one Normal user (the analyst), so **one seat is left**. Webhooks (C4) need the license capability `notification.webhook`: `bootstrap.sh cases` and `healthcheck.sh` warn if the active license lacks it.

**Everyone who runs the cases node needs their own Community license** (it is free, but StrangeBee validates each portal account by hand, so request it on day one; see `CHECKLIST.md` section 9).

### How a license is tied to an instance

The license key is generated from a **challenge** that contains TheHive's **instance ID**: a random UUID that TheHive creates in its own database (Cassandra, graph variable `instance-id`) the first time it needs one. TheHive accepts a key only if its instance ID matches the database's ("License is not for this instance"); the hostname and the machine don't matter. The activated key is stored in the database too (docs/decisions.md A57).

| Action | Instance ID | License |
|---|---|---|
| `soc.sh down` / `up`, restarts, image rebuilds | Kept | Kept |
| `soc.sh reset cases`, then `init` | **New** (Cassandra is wiped) | **Lost**: a new 14-day trial starts; after it, activate again with the new challenge |
| Fresh `soc.sh init` on another machine or another `SOC_INSTANCE` (e.g. the fresh-clone test) | **New** | Its own trial; needs its own activation |
| `restore.sh cases` of a backup (same or another machine) | The backup's | The backup's: a license activated **before** the backup is kept, even on another machine; one activated after it must be re-applied (the same key works, since the ID matches) |

Re-activating for a new instance ID uses the same portal page ("Activate or View details" of your Community license): paste the new challenge and generate a new key. Whether the portal allows unlimited re-activations of one Community license isn't documented; if it refuses, ask StrangeBee.

### Requesting and applying a license

1. **Request (once per person):** register on the StrangeBee license portal (`portal.apps.strangebee.com`) with a professional email, confirm the email, wait until StrangeBee validates the account, then log in and choose **Request a Community license** → **Get a Community license**. When requesting it, **ask StrangeBee whether the license can be re-activated on a new instance** after a reset (a reset changes the instance ID).
2. **Copy the challenge** from your instance: log in to TheHive as the platform admin (`scripts/soc.sh info`, user `admin@thehive.local`), open **Platform management** → **License** → **Update the current license** → **Copy this challenge**.
3. **Generate the key:** on the portal, **Licenses** tab → **Activate** (or **View details**) on your Community license → paste the challenge into **License key activation challenge** → **Activate license** → **Copy the key to clipboard**.
4. **Apply it:** back in TheHive's drawer, paste the key into **License** → **Activate the license key**.
5. **Check:** `scripts/soc.sh info cases` shows the license line (plan, kind, expiry). `scripts/bootstrap.sh cases` (also run by `soc.sh init`) prints a `WARN` when TheHive is read-only or its trial has 3 days or less left (`THEHIVE_LICENSE_WARN_DAYS`).
6. **Back it up right away:** `scripts/backup.sh cases --with-secrets`. From then on, to get a clean or repaired TheHive, **restore that backup instead of running `soc.sh reset cases`**: a reset creates a new instance and loses the license (PROJECT.md D41), while a restore keeps it.

## Contracts and exporting changes

| Contract | Role | Status at `v1.0-baseline` |
|---|---|---|
| C3 n8n → TheHive | Provides the Service account `n8n@asox.local` and its API key | Passes |
| C4 TheHive → n8n | Webhook (endpoint `n8n` + notification rule "n8n (C4)"), token as `Authorization: Bearer` | Passes |
| C5 TheHive → Cortex | Cortex connector (server "Cortex") | Passes |

Check: `scripts/contracts-check.sh --only C3,C4,C5` (C3 and C4 create a test alert with `source: contract-check` and delete it). **Exporting changes:** see the next section. Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Exporting and importing the configuration

TheHive keeps its configuration in its database, so changes made in the UI reach git only through these scripts (PROJECT.md 11.2). Run them on the machine hosting `cases`, while it is up.

| What (kind) | Scope | File in `entities/` |
|---|---|---|
| `custom-fields` | Platform (Entities management → Custom fields) | `custom-fields.json` |
| `observable-types` | Platform (Entities management → Observables) | `observable-types.json` |
| `case-templates` | Organisation `SOC` (Organisation → Templates) | `case-templates.json` |

```bash
nodes/cases/thehive/scripts/thehive-export.sh              # TheHive -> entities/*.json
nodes/cases/thehive/scripts/thehive-import.sh --dry-run    # what would change
nodes/cases/thehive/scripts/thehive-import.sh              # entities/*.json -> TheHive
```

Both take kinds as arguments (default: all), e.g. `thehive-export.sh case-templates`.

- **Export** leaves out IDs, dates and authors and sorts every list by name, so the files are identical on every machine and `git diff` shows only real changes. Export before committing, and before pulling someone else's changes.
- **Import** matches objects by name: it creates what's missing and updates what differs, and never deletes anything (safe to re-run; no duplicates). Custom fields are imported before case templates, which refer to them. Objects that exist only in TheHive are listed and left as they are.
- **Accounts:** the platform admin for custom fields and observable types; for case templates (organisation settings the admin can't reach) the Service account `THEHIVE_BOOTSTRAP_USER`, through a temporary API key revoked when the script exits, as `bootstrap.sh` does (D42). No password or key is written anywhere.
- **Limits:** a custom field's `type` and an observable type's `isAttachment` can't be changed through the API (import warns; change them in the UI). If TheHive refuses to update a case template, import deletes and recreates it; cases already created from it keep their own copy.

After a `restore.sh cases`, nothing needs re-importing (the configuration is in the backup); after a reset or on a new machine, run `thehive-import.sh`.

## Local patches and deprecations (re-check on upgrade)

Pinned: `strangebee/thehive` 5.7.6, `cassandra` 4.1.12, `elasticsearch` 8.19.21 (StrangeBee's reference pairing with Cortex 4.1). On every version bump, re-check each item and update this list.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| `command: --no-config --no-config-secret` | The image's entrypoint would otherwise generate its own database, index and secret settings; everything lives in `config/application.conf` instead (as in StrangeBee's reference) | Entrypoint options (`/opt/thehive/entrypoint`) unchanged |
| Default admin password replaced through the API (`/api/v1/user/<login>/password/change`) | The image ships `admin@thehive.local` / `secret` | Fresh `soc.sh init cases` |
| Cortex connector set through `PUT /api/v1/admin/config/cortex` | Keeps the Cortex API key out of files; the call needs `statusCheckInterval`, `refreshDelay`, `maxRetryOnError` besides `servers` | C5 passes |
| C5 reads `GET /api/v1/status` → `.connectors.cortex` | Only place TheHive 5.7 reports the Cortex server status (`/api/connector/cortex/status` doesn't exist) | C5 passes |
| n8n API user of type `Service` | Doesn't use one of the 2 Normal user seats (A53, A57) | License quotas in `GET /api/v1/status` → `.license.quotas` |
| Webhook: endpoint through `PUT /api/v1/admin/config/global/endpoint` (type `webhook`, `auth` bearer), rule through `PUT /api/v1/notification/organisation` as the bootstrap user | Webhook endpoints ignore custom headers, so the token goes as a bearer key; rules are read only from the organisation's stored settings, not from `application.conf` defaults, and only an org-admin of `SOC` can write them (A64, D42) | C4 passes (rule changes take up to 5 minutes: TheHive caches them) |
| TheHive and Cortex use Elasticsearch's built-in `elastic` superuser | As in StrangeBee's reference; dedicated users are hardening for later (A52) | — |
| Cassandra without authentication | Internal to the cases node, never published or on `soc-net` (A52) | — |
| License: challenge from `GET /api/v1/license/challenge` (instance ID from the graph variable `instance-id`), status from `GET /api/v1/status` → `.license` (`kind`, `plan`, `expiresAt`, `isValid`) | Used by `soc.sh info` and the bootstrap warning (A57) | Both endpoints still answer; a reset still starts a new trial |
| Memory: `THEHIVE_MEM` 1900m / 1300m, swap capped at the limit | Measured need (PROJECT.md D40): TheHive uses ~550 MB beyond its heap | Re-measure the anonymous memory peak (`memory.stat`) through start, bootstrap and some API activity |

## Backlog (PROJECT.md 11.3)

The plan and the features of this component are in [BACKLOG.md](BACKLOG.md): what TheHive does in the SOC, milestones M0–M7 to the 2026-12-01 delivery, and every task with its priority, "done when" and links to the integration register (`docs/integration-backlog.md`).

## Trying it out

```bash
nodes/cases/thehive/scripts/thehive-import.sh                  # load the templates and fields (fresh machine)
nodes/cases/thehive/scripts/thehive-test-alert.sh all          # 12 test alerts, one per case template
nodes/cases/thehive/scripts/thehive-test-alert.sh all --promote  # same, and promote each to a case as n8n would
# triage them in the UI (docs/TRIAGE.md), then:
nodes/cases/thehive/scripts/thehive-test-alert.sh --cleanup    # delete the test alerts and test cases
nodes/cases/thehive/scripts/thehive-fp-report.sh --days 30     # false positives by Wazuh rule (Markdown)
```

| Script | What it does |
|---|---|
| `thehive-export.sh` | Saves custom fields, observable types and case templates from TheHive into `entities/` |
| `thehive-import.sh` | Loads `entities/` into TheHive (creates / updates, never deletes; `--dry-run`) |
| `thehive-test-alert.sh` | Test alerts shaped like n8n's (`ssh malware ids generic login sudo newuser ioc portscan fwlogin web fim`), `--critical-asset`, `--promote`, `--cleanup` |
| `thehive-fp-report.sh` | Cases and alerts closed as false positive / ignored, grouped by `wazuh-rule-id`, for Wazuh tuning (`--days N`, `--out FILE`) |

## Design discussion: direct links between Wazuh and TheHive (decided 2026-09-30)

The team discussed **adding** two direct connections between Wazuh and TheHive, next to the existing ones. The integrator decided both on 2026-09-30 (PROJECT.md 5, D47, D48; `docs/integration-backlog.md` X-26, X-33):

| Proposal | Decision | Why |
|---|---|---|
| **A. Wazuh → TheHive:** Wazuh creates TheHive alerts itself (a Wazuh integration script with a TheHive Service account) | **Rejected** (contract C12, D47). Every alert keeps going C1 → n8n → C3 | n8n is the single orchestration point (D12), and a second path needs deduplication between the two (TheHive's own T5.2), which routing everything through n8n avoids. No use case needs it |
| **B. TheHive → Wazuh:** from a case, look up Wazuh's logs for an observable | **Accepted in another form** (contract C13, D48): a Cortex analyzer calls n8n's read-only `wazuh-lookup` webhook, and n8n queries the Wazuh indexer | Wazuh's alerts live in the indexer, which isn't reachable from `cases` and isn't in the Wazuh API; going through n8n keeps the indexer unexposed. Nothing to build in TheHive: analysts run the analyzer from a case (BACKLOG.md T5.3) |

Still true from the discussion: TheHive holds only the alerts a person must look at (level ≥ 7 through C1), while **all** logs stay in the Wazuh indexer, viewed in Grafana and, through C13, from TheHive cases. Pings reach Wazuh only with firewall logging or the Suricata IDS (D49) plus a Wazuh rule.
