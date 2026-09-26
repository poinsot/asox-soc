# MISP — "Inteligencia de amenazas" (with Cortex)

Owner: Diego (@DiegoGuerraA00835430). Node: `intel`. Run mode: `cases-intel`.

MISP stores threat intelligence (events, IOCs, tags, galaxies) and can share it; Cortex's MISP analyzer searches it (contract C7). The full component README (contracts, export rules, backlog) is completed at the end of Phase 1; this file already covers the operations below.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `misp-core` (MISP), `misp-nginx` (HTTPS front end, 8443 → published 9443), `misp-modules`, `mariadb`, `redis` (Valkey) |
| `seed/seed-event.json` | The seed event with the test IOC `203.0.113.66`, created by bootstrap for C7 |
| `../certs/` (generated, git-ignored) | MISP's self-signed certificate (`scripts/gen-certs.sh intel`) |

UI: `https://localhost:9443` (a certificate warning is expected), login from `scripts/soc.sh info` (`MISP_ADMIN_EMAIL`).

## What bootstrap creates

`scripts/bootstrap.sh intel` (run by `soc.sh init`) creates or checks, from `nodes/intel/.env`:

| Object | Details |
|---|---|
| Site admin `MISP_ADMIN_EMAIL`, organisation `MISP_ORG` (`SOC`) | Applied by the image at every start (e-mail, password, organisation name) |
| Admin API key `MISP_ADMIN_KEY` | Set through MISP's CLI (`cake User change_authkey`); used by the scripts |
| User `MISP_CORTEX_USER` (`cortex@asox.local`) | Role **Read Only**; its API key `MISP_CORTEX_API_KEY` goes to the cases node for Cortex's MISP analyzer (C7) |
| Seed event | From `seed/seed-event.json`, published; C7 checks that the analyzer finds it |

If the Cortex user's key changes (e.g. after `soc.sh reset intel`), Cortex needs it too: `scripts/render-env.sh && scripts/bootstrap.sh cases` on the cases machine (`soc.sh init` with both nodes does this by itself).

## Notes

- **No e-mail:** `misp-docker`'s mail relay is not deployed, so MISP can't send notifications; events are published without e-mail.
- **Start-up:** the first start takes ~2 minutes; every start reloads galaxies, taxonomies, warninglists and object templates from the image (misp-core's memory peaks then).
- **Distributed mode:** Cortex reaches MISP at `https://<INTEL_HOST>:9443`; the certificate is issued for the `MISP_BASE_URL` host, so after changing `INTEL_HOST` run `scripts/gen-certs.sh --force intel` and restart intel.

## Contracts and exporting changes

| Contract | Role | Status (build step) |
|---|---|---|
| C7 Cortex → MISP | Provides the Read Only user `cortex@asox.local`, its API key and the seed event | Passes (1.6) |

Check: `scripts/contracts-check.sh --only C7`. **Exporting changes:** MISP's settings, taxonomies, feeds and events live in its database; export/import scripts in this folder are the owner's task (PROJECT.md 11.2); the seed event is `seed/seed-event.json`. Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Pinned: `misp-core` / `misp-nginx` v2.5.47, `misp-modules` v3.0.10, `mariadb` 10.11.19, `valkey` 7.2.14 (from `misp-docker`'s `template.env`). On every version bump, re-check each item and update this list.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| Compose adapted from `misp-docker` `docker-compose.yml` without `mail` and `misp-guard`; named volumes instead of bind mounts | Lab scope; data never in the repo (docs/decisions.md A58) | Diff the new upstream `docker-compose.yml` and `template.env` against `compose.yml`: new required variables, renamed ones (the image refuses to start on some removed variables) |
| `AUTOGEN_ADMIN_KEY=false`; admin key set by `bootstrap.sh` with `cake User change_authkey 1 <key>` | MISP keys are 40 characters; the image would otherwise print or rotate keys (A60) | Fresh `soc.sh init intel`: the admin key works |
| Certificate from `gen-certs.sh intel` mounted at `/etc/nginx/certs/{cert,key}.pem`, owned by uid 101 | misp-nginx doesn't generate one and serves HTTPS only when both files exist (A59) | nginx image's user id and cert paths (`/docker-entrypoint.d/01-listen.sh`, `04-ssl.sh`) |
| misp-core healthcheck: php-fpm port 9002 | php-fpm starts after the configuration script finishes (`/entrypoint_fpm.sh`) | Still true in the new `entrypoint_fpm.sh` |
| misp-nginx healthcheck via `openssl s_client` | The image has no curl/wget | `openssl` still in the image |
| MariaDB `--innodb-buffer-pool-size=${MARIADB_BUFFER_POOL}` (256M / 128M instead of 2048M) | Memory profile (A58, A63) | Other `command` flags still match upstream |
| Bootstrap API calls: `/users/view/me`, `/roles`, `/admin/users`, `/admin/users/add`, `/admin/users/edit`, `/auth_keys/add`, `/events/restSearch`, `/events/add`, `/events/publish/<id>/disable_email:1` | A60 | `bootstrap.sh intel` on a fresh instance, twice |
| Memory: limits in PROJECT.md section 8, swap capped at the limit | Measured need (D40, A63) | Re-measure the anonymous memory peak (`memory.stat`) through a start (component loading) and some API activity |
