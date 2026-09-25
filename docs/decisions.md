# Implementation decisions

Choices made while building Phase 1: pinned versions and resolved **[ASSUMPTION]** / **[OPEN]** items. Design decisions (D1–D26) are in `PROJECT.md` section 15.

## Pinned images (step 1.0)

Checked against the registries and the upstream reference deployments on 2026-09-25. The tags are also in each node's `.env.example`, which is where compose reads them from.

| Node | Image | Tag | Source / reason |
|---|---|---|---|
| core | `wazuh/wazuh-manager` | `4.14.8` | Latest 4.x; `wazuh-docker` v4.14.8 single-node. 5.0 is still beta. |
| core | `wazuh/wazuh-indexer` | `4.14.8` | Same release as the manager |
| core | `wazuh/wazuh-certs-generator` | `0.0.4` | Version used by `wazuh-docker` v4.14.8 (`CERT_TOOL_VERSION=4.14`) |
| core | `n8nio/n8n` | `2.40.7` | Current `stable` tag |
| core | `postgres` (profile `pg`, off by default) | `16.15-alpine` | Optional n8n database |
| core | `grafana/grafana` | `13.2.2` | Current `latest` |
| core | Grafana plugin `grafana-opensearch-datasource` | `2.34.4` | Latest; requires Grafana >= 10.4 |
| cases | `strangebee/thehive` | `5.7.6` | StrangeBee reference (`StrangeBeeCorp/docker` `versions.env`) |
| cases | `thehiveproject/cortex` | `4.1.0` | StrangeBee reference; see A1 |
| cases | `cassandra` | `4.1.12` | StrangeBee reference |
| cases | `docker.elastic.co/elasticsearch/elasticsearch` | `8.19.21` | StrangeBee reference; Cortex 4 requires ES 8 |
| intel | `ghcr.io/misp/misp-docker/misp-core` | `v2.5.47` | `misp-docker` `template.env` (`CORE_TAG`) |
| intel | `ghcr.io/misp/misp-docker/misp-nginx` | `v2.5.47` | Same release as misp-core; see A2 |
| intel | `ghcr.io/misp/misp-docker/misp-modules` | `v3.0.10` | `misp-docker` `template.env` (`MODULES_TAG`) |
| intel | `mariadb` | `10.11.19` | `misp-docker` uses `mariadb:10.11`; latest patch |
| intel | `valkey/valkey` (service `redis`) | `7.2.14` | `misp-docker` uses `valkey/valkey:7.2`; latest patch |
| lab | `ubuntu` (agent base image) | `noble-20260911` | Dated Ubuntu 24.04 tag, since `24.04` moves |
| lab | Wazuh agent package | `4.14.8` | Must match the manager |

Tooling images (not part of the stack):

| Used by | Image | Tag |
|---|---|---|
| `ci-checks.sh` shellcheck | `koalaman/shellcheck` | `v0.11.0` |
| `ci-checks.sh` secret scan | `zricethezav/gitleaks` | `v8.30.1` |
| `ci-checks.sh` JSON/XML validation | `python` | `3.14.7-slim` |
| `soc.sh reset` (deleting root-owned files) | `alpine` | `3.24.2` |
| GitHub Actions | `actions/checkout` | `v7` |

## Resolved items

| # | Step | Item | Decision |
|---|---|---|---|
| A1 | 1.0 | Cortex version (spec says 3.x) | **Cortex 4.1.0 with Elasticsearch 8.19.21**, approved by the integrator. Cortex 3.2.1 (last 3.x) only supports Elasticsearch 7.x, which is end of life; Cortex 4.0+ supports only ES 8. This matches StrangeBee's current reference pairing (TheHive 5.7.6 + Cortex 4.1.0). TheHive 5.8.0 exists but is not yet in the reference, so 5.7.6 is used. Verified against the Cortex 4.1.0 source: the Docker job runner is still supported (default runners `[kubernetes, docker, process]`), and the image's entrypoint maps the env vars `job_directory` / `docker_job_directory` to `job.directory` / `job.dockerDirectory`. Recorded as D27 in PROJECT.md. |
| A2 | 1.0 | MISP layout | Current `misp-docker` serves HTTPS from a separate `misp-nginx` container (port 8443) in front of `misp-core`. The intel node therefore also runs `misp-nginx`, and `MISP_URL` points to it (`https://misp-nginx:8443` in single-host mode, `https://<INTEL_HOST>:9443` in distributed mode). Adds ~0.1 GB; section 8's table and D28 in PROJECT.md updated. |
| A3 | 1.0 | Container memory limits | `mem_limit` values equal the RAM estimates in section 8 (e.g. `grafana` 200m / 100m). They are tuned in step 1.7 from the `mem-report.sh` measurements. |
| A4 | 1.0 | How `.env` files are produced | `render-env.sh` renders `nodes/<node>/.env` from `.env.example` + `topology.env`. In `.env.example`, `__secret__` means "generate a random secret once and keep it", `__bootstrap__` means "filled by `bootstrap.sh`, then kept". Topology-derived keys are recomputed every run; everything else (image tags) is copied from `.env.example`, so a version bump reaches existing machines with a re-render. Unknown keys in an existing `.env` are kept with a warning. `.env` is written with mode 600. |
| A5 | 1.0 | Secret format | 32 characters: letters (upper and lower), digits and one `-`. Satisfies the Wazuh password policy and needs no quoting in `.env`, YAML or URLs. |
| A6 | 1.0 | Lab node configuration | `nodes/lab/.env.example` added (not in section 12's tree): the lab node needs its own `SOC_INSTANCE`, `WAZUH_MANAGER_ADDR` and memory limit to be runnable on its own. |
| A7 | 1.0 | Mode vs node names in `soc.sh` | Arguments are run modes (section 8.1) or node names. `core` is both; it means the mode (core + lab). `cases` is the same either way; `intel` and `lab` are node names. |
| A8 | 1.0 | Non-interactive reset | `soc.sh reset <nodes> --yes` skips the confirmation prompt, for the backup round trip (step 1.8) and the fresh-clone test (step 1.9). |
| A9 | 1.0 | Extra scripts | `scripts/lib/common.sh` (shared helpers) and `scripts/ci-checks.sh` (the CI checks of section 11.5, run the same way locally and in GitHub Actions through pinned Docker images, on a snapshot of the non-ignored files so local secrets are never scanned). Neither is in section 12's tree; both are integrator-owned. |
| A10 | 1.0 | `preflight.sh` thresholds | RAM: >= 9 GiB for `standard`, >= 5.5 GiB for `low` (what WSL reports for `memory=10GB` / `6GB`). Disk: fail below 20 GiB free, warn below 60 GiB. A required port counts as free if a container of this `SOC_INSTANCE` already holds it, so `init` stays idempotent. |
| A11 | 1.0 | `WAZUH_INDEXER_URL` | Always `https://wazuh-indexer:9200`: the indexer is internal to `core` and never published (section 3.1). |
| A12 | 1.0 | Startup | `soc.sh init` / `up` use `docker compose up --wait` (timeout 900 s, override with `SOC_UP_TIMEOUT`), so bootstrap only runs once services are healthy. Nodes with no services yet are skipped. Helper scripts added in later steps (`gen-certs.sh`, `bootstrap.sh`, `healthcheck.sh`) are skipped with a `SKIP` line until they exist. |
| A13 | 1.0 | Windows 10 fallback | `netsh portproxy` forwards TCP only, so syslog on 514/udp isn't reachable from the LAN on Windows 10 machines; use syslog over TCP there, or Windows 11 mirrored networking. |
| A14 | 1.0 | `soc.sh info` credential variables | UI logins are read from these `.env` keys, which later steps must use: `GRAFANA_ADMIN_USER`/`_PASSWORD`, `N8N_OWNER_EMAIL`/`N8N_OWNER_PASSWORD`, `WAZUH_API_ADMIN_USER`/`_PASSWORD`, `THEHIVE_ADMIN_USER`/`_PASSWORD`, `CORTEX_ADMIN_USER`/`_PASSWORD`, `MISP_ADMIN_EMAIL`/`MISP_ADMIN_PASSWORD`. |
| A15 | 1.1 | Indexer certificate name | The official certificate tool only accepts dotted DNS names, so the indexer certificate is issued for `wazuh.indexer` (CN `wazuh-indexer`) and the `wazuh-indexer` service carries the network alias `wazuh.indexer`, as in `wazuh-docker`. `WAZUH_INDEXER_URL` is therefore `https://wazuh.indexer:9200`; clients that verify the certificate (Filebeat, Grafana in C8) must use that name. |
| A16 | 1.1 | Indexer admin password | `gen-certs.sh` also writes `nodes/core/certs/internal_users.yml` (git-ignored) with the bcrypt hash of `INDEXER_ADMIN_PASSWORD`, hashed with the indexer image's own tool. It contains only `admin` (the demo users are dropped) and is loaded into the security index on the first start only; changing the password afterwards needs `securityadmin.sh` (or `soc.sh reset core`). The certificate tool itself is downloaded from `packages.wazuh.com` by the generator image at generation time (D6). |
| A17 | 1.1 | Wazuh API administrator | `wazuh-wui` with a generated password (`WAZUH_API_ADMIN_USER` / `_PASSWORD`), set by the manager image, which disables the other default user (`wazuh`/`wazuh`). Verified: the default credentials are rejected. |
| A18 | 1.1 | `n8n-api` read-only role (C2) | Role `n8n-api-readonly` linked to Wazuh's built-in read-only policies: `agents_read_agents`, `agents_read_groups`, `rules_read_rules`, `decoders_read_decoders`, `lists_read_rules`, `mitre_read_mitre`, `syscheck_read_syscheck`, `syscollector_read_syscollector`, `sca_read_sca`, `rootcheck_read_rootcheck`, `ciscat_read_ciscat`, `cluster_read_resourceless`. Wazuh rejects custom policies identical to built-in ones, so none are created. Verified: listing agents and rules works; active response, manager restart and user creation return 403. "Alerts" are not a Wazuh API resource (they live in the indexer). |
| A19 | 1.1 | `grafana-ro` indexer role (C8) | Role `asox_grafana_ro`: cluster `cluster_composite_ops_ro`; on `wazuh-alerts-*` only: `read`, `indices:admin/mappings/get`, `indices:admin/resolve/index`. Created (or updated) through the security REST API by `bootstrap.sh`. Verified: it can count alerts and gets 403 on other indices. |
| A20 | 1.1 | Syslog and enrollment exposure | The syslog listener (514/udp) accepts any source (`allowed-ips 0.0.0.0/0`) and agent enrollment needs no password (the `wazuh-docker` default). Acceptable in the lab since single-host mode binds to `127.0.0.1`; tightening both is Wazuh-owner backlog before exposing `core` on a LAN. |
| A21 | 1.1 | How Wazuh config reaches the manager | `ossec.conf`, `rules/` and `decoders/` are mounted under `/wazuh-config-mount`, which the image copies into `/var/ossec` at every start: edit, then restart the manager. Deleting a file from the repo does not delete the copy already in the `wazuh_etc` volume. |
| A22 | 1.1 | `wazuh-query.sh` access | Runs `curl` inside the `wazuh-indexer` container (the indexer is not published) as the read-only `grafana-ro` user. Exit code 0 when alerts match, 1 when none, 2 on errors, so other scripts can use it. |
| A23 | 1.1 | Test rule | Rule `100100`, level 10 (above the C1 threshold of 7), matches the marker `ASOX_TEST_EVENT` in any event. Besides the lab agent (step 1.2), it can be fired through syslog: `echo "<13>$(date '+%b %e %T') host asox-test: ASOX_TEST_EVENT id=x" \| nc -u -w1 127.0.0.1 514`. |
| A24 | 1.1 | Indexer healthcheck | Uses the admin client certificate instead of a password, so no credentials are in the indexer's environment (and no false positive in the secret scan). |
