# Cortex — "Inteligencia de amenazas" (with MISP)

Owner: Diego (@DiegoGuerraA00835430). Node: `cases` (MISP: `intel`, see `nodes/intel/misp/README.md`). Run mode: `cases-intel`.

Cortex analyzes observables with analyzers, each run as a short-lived Docker container. The full component README (contracts, export rules, backlog) is completed at the end of Phase 1; this file already covers the operations below.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `cortex` (Cortex 4.1, port 9001). Analyzer containers are started at runtime, not defined here |
| `config/application.conf` | Cortex configuration; secrets come from the environment (`${VAR}`), never from this file |
| `analyzers/` | Custom analyzers (backlog) |
| `jobs/` | Job directory shared with analyzer containers (git-ignored) |

## What bootstrap creates

`scripts/bootstrap.sh cases` (run by `soc.sh init`) creates or checks, from `nodes/cases/.env`:

| Object | Details |
|---|---|
| Elasticsearch indexes | `POST /api/maintenance/migrate` (idempotent) |
| Superadmin `CORTEX_ADMIN_USER` | Organisation `cortex`: manages organisations and users only |
| Organisation `CORTEX_ORG` (`SOC`) and its admin `CORTEX_ORGADMIN_USER` | Roles `read, analyze, orgadmin`: enables and configures analyzers (UI login `Cortex SOC` in `soc.sh info`) |
| API users `CORTEX_THEHIVE_USER`, `CORTEX_N8N_USER` | Roles `read, analyze` only; keys `CORTEX_THEHIVE_API_KEY` (C5) and `CORTEX_N8N_API_KEY` (C6) |
| Runner test | A throwaway container started through Cortex's Docker socket must share its job directory |
| MISP analyzer `MISP_2_1` | Enabled in the SOC organisation, pointing at `MISP_URL` with `MISP_CORTEX_API_KEY` (MISP's Read Only user), certificate check off (MISP is self-signed); its image is pulled. Skipped while the key is empty (`cases` mode without intel) |

## How analyzers run

- Cortex talks to the **host's** Docker daemon through the mounted `/var/run/docker.sock` (equivalent to root on the host: lab only, PROJECT.md 6.5).
- The job directory is `nodes/cases/cortex/jobs` on the host (`CORTEX_JOBS_HOST_DIR`) and `/tmp/cortex-jobs` inside Cortex; analyzer containers mount their job folder by its host path.
- Analyzer containers join `CORTEX_ANALYZER_NETWORK`: `soc-net` in single-host mode (so they reach MISP as `misp-nginx`), the default `bridge` in distributed mode (MISP through its published port). Each gets a memory limit of `CORTEX_ANALYZER_MEM` bytes (256 MiB) without swap.
- Analyzer definitions come from StrangeBee's online catalog; an analyzer's image is pulled the first time it runs (bootstrap pre-pulls the MISP analyzer's).
- **Job cache:** Cortex returns the previous report for the same observable within an analyzer's job cache (10 min for the MISP analyzer) without starting a container. Send `"force": true` in the run request to get a new job; C7 does (`scripts/contracts-check.sh --only C7`).

## Contracts and exporting changes

| Contract | Role | Status (build step) |
|---|---|---|
| C5 TheHive → Cortex | Provides the user `thehive` and its API key | Passes (1.5) |
| C6 n8n → Cortex | Provides the user `n8n` and its API key | Key exists (1.5); check in step 1.7 |
| C7 Cortex → MISP | MISP analyzer with MISP's Read Only key | Passes (1.6) |

Check: `scripts/contracts-check.sh --only C5,C7`. **Exporting changes:** enabled analyzers and their configuration live in Elasticsearch; export/import scripts in this folder are the owner's first task (PROJECT.md 11.2, 11.6). Custom analyzers go in `analyzers/` as code. Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Pinned: `thehiveproject/cortex` 4.1.0 (with Elasticsearch 8.19.21). On every version bump, re-check each item and update this list.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| Cortex runs as the host user (`CORTEX_UID:CORTEX_GID`) plus the socket's group (`DOCKER_GID`), not as root | Started as root, the image's entrypoint runs `chown cortex /var/run/docker.sock`, which changes the **host's** socket and locks the host user out of Docker (docs/decisions.md A50) | Read `/opt/cortex/entrypoint`; after a start, `ls -l /var/run/docker.sock` on the host must still show `root docker` |
| Entrypoint environment variables `es_uri`, `job_directory`, `docker_job_directory`, `no_config_secret` | The entrypoint turns them into `search.uri`, `job.directory`, `job.dockerDirectory`; `application.conf` is included last and must not set those keys | Entrypoint unchanged; a job runs (C7) |
| `docker.container.networkMode`, `docker.container.memory`, `docker.container.memorySwap` | Not in Cortex's `reference.conf` or docs; found in the 4.1.0 code (`org.thp.cortex.util.docker.DockerClient`) and verified on a real job (A49) | Run an analyzer job and inspect its container while it runs: `docker inspect -f '{{.HostConfig.NetworkMode}} {{.HostConfig.Memory}}' <id>` |
| `job.runners = [docker]` | The 4.1 default list also tries `kubernetes` and `process` | — |
| `auth.method.basic = true` | Bootstrap and checks use the admin logins over the API (plain HTTP in the lab, PROJECT.md 4.1) | — |
| Session secret from `CORTEX_SECRET` (`no_config_secret=1`) | Otherwise the entrypoint generates a random secret at every start and logs everyone out | — |
| MISP analyzer image `ghcr.io/thehive-project/misp:2` | The catalog names a moving major tag; the digest pulled at build time is in docs/decisions.md (Pinned images) | C7 passes after `docker pull` of the new image |
| Catalog URL: the entrypoint's default `https://catalogs.download.strangebee.com/latest/json/analyzers.json` | "latest" catalog: analyzer definitions and image tags can change without a Cortex upgrade | The enabled analyzers still exist under the same name/version |
| Memory: `CORTEX_MEM` 600m / 500m, swap capped at the limit | Measured need (PROJECT.md D40) | Re-measure the anonymous memory peak (`memory.stat`) |
