# Session handoff

Read after PROJECT.md, before starting work (CLAUDE.md). Update at the end of each session.

## Current state (2026-09-25)

- **Last completed step: 1.6** (`intel` node, MISP, C7). Commits this session: `a299289` step 1.5 (cases node), `a43ebd2` TheHive license handling (D41, A57), `6b1b9d2` step 1.6, then "docs: post-1.6 wrap-up and handoff". Next: **step 1.7**, in two parts (below).
- **Running: nothing.** All nodes are stopped (`soc.sh down`); volumes, images, certificates and `.env` files are kept. Restart with `scripts/soc.sh up full` (standard profile, single-host, instance `asox`). Last results in `full`: C1, C2, C5, C7, C8 pass; C3, C4, C6 report SKIP (1.7).
- The integrator reviews after each step; approved so far: Cortex 4.1 + ES 8 (D27), Grafana 12.4 (D34), n8n memory (D38, revised by D40), D39 as revised in 1.5 (`core`, `cases`, `cases-intel` must fit 6 GB on `low`; `core-cases`/`full` best effort), D40 (limits from measured anon need, swap capped), D41 (each person requests and activates their own TheHive Community license).
- **Owners** (PROJECT.md section 3, 11.1): Wazuh Daniel (@dmelgar1110), n8n Inigo (@poinsot, also the integrator, on the 32 GB machine), Grafana Jesus (@JC-535), TheHive Park (@Jinhyuk-P), Cortex + MISP Diego (@DiegoGuerraA00835430). The integrator adds collaborators at step 1.9.
- **TheHive trial of the build instance ends 2026-10-11.** The integrator is requesting a Community license. Until it's activated, don't `soc.sh reset cases` (new instance, license lost, D41); once activated, back up `cases` with `--with-secrets` as soon as `backup.sh` exists (1.8). `soc.sh info cases` shows the license state.

## Step 1.7 plan: two parts

The low-profile check needs `.wslconfig` changed and WSL restarted, which ends the Claude Code session, so 1.7 is split.

**Part 1 (`standard`, current `.wslconfig`: memory=16GB, swap=4GB)**
1. n8n credentials for TheHive and Cortex (C3, C6): add to `n8n_credentials_json` in `scripts/bootstrap.sh` with fixed 16-char IDs. Keys `THEHIVE_N8N_API_KEY` and `CORTEX_N8N_API_KEY` come from the cases `.env` via `__from:cases__` in the core `.env.example` (the bootstrap order intel → cases → core with a render before each already delivers them, A62). n8n's TheHive user is a **Service** account: `Authorization: Bearer <key>`.
2. TheHive webhook (C4, D36, A41): to `${N8N_WEBHOOK_URL}/webhook/thehive-event` with header `X-ASOX-Token: ${N8N_WEBHOOK_TOKEN}`; the cases `.env` gets the token with `N8N_WEBHOOK_TOKEN=__from:core__`. **Fallback:** if TheHive 5 can only send an `Authorization` header, add a second Header Auth credential (header `Authorization`, value e.g. `Bearer <token>`) in `bootstrap.sh`, use it on `recv-thehive-event`'s webhook node, and re-export the workflow. Check that webhooks (notifications) work under the license (A53). Extend C4's check: requests without/with a wrong token get 401/403 (as `check_C1`); creating the C3 test alert produces a `recv-thehive-event` execution.
3. `scripts/healthcheck.sh` (PROJECT.md 14.1): per node container health, UIs/APIs, indexer and Elasticsearch cluster status, Cassandra/MariaDB/Redis; Cortex socket + job dir + MISP analyzer image (reuse `cortex_test_container`); **TheHive license via `thehive_license_check`** (WARN only); `--cross-node`. `soc.sh init` already calls it when present.
4. `scripts/mem-report.sh`: the D40 method (per container anon/file from `memory.stat`, peak, limit, OOM kills, swap), plus node/mode totals; output saved in `docs/`.
5. Complete `contracts-check.sh` (C3, C4, C6; no more SKIP).
6. Document the `__from:<node>__` `.env.example` marker in PROJECT.md section 4, including the manual copy in distributed mode (value pasted from the source machine's `.env`; `render-env.sh` warns while empty, only in distributed mode, A62).
7. Pass C1–C8 in `full` on `standard` with `healthcheck.sh` all green; save the standard memory report in `docs/`; update the handoff; commit; stop everything; **tell the integrator to change `%UserProfile%\.wslconfig` to `memory=6GB`, `swap=8GB`, then `wsl --shutdown` and restart.**

**Part 2 (after the integrator restarts WSL with memory=6GB, swap=8GB)**
1. Check `free -h` shows ~6 GB RAM / 8 GB swap. Set `MEM_PROFILE=low` in `topology.env`, run `scripts/render-env.sh`.
2. D39 checks, each dev mode started alone (`soc.sh down` the others): `core`, `cases`, `cases-intel`: healthchecks green, relevant contracts pass (core: C1, C2, C8; cases: C5; cases-intel: C5, C7), no OOM kills, fits the 6 GB allocation (measured usage, not the sum of limits). `core-cases` and `full` on `low` are best effort (record the result).
3. Save the low memory reports in `docs/`; update section 17 (1.7 done) and the handoff; commit.
4. **Remind the integrator to restore `.wslconfig` to `memory=16GB`, `swap=4GB`** (then `wsl --shutdown`), and set `MEM_PROFILE=standard` back in `topology.env`.

## Pending notes for later steps

- **Step 1.8 (backups):** `backup.sh intel --with-secrets` must include `nodes/intel/certs/` (like core's certs). `restore.sh cases` must bring back TheHive's license (compare the `soc.sh info cases` line before/after). After `soc.sh reset intel`, cases needs `render-env.sh` + `bootstrap.sh cases` (new MISP key, A61). Distribution simulation: C7 goes through `https://<INTEL_HOST>:9443` from the `bridge` network (A49); regenerate MISP's certificate for the new host (`gen-certs.sh --force intel`, A59); the TheHive and Cortex APIs are reached at `CASES_HOST` (contracts-check already switches, A55).
- **Step 1.9:** component READMEs (Wazuh, n8n, Grafana, TheHive, Cortex, MISP) have owner, run mode, contracts with status, export notes and "Local patches and deprecations" lists; complete them with backlogs (11.3), update contract statuses after 1.7, and keep the patches list in every README. The fresh-clone test (`SOC_INSTANCE=fresh`) gets its own TheHive trial.

## Gotchas learned

- **Memory limits (D40, A56, A63):** size from the anon peak in the cgroup's `memory.stat` (`/sys/fs/cgroup/system.slice/docker-<id>.scope/`) through start + bootstrap + activity + idle; limit = anon peak × 1.15 + 64 MiB, rounded up to 50 MiB. `docker stats`/`memory.peak` include page cache (the Wazuh manager and misp-core hold ~350–450 MiB of reclaimable cache and sit near their limit harmlessly). `memswap_limit` = `mem_limit` everywhere, so undersized limits show as OOM kills or Java/Node "out of memory", not silent swap. Elasticsearch 8 and TheHive use ~0.5–1 GB beyond their heap. n8n needs an explicit Node heap (`N8N_HEAP`, 320 MB minimum on `low`). When sampling across a reset, drop samples from before the recreate.
- **Cortex analyzers and MISP (A49):** analyzer containers join `CORTEX_ANALYZER_NETWORK` (`soc-net` single, `bridge` distributed) through `docker.container.networkMode`, which is in Cortex's code but not its docs; no D16 exception needed.
- **Cortex must not run as root (A50):** its entrypoint chowns the (host's) Docker socket; it runs as the host user plus the socket's group.
- **Cortex result cache (A61):** within an analyzer's job cache (10 min for MISP) Cortex returns the previous job without starting a container; C7 sends `force: true`.
- **Bootstrap order (A62):** `soc.sh init` bootstraps intel → cases → core → lab with a render before each, so `__from:` values arrive in one init; after resetting a provider node, re-render and bootstrap its consumers.
- **TheHive:** 14-day trial, then read-only; license bound to the instance ID in Cassandra (D41, A57). Connector config via `PUT /api/v1/admin/config/cortex` needs `statusCheckInterval`, `refreshDelay`, `maxRetryOnError`; server status in `GET /api/v1/status` → `.connectors.cortex`, license in `.license`. User type (Normal/Service) can't be changed after creation.
- **MISP:** API keys are 40 alphanumeric characters (not our secret format); misp-nginx needs a mounted certificate (`gen-certs.sh intel`); first start ~2 min; misp-core peaks while loading galaxies/taxonomies at every start.
- **Healthchecks must mean "ready":** Wazuh manager API + daemons (A27), lab agent post-enrollment reload (A31), cases `cqlsh`/cluster health/`/api/status` (A51), misp-core php-fpm port (starts after configuration), misp-nginx an HTTPS request (A58).
- **Wazuh manager restart:** "0-wazuh-init: exited 1" on `docker restart` is expected; `05-restart-fixes.sh` redoes the config copy (A26). Deleted config files stay in the volume.
- **Re-enrollment:** a fresh agent with an existing name is refused; `soc.sh reset lab` removes the old registration (A30).
- **Wazuh API RBAC:** changes revoke tokens issued in the same second (retry, A18); custom policies identical to built-ins are rejected. **Certs:** the indexer is `wazuh.indexer` (D32).
- **n8n:** UI login rate-limited → scripts use `N8N_API_KEY`. CLI import in a one-off container; activation via API (A44). Never put secrets in n8n's environment (D37).
- **Grafana:** daily index pattern for the plugin health check (D35); only the pinned plugin via `GF_INSTALL_PLUGINS` (A35).
- **Secret scan:** gitleaks flags literal credentials in `curl -u` / `-H`; use variables.
- **Shell:** the harness blocks leading `sleep N` (use `timeout N bash -c 'until ...; do sleep 3; done'`); background samplers need a tracked background task (`nohup &` dies with the shell); `pkill -f` can match its own shell.
- **Local CI:** `scripts/ci-checks.sh all` before each commit.
