# Session handoff

Read after PROJECT.md, before starting work (CLAUDE.md). Update at the end of each session.

## Current state (2026-09-26)

- **Step 1.7 done** (Part 1 `standard`, Part 2 `low`; see PROJECT.md section 17 and docs/decisions.md A70). **Next: step 1.8** (distribution simulation, `backup.sh` / `restore.sh`).
- **Before 1.8, the integrator restores `.wslconfig` to `memory=16GB`, `swap=4GB`** (then `wsl --shutdown`), and `topology.env` goes back to `MEM_PROFILE=standard` + `scripts/render-env.sh` (it is still `low`, matching the current 6 GB VM).
- **Running: nothing.** All nodes stopped (`soc.sh down`); volumes, images, certificates and `.env` files kept. The containers were last created with the `low` limits: the next `soc.sh up` after re-rendering with `standard` recreates them.
- **Testing budget (integrator, 2026-09-26):** memory measurements = startup peak + 5 min steady state per mode (`mem-report.sh --sample` ≈ init time + 300 s), longer only if a value is still rising. Re-run a full reset+init or the whole contract suite only when a change touches that area; otherwise only the relevant checks. The fresh-clone test (1.9) and the backup round trip (1.8) stay as planned.
- The integrator reviews after each step; approved so far: Cortex 4.1 + ES 8 (D27), Grafana 12.4 (D34), n8n memory (D38, revised by D40), D39 as revised in 1.5, D40, D41, D42, D43.
- **Owners** (PROJECT.md section 3, 11.1): Wazuh Daniel (@dmelgar1110), n8n Inigo (@poinsot, also the integrator, on the 32 GB machine), Grafana Jesus (@JC-535), TheHive Park (@Jinhyuk-P), Cortex + MISP Diego (@DiegoGuerraA00835430). The integrator adds collaborators at step 1.9.
- **TheHive trial of the build instance ends 2026-10-11.** The integrator is requesting a Community license. Until it's activated, don't `soc.sh reset cases` (new instance, license lost, D41); once activated, back up `cases` with `--with-secrets` as soon as `backup.sh` exists (1.8). `soc.sh info cases` shows the license state. **Once the license is active, check C4 still passes** (webhooks need the capability `notification.webhook`; `healthcheck.sh` warns if it's missing, A64).

## Step 1.7 results on `low` (A70)

- 6 GB WSL VM: `core`, `cases`, `cases-intel` each fit (VM peaks ~3.1 / ~4.6 / ~5.3 GB including Claude Code ~0.4 GB and VS Code ~0.6 GB); their contracts pass; no OOM kills. `core-cases` passes near the limit. **`full` on `low` stalled the VM** (the first Part 2 session hung there): never start it on a 6 GB VM.
- Low limits raised: grafana 250m, cortex 550m, wazuh-indexer 1150m.

## What Part 1 built (step 1.7)

- n8n credentials "TheHive API (n8n)" / "Cortex API (n8n)" (keys via `__from:cases__` in the core `.env`) and "ASOX webhook token (Bearer)"; check workflows `chk-thehive-api` (C3) and `chk-cortex-api` (C6). n8n now joins `soc-net` (it didn't before, so it couldn't reach cases).
- TheHive webhook (C4): global endpoint `n8n` (bearer auth = the token) + SOC notification rule "n8n (C4)" (AnyEvent), written by `bootstrap.sh cases` (A64, A65). TheHive webhooks can't send custom headers, and `application.conf` notification defaults are ignored (only stored org config counts).
- `healthcheck.sh` (A67), `mem-report.sh` (A68), `contracts-check.sh` complete (no more SKIP).
- PROJECT.md section 4 documents `__from:<node>__` (incl. the manual copy in distributed mode).

## Pending notes for later steps

- **Step 1.8 (backups):** `backup.sh intel --with-secrets` must include `nodes/intel/certs/` (like core's certs). `restore.sh cases` must bring back TheHive's license (compare the `soc.sh info cases` line before/after). After `soc.sh reset intel`, cases needs `render-env.sh` + `bootstrap.sh cases` (new MISP key, A61). Likewise after `soc.sh reset cases` or `restore.sh cases` without secrets: `render-env.sh` + `bootstrap.sh core` (new TheHive/Cortex keys for n8n, `__from:cases__`), and C4 needs `bootstrap.sh cases` (endpoint + rule; rules take up to 5 min to apply). In the distribution simulation the webhook URL becomes `http://<CORE_HOST>:5678/...` (re-run `bootstrap.sh cases` after `render-env.sh`), and `healthcheck.sh --cross-node` checks n8n → TheHive/Cortex, TheHive → n8n and analyzers → MISP through the published ports. Distribution simulation: C7 goes through `https://<INTEL_HOST>:9443` from the `bridge` network (A49); regenerate MISP's certificate for the new host (`gen-certs.sh --force intel`, A59); the TheHive and Cortex APIs are reached at `CASES_HOST` (contracts-check already switches, A55).
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
- **`ps` in a pipe truncates `cgroup`** unless given a width (`cgroup:256`); `soc.sh down` removes containers, so exit codes / `memory.events` are gone afterwards: look for OOM kills in `journalctl -b -1 -k` instead. Don't edit a script while a background run of it is still going (bash reads it as it runs).
- **TheHive notifications (A64):** rules live in the organisation's stored config (only an org-admin of SOC can write them: `bootstrap@asox.local`, key revoked after each run); `application.conf` defaults are ignored; changes take up to 5 min (cache). Webhook endpoints ignore `headers`: only `auth` (bearer) is sent.
- **n8n executions store webhook request headers**, including the webhook token; executions are visible to the n8n owner only (lab; same as C1).
