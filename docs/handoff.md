# Session handoff

Read after PROJECT.md, before starting work (CLAUDE.md). Update at the end of each session.

## Current state (2026-09-26)

- **Step 1.8 done** (PROJECT.md section 17, docs/decisions.md A71, A72). **Next: step 1.9** (component READMEs + `CONTRIBUTING.md`, fresh-clone test, then tag `v1.0-baseline` and owner branches locally; the integrator pushes).
- **Running: `full`** in `single` / `standard` (WSL 16 GB), healthcheck green. `topology.env` is back to `DEPLOY_MODE=single` (hosts back to the example values); every published port is on `127.0.0.1`.
- **Backups on disk (git-ignored):** `backups/cases-20260926-152640/` (with secrets; the TheHive instance still on its trial, the one to keep until the license is activated) and `backups/intel-20260926-152438/` (with secrets; test). Both contain credentials.
- **Testing budget (integrator, 2026-09-26):** memory measurements = startup peak + 5 min steady state per mode, longer only if still rising. Re-run a full reset+init or the whole contract suite only when a change touches that area; otherwise only the relevant checks. The fresh-clone test (1.9) stays as planned.
- The integrator reviews after each step; approved so far: Cortex 4.1 + ES 8 (D27), Grafana 12.4 (D34), n8n memory (D38, revised by D40), D39 as revised in 1.5, D40, D41, D42, D43.
- **Owners** (PROJECT.md section 3, 11.1): Wazuh Daniel (@dmelgar1110), n8n Inigo (@poinsot, also the integrator, on the 32 GB machine), Grafana Jesus (@JC-535), TheHive Park (@Jinhyuk-P), Cortex + MISP Diego (@DiegoGuerraA00835430). The integrator adds collaborators at step 1.9.
- **TheHive trial of the build instance ends 2026-10-11.** The integrator is requesting a Community license. Until it's activated, don't `soc.sh reset cases` without restoring afterwards (D41). **Once activated: `scripts/backup.sh cases --with-secrets`**, and check C4 still passes (webhooks need the capability `notification.webhook`; `healthcheck.sh` warns if it's missing, A64).

## Step 1.8 results (A71, A72)

- **Distribution simulation:** all hosts = 192.168.1.64 (mirrored LAN IP); C1–C8 and `healthcheck.sh --cross-node` pass through published ports; `soc-net` empty. Needed after switching mode either way: `render-env.sh`, `gen-certs.sh --force intel`, `soc.sh down` + `up`, `bootstrap.sh cases` (webhook URL, MISP analyzer URL) and `bootstrap.sh core` (n8n credential URLs).
- **Windows firewall:** WSL's Hyper-V firewall has default inbound **Block** and no ASOX rules exist; the simulation didn't need them (traffic stays in the VM). A second computer would need, in an Administrator PowerShell: `powershell -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu-24.04\home\poinsot\asox-soc\windows\firewall-rules.ps1` (check the distro name with `wsl -l`).
- **Backups:** `backup.sh cases --with-secrets` ~1 min, 9 MB; `restore.sh cases` ~1 min, same TheHive instance and license, no re-bootstrap needed with secrets. `intel` ~0.6 GB; `core` would be large (Wazuh's vulnerability feed ~9.5 GB in `wazuh_queue`). Restores of core, intel and lab were not run.

## Pending notes for later steps

- **Step 1.9:** component READMEs (Wazuh, n8n, Grafana, TheHive, Cortex, MISP) have owner, run mode, contracts with status, export notes and "Local patches and deprecations" lists; complete them with backlogs (11.3), update contract statuses after 1.7, and keep the patches list in every README. `CONTRIBUTING.md` gets 11.6 (including the 8 GB / VS Code note). The fresh-clone test (`SOC_INSTANCE=fresh`) gets its own TheHive trial; stop the build instance first (`soc.sh down`), and restart it afterwards.
- After `soc.sh reset intel`, cases needs `render-env.sh` + `bootstrap.sh cases` (new MISP key, A61). After `soc.sh reset cases` or `restore.sh cases` **without** secrets: `render-env.sh` + `bootstrap.sh core` and `bootstrap.sh cases` (C4 rules take up to 5 min to apply).

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
- **Backups:** `restore.sh` renders before starting and uses `compose create` so volumes carry Compose's labels. Tar runs in `ubuntu:noble-20260911` (GNU tar, `--numeric-owner`); MISP's certificate key is owned by uid 101 (mode 400), so certs are archived from a container too.
- **Windows side from WSL:** read-only PowerShell works through interop (`powershell.exe -NoProfile -Command ...`, from a Windows-visible cwd such as `/mnt/c`); anything that changes Windows (firewall rules) is the integrator's, as Administrator.
