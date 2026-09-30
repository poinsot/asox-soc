# Session handoff

Read after PROJECT.md, before starting work (CLAUDE.md). Update at the end of each session.

## Current state (2026-09-30): component development

- **Team onboarded:** all five owners' `BACKLOG.md` files are merged on `main` (PRs #1–#5). The integrator compared them in `docs/integration-backlog.md` (the cross-component register: X-nn items, R-nn requests to the integrator, section F dates, section G follow-ups each owner makes in their own folder).
- **Contracts decided 2026-09-30, audited the same day** (PROJECT.md 5 and D44–D49): C9 separate Wazuh user `n8n-response`, built-in AR commands only (Phase 2); C10 n8n → MISP warninglist check (after R-14's size cap); C11 `asox-metrics` in the Wazuh indexer, written by n8n as `n8n-indexer`, read by `grafana-ro`; C12 rejected; C13 "seen before in Wazuh?" = Cortex analyzer → n8n webhook `wazuh-lookup` (own token `N8N_LOOKUP_TOKEN`) → indexer (the first version, a Wazuh API credential in Cortex, couldn't reach alert data: the API has none and the indexer isn't reachable from `cases`); C14 MISP → Wazuh CDB lists proposed, design due 2026-10-16. D49: Suricata replaces Snort (sensor in the `lab` node for now). Owner decisions D-N1–N6 and D-G1–G4 are at the end of `docs/decisions.md`. None of C9–C14 is built; their checks aren't in `contracts-check.sh` yet.
- **Waiting on owners:** acknowledgements of C9 (Wazuh), C11 (Grafana, Wazuh), C13 (Cortex + MISP, Wazuh); C12's rejection to be told to TheHive and Wazuh; dates from Grafana and Cortex + MISP; the section G edits in their own folders (other owners' files were deliberately not edited on `main`, to avoid merge conflicts with their branches).
- **Integrator's next shared-file work** (register section E): R-06 (syslog allowed IPs, needed by 2026-10-09), R-16 (indexer user `n8n-indexer`, first piece of C11/C13), R-11, R-13 (after R-14), R-15 (after R-10), R-07 (Suricata memory).
- **Deadlines:** build instance TheHive trial **2026-10-11**; C14 design 2026-10-16; checkpoint 1 **2026-10-20**; feature freeze 2026-11-24; delivery 2026-12-01.

## State at the end of Phase 1 (2026-09-26)

- **Phase 1 complete and pushed: steps 1.0–1.9 done** (PROJECT.md section 17; docs/decisions.md up to A75). The integrator pushed `main`, tag `v1.0-baseline` (at 67016c1) and the owner branches `wazuh`, `n8n`, `thehive`, `grafana`, `cortex-misp` to `github.com/poinsot/asox-soc`; CI is green on `main` and every branch.
- **Docs review before onboarding (2026-09-26):** fixes committed on `main` as "docs: review fixes before onboarding" (clone URL, PR steps, `git pull --no-rebase --no-edit origin main`, CHECKLIST setup steps, branch/URL/license notes in the component READMEs, clean `--help` via `print_usage` in `scripts/lib/common.sh`). The five owner branches were fast-forwarded to that commit locally; the tag stays at the baseline. **Next (integrator):** push `main` and the five branches (normal pushes, no force), then invite the teammates as collaborators; component work starts from CONTRIBUTING.md.
- **Running: `full`** in `single` / `standard` (WSL 16 GB), healthcheck green, ports on `127.0.0.1`.
- **Backups on disk (git-ignored, contain credentials except core's):** `backups/cases-20260926-152640/` (with secrets; the TheHive trial instance, keep it until the license is activated), `backups/intel-20260926-152438/` (with secrets), `backups/core-20260926-153828/` (no secrets, 1.1 GB, made to measure the size).
- **Still open (integrator):** ~~invite collaborators~~ (done; owners have merged PRs); **TheHive trial of the build instance ends 2026-10-11.** Once the Community license is activated: `scripts/backup.sh cases --with-secrets`, and check C4 still passes (webhooks need the capability `notification.webhook`; `healthcheck.sh` warns if it's missing, A64). Until then, don't `soc.sh reset cases` without restoring afterwards (D41).
- **Testing budget (integrator, 2026-09-26):** memory measurements = startup peak + 5 min steady state per mode, longer only if still rising. Re-run a full reset+init or the whole contract suite only when a change touches that area; otherwise only the relevant checks.
- The integrator reviews after each step; approved so far: Cortex 4.1 + ES 8 (D27), Grafana 12.4 (D34), n8n memory (D38, revised by D40), D39 as revised in 1.5, D40, D41, D42, D43. A73 (the `__from:` fix in `render-env.sh`) reviewed and approved.
- **Owners** (PROJECT.md section 3, 11.1; CONTRIBUTING.md): Wazuh Daniel (@dmelgar1110), n8n Inigo (@poinsot, also the integrator, on the 32 GB machine), Grafana Jesus (@JC-535), TheHive Park (@Jinhyuk-P), Cortex + MISP Diego (@DiegoGuerraA00835430).

## Step 1.9 results (A73–A75)

- **1.8 follow-ups:** the `__from:` manual copy was checked on a cases-only copy of the repo with distinct hosts. It found a bug, now fixed (A73): `render-env.sh` renders every node's `.env`, so on a cases machine it had created a core `.env` with its own `N8N_WEBHOOK_TOKEN` and copied it over the pasted one. Now a local source `.env` is only read in single-host mode or when `topology.env` gives both nodes the same host (lab = `CORE_HOST`). PROJECT.md 14.3 lists what the single-machine simulation doesn't cover.
- **Disk (A74):** images core 8.5 / cases 5.6 / intel 4.6 / lab 0.3 GB; volumes core 10.2 GB (Wazuh vulnerability feed 9.5 GB) / intel 1.9 / cases 0.1 GB; per mode ~19 / 6 / 12 / 25 / 31 GB (core / cases / cases-intel / core-cases / full). `backup.sh core` 1.1 GB in under 3 min.
- **Fresh-clone test (A75):** `init full` with `SOC_INSTANCE=fresh` green in ~7 min; C1–C8 pass; fresh instance reset and deleted; build instance restarted.

## Integrator backlog

- **Exclude the re-downloadable Wazuh vulnerability feed** (`wazuh_queue` → `queue/vd/feed`, ~9.5 GB, possibly `queue/vd_updater` with it) **from core backups**, then test a core restore: the manager must re-download the feed on its own (A72, A74). Today core backups are ~1.1 GB, so this saves time and space, not correctness.
- Restores of `core`, `intel` and `lab` haven't been run (only `cases`, A72).
- Windows Firewall: `windows/firewall-rules.ps1` hasn't been run on any machine; a real multi-host deployment (e.g. the shared instance) needs it on each hosting machine (A71), plus the manual `__from:` copies (PROJECT.md section 4).
- `COMPOSE_PROFILES=pg` for n8n's optional Postgres isn't managed by `soc.sh` (n8n README).
- Open questions: PROJECT.md section 16 (shared instance host, license re-activation, teammates' RAM and Windows versions, the build instance's license and C4).
- `healthcheck.sh` right after `soc.sh up` can report the lab agent `pending` for a few seconds (manager reconnection, A75); a short wait for `active` in `check_lab` would avoid the false FAIL.

## Pending notes

- After `soc.sh reset intel`, cases needs `render-env.sh` + `bootstrap.sh cases` (new MISP key, A61). After `soc.sh reset cases` or `restore.sh cases` **without** secrets: `render-env.sh` + `bootstrap.sh core` and `bootstrap.sh cases` (C4 rules take up to 5 min to apply).
- Switching `DEPLOY_MODE` either way: `render-env.sh`, `gen-certs.sh --force intel`, `soc.sh down` + `up`, `bootstrap.sh cases` and `bootstrap.sh core` (A71).

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
- **Git remote from Claude Code's shell:** the integrator's SSH key has a passphrase and no agent runs there, so `git fetch`/`ls-remote` fail with "Permission denied (publickey)"; ask the integrator for `git ls-remote origin` output instead.
- **Windows side from WSL:** read-only PowerShell works through interop (`powershell.exe -NoProfile -Command ...`, from a Windows-visible cwd such as `/mnt/c`); anything that changes Windows (firewall rules) is the integrator's, as Administrator.
