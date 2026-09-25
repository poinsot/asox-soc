# Session handoff

Read after PROJECT.md, before starting work (CLAUDE.md). Update at the end of each session.

## Current state (2026-09-25)

- **Last completed step: 1.4** (commit `ffbe03b`), plus doc adjustments ("docs: post-1.4 adjustments and handoff"). Next: **step 1.5** (`cases` node).
- **Running:** `core` (wazuh-indexer, wazuh-manager, grafana, n8n) and `lab` (lab-agent), `standard` profile, single-host, instance `asox`. `cases` and `intel` have no services yet.
- **Nothing half-done.** `contracts-check.sh`: C1, C2, C8 pass; C3–C7 report SKIP with their build step.
- The integrator reviews after each step; approved so far: Cortex 4.1 + ES 8 (D27), Grafana 12.4 (D34), n8n memory (D38), low-profile criterion per dev mode (D39).

## Pending notes for later steps

- **Step 1.7, C4 webhook token (D36, A41):** configure TheHive's webhook to `${N8N_WEBHOOK_URL}/webhook/thehive-event` with header `X-ASOX-Token: ${N8N_WEBHOOK_TOKEN}`; the cases node gets the token with `N8N_WEBHOOK_TOKEN=__from:core__`. **Fallback:** if TheHive 5 can only send an `Authorization` header, add a second Header Auth credential (header `Authorization`, value e.g. `Bearer <token>`) in `bootstrap.sh`, use it on `recv-thehive-event`'s webhook node, and re-export the workflow. Extend C4's check: requests without/with a wrong token get 401/403 (same as `check_C1`).
- **Step 1.7, docs:** document the `__from:<node>__` `.env.example` marker in PROJECT.md section 4, including the manual copy needed in distributed mode (value pasted from the source node's machine `.env`; `render-env.sh` warns while empty).
- **Step 1.7, n8n credentials for TheHive and Cortex:** add them to `n8n_credentials_json` in `scripts/bootstrap.sh` with fixed 16-char IDs; keys come from the cases `.env` via `__from:cases__` in the core `.env.example`. Nodes are rendered in the order core, cases, intel, lab, so a core key copied from cases is empty until the next `render-env.sh` after cases is bootstrapped: re-run `render-env.sh` after `bootstrap.sh cases` (or render twice in `soc.sh init`).
- **Step 1.7:** `healthcheck.sh` doesn't exist yet (`soc.sh init` prints SKIP); `mem-report.sh` too. Measure each dev mode on `low` (D39).
- **Step 1.9:** component READMEs exist for Wazuh, Grafana, n8n (partial: operations and conventions); complete them with contracts and backlog (11.3). TheHive, Cortex, MISP READMEs don't exist yet.

## Gotchas learned

- **Memory limits:** measure, don't trust section 8 estimates. Grafana 13 leaked per browser session (pinned 12.4). n8n 2.x peaks ~730 MB at start and needs an explicit Node heap (`N8N_HEAP`). Java services: heap vars from the profile; check `memory.peak` / `memory.events` in the container cgroup (`/sys/fs/cgroup/`) after a restart, not just `docker stats`.
- **Healthchecks must mean "ready"**, not "process up": the Wazuh manager check covers the API and core daemons (A27); the lab agent waits for its post-enrollment reload (A31). `soc.sh up --wait` relies on this. Expect the same for TheHive/Cortex (e.g. API status endpoints), and bootstrap only after healthy.
- **Wazuh manager restart:** the image's init aborts on `docker restart` ("0-wazuh-init: exited 1", harmless now); `entrypoint-scripts/05-restart-fixes.sh` redoes the config copy (A26). Config under `/wazuh-config-mount` is copied at every start; deleted files stay in the volume.
- **Re-enrollment:** a fresh agent with an existing name is refused; `soc.sh reset lab` removes the old registration (A30).
- **Wazuh API RBAC:** changes revoke tokens issued in the same second (retry, A18); custom policies identical to built-ins are rejected.
- **Wazuh certs:** the cert tool only accepts dotted DNS names → indexer is `wazuh.indexer` (D32).
- **n8n:** UI login rate-limited (5/window) → scripts use `N8N_API_KEY` (public API). CLI import runs in a one-off container; activation via API, then wait for webhook registration (~0.1 s, A44). Never put secrets in n8n's environment (D37).
- **Grafana:** OpenSearch plugin health check needs the daily index pattern (D35); `GF_INSTALL_PLUGINS` + preinstall disabled for pinning only the plugin (A35).
- **Secret scan:** gitleaks flags literal credentials in `curl -u` / `-H` even in healthchecks or probes; use variables or client certs.
- **Shell waits:** the harness blocks leading `sleep N`; use `timeout N bash -c 'until ...; do sleep 3; done'`.
- **Local CI:** `scripts/ci-checks.sh all` (compose config both modes, shellcheck, JSON/XML, gitleaks) before each commit.

## Verify first in step 1.5

- Cortex 4.1 runs analyzers as **Docker containers** (`job.runners = [docker]`, set explicitly) with `job_directory=/tmp/cortex-jobs` and `docker_job_directory=${CORTEX_JOBS_HOST_DIR}` as env vars (entrypoint maps them to `job.directory` / `job.dockerDirectory`); a mounted `application.conf` must not set those keys (it's included last and would override). Test that Cortex can start a test container and that the job dir is writable (Cortex runs as uid 1001 by default; `DAEMON_USER`).
- The **Docker socket** mount and its permissions inside the Cortex container.
- **Analyzer containers and networks:** analyzers are started by the host daemon on the default bridge, so they can't resolve `misp-nginx` via soc-net; C7 (step 1.6) needs a reachable `MISP_URL` for analyzers (check for a Cortex docker network setting, or use the published port).
- TheHive 5.7.6 + Cortex 4.1.0 + ES 8.19.21 + Cassandra 4.1.12 as in StrangeBee's `testing` compose (`StrangeBeeCorp/docker`): adapt it; ES 8 security settings; memory at the section 8 values (measure).
- TheHive 5 community license limits → record in `docs/decisions.md` (PROJECT.md 6.4).
- Cortex catalog URL default in 4.1: `https://catalogs.download.strangebee.com/latest/json/analyzers.json`.
