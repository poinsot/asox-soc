# Contributing to ASOX SOC

How the team works on the platform after the Phase 1 baseline (`v1.0-baseline`). Details and reasons are in [PROJECT.md](PROJECT.md) (sections 5, 11) and [docs/decisions.md](docs/decisions.md).

## Who owns what

| Component | Owner | Branch | Folders you change | `init` mode |
|---|---|---|---|---|
| Wazuh | Daniel (@dmelgar1110) | `wazuh` | `nodes/core/wazuh/`, `nodes/lab/` | `core` |
| n8n (SOAR) | Inigo (@poinsot) | `n8n` | `nodes/core/n8n/` | `core-cases` |
| Grafana | Jesus (@JC-535) | `grafana` | `nodes/core/grafana/` | `core` |
| TheHive | Park (@Jinhyuk-P) | `thehive` | `nodes/cases/thehive/` | `cases` |
| Cortex + MISP | Diego (@DiegoGuerraA00835430) | `cortex-misp` | `nodes/cases/cortex/`, `nodes/intel/misp/` | `cases-intel` |
| Integrator | Inigo (@poinsot) | `main` | Everything else: node root compose files, `soc-net.yml`, `nodes/cases/storage.yml`, `.env.example` files, `scripts/`, `topology.env.example`, `windows/`, `docs/`, `PROJECT.md`, `CHECKLIST.md`, this file, `.gitattributes`, `.github/` | — |

`main` is the integrated, working platform; only the integrator merges into it (by team agreement: there is no branch protection). The integrator is also the n8n owner and follows the same rules for n8n work.

## The five light rules

1. **Work only on your branch.**
2. **Push at the end of every work session** (`git push`), so your work is backed up and visible.
3. **Only change your own folders.** Need a shared file changed (a new variable in an `.env.example`, a fix in `soc.sh`, ...)? Ask the integrator: they change it on `main`, and you pull it in.
4. **Merge at checkpoints, not only at the end** (every ~2 weeks, or whenever something works):
   1. Export your UI changes, commit, then bring in `main`: `git pull --no-rebase --no-edit origin main` (merges `main` into your branch without opening an editor).
   2. Check it still runs: `scripts/healthcheck.sh`, plus `scripts/contracts-check.sh --only <contracts>` if you touched an integration.
   3. `git push`, then open the pull request on GitHub: on the repo page, click **Compare & pull request** (or **Pull requests → New pull request**), choose base **`main`** ← compare **your branch**, describe what changed and tick the template's checklist, then **Create pull request**.
   4. CI runs; the integrator reviews and merges.
5. **Talk before changing a contract.** Anything another component relies on (URL path, payload, auth, permissions; the table in PROJECT.md section 5) is agreed with that owner first and goes in at a checkpoint.

A merge conflict you're unsure about: stop and ask the integrator rather than guessing. Claude Code on your branch is fine; these rules still apply to what it changes.

## Keeping everything as code

Changes made in a UI live in a database until you export them. Export **before** committing, and before pulling someone else's changes.

| Component | Where you change things | How it reaches git |
|---|---|---|
| Wazuh | Files (rules, decoders, `ossec.conf`) | Edit, restart the manager, commit |
| n8n | n8n UI | `scripts/n8n-export.sh`, commit the JSON; others load it with `scripts/n8n-import.sh` |
| Grafana | Grafana UI | `scripts/grafana-export.sh`, commit the dashboard JSON |
| TheHive | UI / API (templates, custom fields) | Your own export/import scripts in your folder (your first task) |
| Cortex + MISP | UI / API (analyzers, MISP settings) | Your own export/bootstrap scripts in your folders (your first task); custom analyzers as code in `nodes/cases/cortex/analyzers/` |

- **Never commit** `.env` files, certificates, API keys, backups or data. `.gitignore` covers them, and CI runs a secret scan.
- Exported n8n workflows reference credentials by name and ID only, never their values. A new credential is added to `bootstrap.sh` by the integrator.
- n8n JSON merges badly: **one owner per workflow file**.

## Onboarding (day one)

You receive the repo link (you're already a collaborator and your branch exists) and your component. Then:

1. Accept the GitHub invite.
2. Complete [CHECKLIST.md](CHECKLIST.md): WSL, Docker, tools, GitHub access from WSL, and **request the TheHive Community license** if your mode includes `cases` (section 9: StrangeBee validates accounts by hand, so request it on day one).
3. Clone into WSL's Linux filesystem and switch to your branch (the SSH URL needs the SSH key from `CHECKLIST.md` section 9; with a personal access token use `https://github.com/poinsot/asox-soc.git`):
   ```bash
   git clone git@github.com:poinsot/asox-soc.git ~/asox-soc && cd ~/asox-soc && git checkout <your-branch>
   ```
4. `cp topology.env.example topology.env`, then set `MEM_PROFILE` (`standard` for 16 GB+, `low` for 8 GB) and leave `DEPLOY_MODE=single`.
5. `./scripts/soc.sh init <mode>` with your mode (table above). The first time takes 5–15 minutes plus the image download (6–19 GB of images depending on the mode; `CHECKLIST.md` section 1), and ends with an all-green healthcheck.
6. `./scripts/soc.sh info` shows your URLs and UI logins. They're generated on your machine and stored in `nodes/<node>/.env`.
7. Read your component's `README.md`: backlog, contracts, how to export.
8. **If your mode includes `cases`** (TheHive, Cortex + MISP, n8n): apply the Community license before the 14-day trial ends (TheHive becomes read-only after it), following `nodes/cases/thehive/README.md` (section License). **Right after activating it, run `./scripts/backup.sh cases --with-secrets`**, and later restore that backup instead of running `soc.sh reset cases`, which creates a new instance and loses the license.

**8 GB machines** (`MEM_PROFILE=low`, WSL 6 GB): `core`, `cases` and `cases-intel` fit; `core-cases` barely does, and `full` doesn't (use a 16 GB+ machine, or the shared instance once it exists: it's optional and not set up yet, PROJECT.md 11.4). **Close VS Code's WSL connection while running `cases-intel`**: with the VS Code server and Claude Code running, it peaks at ~5.3 of the VM's 5.8 GB.

### Daily loop

```bash
git pull && ./scripts/soc.sh up <mode>
# work in your folders; export UI changes (above); test:
./scripts/healthcheck.sh                        # + contracts-check.sh --only <Cx,...> for integrations
git add -A && git commit -m "<what changed>" && git push
./scripts/soc.sh down
```

| Owner | Test loop | Contracts |
|---|---|---|
| Wazuh | Edit rule → restart manager → `nodes/lab/trigger.sh` → `scripts/wazuh-query.sh` or Grafana | C1, C2, C8 (later C9) |
| n8n | Edit playbook → `nodes/lab/trigger.sh` → execution and TheHive alert → `scripts/n8n-export.sh` | C1–C4, C6 (later C9) |
| Grafana | Edit dashboard → `nodes/lab/trigger.sh` for more data → `scripts/grafana-export.sh` | C8 |
| TheHive | Configure → test alerts through the API (no Wazuh in `cases`) → alert and case flow | C3, C4, C5 |
| Cortex + MISP | Add intel in MISP → run analyzers on test observables → reports | C5, C6, C7 |

### After a checkpoint merge (machines that run `core`)

When a checkpoint merge brings new n8n workflows or a changed n8n compose file into `main` (first time: checkpoint 1, the `n8n` branch), every machine that runs `core` does this once, whatever its `MEM_PROFILE` (the same steps apply on `low`):

1. If you changed any n8n workflow in the UI, the import below overwrites it. Only the n8n owner commits workflow files: export it (`scripts/n8n-export.sh`) and send the diff to the n8n owner before pulling, or accept losing it.
2. `git pull` (on your branch: `git pull --no-rebase --no-edit origin main`).
3. `./scripts/render-env.sh`, then `./scripts/soc.sh up <mode>`: Compose recreates the n8n container when its compose file or `.env` changed (`soc.sh up` doesn't re-render `.env` itself; the render brings shared changes such as `N8N_MEM`). Environment settings such as `N8N_EVENTBUS_RECOVERY_MODE` and `N8N_CONCURRENCY_PRODUCTION_LIMIT` only arrive this way, so do it **before** the import.
4. `./scripts/n8n-import.sh`: loads every workflow file, **overwriting** workflows with the same ID, and activates them in an order that works. It must end with `All checks passed`; a workflow it couldn't activate gets a `FAIL` line with its name and n8n's reason (send that line to the n8n owner).
5. Verify:
   - the import printed `PASS  n8n: all <N> workflow(s) marked active are active on the server`;
   - both settings are in the container (expect `2`: the recovery mode and the limit of 10 concurrent webhook and trigger executions). Never print the container's whole environment: it holds keys and the webhook token.
     ```bash
     docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' asox-core-n8n-1 | grep -c -e '^N8N_EVENTBUS_RECOVERY_MODE=simple$' -e '^N8N_CONCURRENCY_PRODUCTION_LIMIT=10$'
     ```
   - `./scripts/contracts-check.sh --only C1,C3` passes (C3 needs `cases` running).

The alert queue's Data Tables (`asox_alert_queue`, `asox_queue_slots`) are created automatically on n8n's first run with the new workflows, and found again on later ones: nothing to do.

### Git cheat sheet

| Situation | Command |
|---|---|
| Which branch? Anything unsaved? | `git status` |
| Save and back up | `git add -A && git commit -m "message" && git push` |
| Latest from my branch | `git pull` |
| Bring in merged work from `main` | `git pull --no-rebase --no-edit origin main` |
| Recent history | `git log --oneline -10` |
| Conflict or anything unexpected | Stop and ask the integrator |

### Useful scripts

`soc.sh init|up|down|status|info|reset`, `healthcheck.sh [--cross-node]`, `contracts-check.sh [--only C3,C4]`, `backup.sh <node> [--with-secrets]` / `restore.sh <node> <dir>`, `wazuh-query.sh`, `n8n-export.sh` / `n8n-import.sh`, `grafana-export.sh`, `ci-checks.sh all` (the CI checks, locally). Each prints its usage with `--help`.

### Troubleshooting

- **You ran `cases` once and now run only `core`, and n8n parks alerts as `thehive_unreachable`** instead of recording `skipped: TheHive not configured`: `nodes/core/.env` still holds the `THEHIVE_N8N_API_KEY` of that earlier `init`, so `render-env.sh` renders `THEHIVE_ENABLED=true` (it prints an INFO line saying so). Empty `THEHIVE_N8N_API_KEY=` in **both** `nodes/core/.env` and `nodes/cases/.env` (render copies it from cases, and keeps core's value while cases' is empty), then `./scripts/render-env.sh` and `./scripts/bootstrap.sh core` (recreates n8n with `THEHIVE_ENABLED=false`). If you run `cases` again later, `bootstrap.sh cases` creates a new key. (`docs/decisions.md` A83)
- **`healthcheck.sh` fails right after `soc.sh up`** on a `low` machine: services can be slow for their first minute. Run it again after a minute before investigating; the Grafana login check already retries once.

## When everyone meets

- **Checkpoints:** each owner opens a pull request; the integrator merges and runs `contracts-check.sh` in `full` mode on the result.
- **Whole chain** (Wazuh → n8n → TheHive → Cortex → MISP): on a 16 GB+ machine in `full` (or the optional shared instance, once it exists).
- **Milestones:** the integrator tags `main` (e.g. `v1.1-detections`) once the combined result works end to end.
