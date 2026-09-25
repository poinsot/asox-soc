# ASOX SOC

A containerized SOC built from open-source tools — Wazuh, n8n (SOAR), Grafana, TheHive, Cortex and MISP — grouped into three deployment nodes (`core`, `cases`, `intel`) plus an optional `lab` test agent. The full specification is in [PROJECT.md](PROJECT.md).

## Quick start (Windows + WSL2, Ubuntu 24.04)

1. Complete [CHECKLIST.md](CHECKLIST.md) (WSL, Docker Engine, tools).
2. Clone into the Linux filesystem and configure the topology:
   ```bash
   git clone <repo-url> ~/asox-soc && cd ~/asox-soc
   cp topology.env.example topology.env   # set MEM_PROFILE: standard (16 GB+) or low (8 GB)
   ```
3. First-time setup for a run mode (`core`, `cases`, `cases-intel`, `core-cases` or `full`):
   ```bash
   ./scripts/soc.sh init full
   ./scripts/soc.sh info          # URLs and the logins generated for this machine
   ```
4. Day to day:
   ```bash
   ./scripts/soc.sh up <mode>
   ./scripts/soc.sh status
   ./scripts/soc.sh down
   ```

The repo never contains secrets, certificates or data: `init` generates them on each machine, in git-ignored files (`nodes/<node>/.env`, `nodes/core/certs/`).

## Useful scripts

| Script | Purpose |
|---|---|
| `scripts/preflight.sh [mode]` | Checks the machine is ready |
| `scripts/render-env.sh` | Renders `nodes/<node>/.env` from `topology.env` (run after editing it) |
| `scripts/soc.sh` | `init`, `up`, `down`, `status`, `info`, `reset` |
| `scripts/ci-checks.sh all` | The CI checks, run locally (compose config, shellcheck, JSON/XML, secret scan) |

Team workflow and onboarding: `CONTRIBUTING.md` (added at the end of Phase 1). Implementation choices and pinned versions: [docs/decisions.md](docs/decisions.md).
