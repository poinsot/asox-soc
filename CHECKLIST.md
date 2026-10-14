# ASOX SOC Platform — Development Checklist

> Companion to `PROJECT.md` (v2.1). Lists everything that must be installed, configured or available on a **Windows + WSL2** machine, both for building the Phase 1 baseline and for teammates developing components afterwards. Every team machine is Windows + WSL2 (`PROJECT.md` D18).
>
> **Who needs what:**
> - **Everyone:** sections 1–5, 7, 9 (required accounts) and the teammate gate in section 10.
> - **Baseline builder only**, marked **[Builder]**: section 6 (Claude Code), the builder gate in section 10, and section 11 (backups).
>
> The baseline is built on a **32 GB** machine (`MEM_PROFILE=standard`). Teammates on **8 GB** machines use `MEM_PROFILE=low`.
>
> Check each item and run its verification command. `scripts/preflight.sh` (build step 1.0) automates most WSL-side checks. This list also covers the things it can't check: Windows settings, accounts and hardware.

---

## 1. Hardware

- [ ] **CPU is x86-64 (amd64).** Standard for Windows PCs. Windows on ARM (e.g. Snapdragon laptops) would run arm64 containers and is not tested.
  Verify (PowerShell): `$env:PROCESSOR_ARCHITECTURE` → `AMD64`
- [ ] **Hardware virtualization enabled in BIOS/UEFI** (Intel VT-x / AMD-V).
  Verify: Task Manager → Performance → CPU → "Virtualization: Enabled"
- [ ] **RAM and matching memory profile** (`PROJECT.md` §8):
  - Baseline build machine: **32 GB** → WSL 16 GB, `MEM_PROFILE=standard`
  - 16 GB machine → WSL 10 GB, `MEM_PROFILE=standard` (use run modes if tight)
  - 8 GB machine → WSL 6 GB, `MEM_PROFILE=low`, run modes recommended. **Close VS Code's WSL connection while running `cases-intel`**: with the VS Code server and Claude Code running it peaks at ~5.3 of the VM's 5.8 GB (`PROJECT.md` §11.6).
- [ ] **≥ 60 GB free disk on the drive that holds the WSL virtual disk** (C: by default). Measured on the build machine (step 1.9; images uncompressed, volumes after a few days of lab use):

  | Mode | Images | Volumes | Total |
  |---|---|---|---|
  | `core` (core + lab) | 8.8 GB | 10.2 GB (9.5 GB of it is Wazuh's vulnerability feed, downloaded by the manager after the first start) | ~19 GB |
  | `cases` | 5.6 GB | 0.1 GB | ~6 GB |
  | `cases-intel` | 10.2 GB | 2.0 GB | ~12 GB |
  | `core-cases` | 14.5 GB | 10.3 GB | ~25 GB |
  | `full` | 19.1 GB | 12.2 GB | ~31 GB |

  **Since 2026-10-14 the lab node also runs Suricata** (network IDS, D49): every mode with the lab (`core`, `core-cases`, `full`) needs **~0.65 GB more** than the table (the `jasonish/suricata` image, ~0.62 GB, plus its rules volume), e.g. `core` ~20 GB.

  Add room for backups (`core` ~1.1 GB, `intel` ~0.6 GB, `cases` a few MB, compressed), logs and WSL's own files. The WSL virtual disk grows but doesn't shrink by itself when data is deleted.
  Verify (PowerShell): `Get-PSDrive C`
- [ ] *(Optional)* **Second x86-64 computer** on the same LAN for the distribution test (build step 1.8).

---

## 2. Windows host

- [ ] **Windows 11 22H2 or later** (recommended, enables WSL mirrored networking). If on Windows 10 1809+, the `portproxy` fallback from `PROJECT.md` §7.2 applies.
  Verify: `winver`
- [ ] **Administrator access**, needed once for WSL install, firewall rules and the portproxy fallback.
- [ ] **WSL 2 installed and up to date** (WSL 2.0+ needed for mirrored networking).
  Install: `wsl --install` · Update: `wsl --update`
  Verify: `wsl --version` and `wsl --status` (default version must be 2)
- [ ] **`%UserProfile%\.wslconfig` created** (Windows side; the same content as `windows/wslconfig.example` in the repo), then run `wsl --shutdown` in PowerShell so WSL restarts with it. Set `memory` and `swap` for the machine's RAM:

  | Machine RAM | `memory` | `swap` | `MEM_PROFILE` |
  |---|---|---|---|
  | 32 GB | `16GB` | `4GB` | `standard` |
  | 16 GB | `10GB` | `4GB` | `standard` |
  | 8 GB | `6GB` | `8GB` | `low` |

  ```ini
  [wsl2]
  memory=16GB
  swap=4GB
  processors=4
  # Windows 11 22H2+. On Windows 10 remove this line (PROJECT.md 7.2).
  networkingMode=mirrored
  kernelCommandLine = sysctl.vm.max_map_count=262144
  ```
- [ ] **Docker Desktop not installed, or its WSL integration disabled for the project distro.** It conflicts with Docker Engine inside WSL and consumes extra RAM.
- [ ] **Windows Firewall inbound rules** for published ports, via `windows/firewall-rules.ps1` (created in step 1.0, run as Administrator):
  - core: 1514/tcp, 1515/tcp, 514/udp, 55000/tcp, 5678/tcp, 3000/tcp
  - cases: 9000/tcp, 9001/tcp
  - intel: 9443/tcp
  - Only required in distributed mode. In single-host mode ports bind to `127.0.0.1` and aren't reachable from the LAN anyway (`PROJECT.md` D16).
  - With mirrored networking, WSL's Hyper-V firewall blocks inbound traffic by default (seen in step 1.8), so other computers can't reach the nodes until the script has run on each machine that hosts one.
- [ ] **Web browser** for n8n, Grafana, TheHive, Cortex and MISP UIs.
- [ ] *(Optional)* **Windows Terminal**, for a better WSL terminal experience.
- [ ] *(Optional)* **VS Code + "WSL" extension**, to browse and edit the repo inside WSL.

---

## 3. WSL distribution

- [ ] **Ubuntu 24.04 installed as a WSL 2 distro.**
  Install: `wsl --install -d Ubuntu-24.04`
  Verify: `wsl -l -v` → VERSION `2`
- [ ] **systemd enabled** in `/etc/wsl.conf`:
  ```ini
  [boot]
  systemd=true
  ```
  Verify (after `wsl --shutdown` and reopening): `systemctl is-system-running` → `running` or `degraded`
- [ ] **Memory limit applied.**
  Verify: `free -h` → total and swap match the `.wslconfig` values (≈16 GB / 4 GB on the build machine)
- [ ] **`vm.max_map_count` >= 262144** (a minimum; Ubuntu 24.04 defaults to 1048576, which is fine).
  Verify: `sysctl vm.max_map_count` → 262144 or more
  Fallback (only if lower): `echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-soc.conf && sudo sysctl --system`
- [ ] **Mirrored networking active** (Windows 11).
  Verify: `ip addr` shows the same LAN IP as Windows (`ipconfig`)
- [ ] **System updated**: `sudo apt update && sudo apt upgrade -y`
- [ ] **Work in the Linux filesystem** (`~`), never under `/mnt/c/`: the repo is cloned into `~/asox-soc` (`CONTRIBUTING.md`, Onboarding).

---

## 4. Docker (inside WSL)

- [ ] **Docker Engine installed from Docker's official apt repository**, with packages `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`. Follow "Install using the apt repository" at https://docs.docker.com/engine/install/ubuntu/ (inside WSL; not Docker Desktop).
  Verify: `docker version` shows both Client and Server
- [ ] **Docker Compose v2.20 or later** (the project uses per-node compose files and profiles).
  Verify: `docker compose version`
- [ ] **User in the `docker` group** (no `sudo` needed).
  `sudo usermod -aG docker $USER`, then reopen the terminal.
  Verify: `docker run --rm hello-world`
- [ ] **Docker starts automatically with WSL.**
  `sudo systemctl enable --now docker`
  Verify: `systemctl is-active docker` → `active`
- [ ] **Docker log rotation configured** so container logs don't fill the disk. `/etc/docker/daemon.json`:
  ```json
  { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
  ```
  Then `sudo systemctl restart docker`.
- [ ] *(Optional)* **Docker Hub account + `docker login`**, to avoid anonymous pull rate limits while pulling many images.

---

## 5. CLI tools (inside WSL)

Used by the project scripts (`preflight.sh`, `bootstrap.sh`, `healthcheck.sh`, `backup.sh`, etc.).

- [ ] Install everything in one go:
  ```bash
  sudo apt install -y git curl jq openssl ca-certificates gnupg \
    netcat-openbsd dnsutils iproute2 unzip python3 htop openssh-client
  ```

| Tool | Used for | Verify |
|---|---|---|
| `git` | Version control, commits after each build step | `git --version` |
| `curl` | API calls to Wazuh, TheHive, Cortex, MISP, n8n, Grafana in scripts and tests | `curl --version` |
| `jq` | Parsing API JSON responses in scripts | `jq --version` |
| `openssl` | Generating random passwords and inspecting certificates | `openssl version` |
| `sha256sum`, `tar` | Backup checksums and volume archives (preinstalled) | `sha256sum --version` |
| `nc` (netcat) | Sending test syslog messages to 514/udp, port checks | `nc -h` |
| `dig` | DNS checks in distributed mode | `dig -v` |
| `ss` (iproute2) | Checking ports are free / listening | `ss -tulpn` |
| `logger` | Emitting test log lines (preinstalled, util-linux) | `logger --version` |
| `python3` | Helper scripts and JSON handling where bash/jq falls short | `python3 --version` |
| `htop` | Watching RAM/CPU while nodes start | `htop` |
| `ssh` | Managing other machines in distributed mode | `ssh -V` |

- [ ] *(Optional)* **GitHub CLI** (`gh`) for opening checkpoint pull requests from the terminal (the GitHub website works just as well). Verify: `gh auth status`
- [ ] *(Optional)* **shellcheck** to run the CI script checks locally: `sudo apt install -y shellcheck`
- [ ] **Git configured**:
  `git config --global user.name "..."`, `git config --global user.email "..."`, `git config --global init.defaultBranch main` (so new repos start on `main`, as the project expects) and `git config --global pull.rebase false` (so a plain `git pull` merges instead of stopping with "Need to specify how to reconcile divergent branches"; the documented checkpoint command already passes `--no-rebase`)

---

## 6. Claude Code [Builder]

- [ ] **Claude account with Claude Code access**: Pro, Max, Team, Enterprise or Console. The free plan does not include Claude Code.
- [ ] **Claude Code installed inside WSL** (not in PowerShell/CMD), using the native installer:
  ```bash
  curl -fsSL https://claude.ai/install.sh | bash
  ```
  Verify: `claude --version` and `claude doctor`
- [ ] **Logged in**: run `claude` in `~/asox-soc` and complete the browser login.
- [ ] **Project documents in place**: `PROJECT.md` and `CHECKLIST.md` copied into `~/asox-soc/`.
- [ ] **Repository initialized**: `cd ~/asox-soc && git init`
- [ ] **Empty private GitHub repo `asox-soc` created** (no README, license or .gitignore, so the first push is clean). Needed at step 1.9, when you push; Claude Code itself never pushes.
- [ ] *(Teammates)* Claude Code is optional for component work; if an owner uses it, the install and login steps in section 6 apply to them too.
- [ ] **`CLAUDE.md` created** in `~/asox-soc`. Claude Code reads it automatically at the start of every session, so it keeps following the plan across sessions:
  ```markdown
  # CLAUDE.md
  Read PROJECT.md fully before doing anything. Build Phase 1 by following
  section 10 in order and the working rules in 10.1. Commit locally after
  each step, never push, and update section 17 (Status) as you go.
  If docs/handoff.md exists, read it after PROJECT.md and before starting work; update it at the end of each session.
  ```
- [ ] **RAM awareness:** Claude Code runs inside the same WSL memory as the stack. On the 32 GB build machine with WSL at 16 GB there is ample headroom; on smaller machines, close other heavy processes during the `full` run mode.

Reference: https://code.claude.com/docs/en/setup

---

## 7. Network and internet access

- [ ] **Internet access from WSL**, needed throughout (D6): images and packages, Grafana's plugin install at startup, the Cortex analyzer catalog, optional online analyzers, GitHub, and Claude Code.
- [ ] **Container registries reachable** (not blocked by proxy or firewall):
  - `registry-1.docker.io` (Docker Hub): Wazuh, TheHive, Cortex, Cassandra, n8n, Grafana, MariaDB, Redis
  - `docker.elastic.co`: Elasticsearch
  - `ghcr.io`: MISP images
- [ ] **Other download sources reachable**: `github.com` (repo, wazuh-docker reference), the Cortex analyzer catalog host (`catalogs.download.strangebee.com` by default), `packages.wazuh.com` (Wazuh agent package for the lab image), `grafana.com` (Grafana plugins), `claude.ai` and `downloads.claude.ai` (Claude Code).
- [ ] **Required host ports free.**
  Verify: `ss -tulpn | grep -E ':(514|1514|1515|55000|5678|3000|9000|9001|9443)\b'` returns nothing
- [ ] *(Distributed mode)* **Machines on the same LAN with fixed IPs** (static or DHCP reservation), since `topology.env` depends on them.

---

## 8. Container images (Phase 1)

Nothing to install by hand: `soc.sh init` pulls (or, for the lab agent, builds) every image the chosen mode needs. The exact pinned tags are in each node's `.env.example` (`nodes/<node>/.env.example`, where compose reads them from) and in [docs/decisions.md](docs/decisions.md) (Pinned images). The first pull is 6–20 GB depending on the mode (section 1; Suricata adds ~0.65 GB to `core`).

- [ ] **Internet at the first start of the lab node.** Suricata downloads the ET Open rules (no account needed) when it first starts, then refreshes them at most once a day; without internet it has no signatures.

---

## 9. Accounts and API keys

**Phase 1 — required**
- [ ] **[Builder]** Claude account with Claude Code access (section 6)
- [ ] **GitHub account for every teammate**, added as collaborators on the project repo
- [ ] **GitHub authentication from WSL** (SSH key added to GitHub, or HTTPS with a personal access token)
  SSH (recommended), inside WSL:
  ```bash
  ssh-keygen -t ed25519 -C "you@example.com"   # Enter for the default path; a passphrase is optional
  cat ~/.ssh/id_ed25519.pub                      # copy this line
  ```
  On GitHub: your picture → **Settings** → **SSH and GPG keys** → **New SSH key**, paste the line, **Add SSH key**.
  Verify: `ssh -T git@github.com` → "Hi <username>! You've successfully authenticated". (With a passphrase, run `eval "$(ssh-agent -s)" && ssh-add` once per terminal so git doesn't fail with "Permission denied (publickey)".)
- [ ] **TheHive Community license, requested from StrangeBee by each person who runs the `cases` node** (TheHive, Cortex + MISP and n8n owners; anyone running `cases-intel`, `core-cases` or `full`). Free, at `portal.apps.strangebee.com`: register with a professional email, confirm it, wait for StrangeBee to validate the account, then **Request a Community license**.
  **Request it early:** account validation is manual, and a new TheHive instance only runs a **14-day trial** before it becomes read-only. The license is activated on your own instance after `soc.sh init` (`PROJECT.md` 11.6, `nodes/cases/thehive/README.md`).

**Phase 1 — optional**
- [ ] Docker Hub account (pull rate limits)
- [ ] VirusTotal API key (Cortex analyzer)
- [ ] AbuseIPDB API key (Cortex analyzer)

**Later phases (not needed now)**
- [ ] Slack workspace where you can create an app with Socket Mode
- [ ] LLM provider access for ASOX
- [ ] pfSense device or VM, Snort machine

Credentials generated by the platform itself (Wazuh, TheHive, Cortex, MISP, n8n, Grafana users and API keys) are created by `bootstrap.sh` and stored in each node's `.env`. Never commit them.

---

## 10. Ready-to-start gates

**Teammate gate** (before running `soc.sh init <mode>`):

- [ ] `wsl -l -v` → Ubuntu 24.04, version 2
- [ ] `free -h` → matches `.wslconfig`
- [ ] `sysctl vm.max_map_count` → >= 262144
- [ ] `docker run --rm hello-world` works without sudo
- [ ] `docker compose version` → v2.20+
- [ ] `git`, `curl`, `jq`, `openssl`, `nc` all respond to their version/help command
- [ ] GitHub access works from WSL, and the repo is cloned into `~/asox-soc`
- [ ] `topology.env` created from `topology.env.example`, with `MEM_PROFILE` set for this machine
- [ ] Required ports are free
- [ ] ≥ 60 GB free disk
- [ ] `./scripts/preflight.sh <mode>` (in `~/asox-soc`) prints no FAIL line

**[Builder] gate** (before starting build step 1.0 with Claude Code): the same checks, except the clone and `topology.env` items (they don't exist yet), plus:

- [ ] `free -h` → ~16 GB RAM, ~4 GB swap
- [ ] `claude --version` works and you are logged in
- [ ] `~/asox-soc` contains `PROJECT.md`, `CHECKLIST.md` and `CLAUDE.md`, and is a git repo on branch `main`

---

## 11. Backups [Builder] (before step 1.8; also whoever maintains the shared instance)

- [ ] Enough free disk for backups: `core` ~1.1 GB, `intel` ~0.6 GB, `cases` a few MB (compressed, step 1.9; they grow with data). Archiving needs no extra temporary space
- [ ] A safe place to keep copies outside the machine (another disk, a network share or another computer)
- [ ] Backups made with `--with-secrets` contain credentials: stored somewhere private, never committed or shared publicly
