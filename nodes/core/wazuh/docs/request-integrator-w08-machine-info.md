# Answer: Wazuh owner's machine (PROJECT.md 16, questions 1 and 3)

**To:** Inigo (@poinsot), integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-01
**Refs:** W0.8, W0.2, PROJECT.md 16 (questions 1 and 3), CHECKLIST.md sections 1–3
**Status:** sent; answers recorded by the integrator 2026-10-06 (12 GB row for CHECKLIST.md is R-24, open)

## Answers

| Question | Answer |
|---|---|
| 1. Windows version | **Windows 11 Home, build 26200** (25H2). Mirrored networking works: WSL shows the same LAN IP as Windows (`192.168.1.191`). |
| 3. RAM | **12 GB** (11.8 GB usable). WSL gets `memory=8GB`, `swap=8GB`, `processors=4`; `free -h` shows 7.8 GiB / 8.0 GiB. `MEM_PROFILE=low`, `DEPLOY_MODE=single`. |

## The rest of the machine (CHECKLIST.md teammate gate, W0.2)

All checked on 2026-10-01:

- **Hardware:** x86-64 (AMD64). Virtualization is on (WSL 2 runs). C: has 85 GB free.
- **WSL and Ubuntu:** WSL 3.0.1, Ubuntu 24.04.1 as WSL 2, systemd `running`, `vm.max_map_count` 1048576.
- **Docker:** Engine 29.8.1 inside WSL with Compose v5.5.1; log rotation configured; no Docker Desktop installed.
- **Tools, git and network:** every required CLI tool is present; git is configured; the registries and download hosts are reachable.
- **Checks:** `preflight.sh` passes. `ci-checks.sh all` passes.
- **Stack in use:** `core` + lab uses about 2.3 GB of containers, with about 4.5 GB still available in the VM.

## One note for CHECKLIST.md (your call)

The RAM table in sections 1 and 2 lists 8, 16 and 32 GB machines, but not 12 GB. I use the 8 GB row's profile (`low`) with an 8 GB VM instead of 6 GB, and `core` runs comfortably. A 12 GB row (`memory=8GB`, `swap=8GB`, `low`) might help the next person with this RAM.

## By

No deadline; it only closes the open questions.
