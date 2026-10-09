# Request: two findings from a core-only machine after the 2026-10-01 merge

**To:** Inigo (@poinsot), integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-01
**Refs:** W0.9, R-18 / A79 (`THEHIVE_ENABLED`), `scripts/healthcheck.sh`
**Status:** done (2026-10-06: item 1 as R-19/A83, an INFO line and CONTRIBUTING.md note; item 2 as R-20/A82, healthcheck retry)

## Context

On my machine (WSL ~7.6 GB, `MEM_PROFILE=low`, `DEPLOY_MODE=single`, mode `core`), after pulling `main` at `6da861b` I ran `render-env.sh`, `soc.sh up core`, `bootstrap.sh core` and `n8n-import.sh`. The result: `preflight.sh` passes, `healthcheck.sh` passes (on a second run), and `contracts-check.sh --only C1,C2,C8` passes. Nothing is broken for Wazuh. Two things in shared files behaved differently from what the docs lead a core-only owner to expect.

## 1. `THEHIVE_ENABLED=true` on a core-only machine

**Seen:** `render-env.sh` rendered `THEHIVE_ENABLED=true`, because `nodes/core/.env` still holds a `THEHIVE_N8N_API_KEY` from an earlier `soc.sh init` that included `cases` on this machine. Today I run only `core`, so TheHive is not reachable (`contracts-check.sh` C1 cleanup: "TheHive not reachable at http://127.0.0.1:9000 (HTTP 000)").

**Effect:** n8n treats TheHive as configured, so it parks alerts as unreachable instead of recording "skipped: TheHive not configured". This is exactly the case A79 was meant to avoid. It works as A79 is written (key non-empty → `true`), but it doesn't cover a key that is left over from an earlier `init`.

**What would help (your call):** either document that an owner who stops running `cases` should clear `THEHIVE_N8N_API_KEY` in `nodes/core/.env` and re-render, or let `render-env.sh` derive `THEHIVE_ENABLED` from the mode being run rather than from the key alone. I haven't edited `nodes/core/.env`.

## 2. `healthcheck.sh` Grafana login times out right after `soc.sh up` on `low`

**Seen:** the first `healthcheck.sh` after `soc.sh up core` failed with `FAIL core: Grafana login as admin failed`. Grafana's log shows `/api/user` took 11.08 s (`status=500 ... failed to resolve user: context canceled`), and the check uses `curl --max-time 10` (`scripts/healthcheck.sh` line 81). A second run a few minutes later passed, and the same login answers HTTP 200 by hand. Grafana was at ~174 MiB of its 250 MiB limit at the time.

**What would help:** a longer timeout or one retry for that check, so a slow first request on `low` doesn't read as a failure. It's similar to the lab agent's brief `pending` noted in the handoff (A75).

## By

No deadline: neither blocks Wazuh work. Item 1 matters for every owner who ran `cases` once and now runs only `core`.
