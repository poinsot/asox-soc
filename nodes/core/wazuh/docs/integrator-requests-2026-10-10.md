# Integrator / n8n → Wazuh: alert handling hardened, two questions, test IOC (2026-10-10)

Received by the Wazuh owner on 2026-10-11. Summary of the message (as sent to Daniel), then the reply tracker. Earlier messages: [integrator-requests-2026-10-06.md](integrator-requests-2026-10-06.md), [n8n-requests-2026-09-30.md](n8n-requests-2026-09-30.md).

## Reply tracker

| # | Item | Wazuh task | Status | Reply |
|---|---|---|---|---|
| 1 | n8n survives bursts and parallel deliveries (queue, A87/A91); scenarios can run together again | — | noted | `tests/e2e.sh` already runs all 11 scenarios one after another (28/28, every forwarded alert found in n8n) |
| 2 | C1: n8n's 200 now means "queued" (`{"status":"queued"}` or `"filtered"`); no answer if n8n crashes before saving | — | done | README "Contracts" C1 paragraph updated 2026-10-11. `custom-n8n.py` reads only the status code: no change |
| 3a | X-35: does integratord run `custom-n8n.py` in parallel? | — | done | **No**: from the v4.14.8 source, and live on 2026-10-11 (20-alert burst plus two scenarios: never more than one integratord child). Your `ps` count shows 2 per delivery (wrapper + Python): count `/bin/sh integrations/custom-n8n` only (`docs/request-n8n-c1-delivery.md`) |
| 3b | X-10: a short retry in `custom-n8n.py`, to agree after 10-20 | — | answered | Proposal in `docs/request-n8n-c1-delivery.md`: retry on connect error, timeout or 5xx, at 2/5/10/20 s; never on 4xx. Sequential integratord means later alerts wait in `alerts.json`, none lost |
| 4 | X-36: `203.0.113.66` is on MISP's "RFC 5735" warninglist; likely a new test IOC outside reserved ranges | W6.1, W1.5 | answered | Ready either way: `trigger.sh` now takes `ASOX_IOC_IP` (default `203.0.113.66`). Once Diego picks the address, the default becomes a one-line change. C14's sync skips warninglisted values (`enforceWarninglist`) |
| 5a | BACKLOG shows W1.6, W1.7, W2.5, W2.7 in progress | — | done | W1.7, W2.5, W2.7 closed 2026-10-11. W1.6 stays open only for the marker level (Jesus, X-32 "level open") |
| 5b | After the checkpoint merge: `git pull`, `render-env.sh`, `soc.sh up`, `n8n-import.sh`, short check | OPS | noted | `render-env.sh` run 2026-10-11: core's `.env` now has `MISP_URL` (R-13), which C14 reuses |

## Also from main (R-13, 2026-10-10)

Core's `.env` has `MISP_URL` (C10). C14's `WAZUH_MISP_URL` now defaults to it (`compose.yml`). **R-08 shrinks to one value: `WAZUH_MISP_API_KEY`**, the Read Only key of Diego's `wazuh@asox.local`. See `request-cortex-misp-c14-design.md`.

## Message summary (Inigo, 2026-10-10)

1. **Bursts fixed on n8n's side:** an in-n8n queue processes alerts 2 at a time. Each alert is saved before the 200, and concurrent deliveries are limited. 20, 40 and 60 parallel deliveries pass on `standard` and `low`. A 20-alert burst reaches TheHive in about 30 s.
2. **C1 clarification, no contract change:**
   - a 200 means queued: about 0.1 s for one alert, about 1 s for 20, about 3 s for 60;
   - no answer if n8n crashes before saving, so a failure is logged instead of the alert vanishing;
   - the body is `{"status": "queued"}` or `"filtered"`.

   Written into PROJECT.md 5 (C1).
3. **Questions:**
   - X-35: is integratord parallel? Suggested check: `ps -ef | grep -c '[c]ustom-n8n'` during a burst.
   - X-10: a retry after the checkpoint, now safe on n8n's side, and a C1 change to agree after 10-20.
4. **X-36:** `203.0.113.66` matches "List of RFC 5735 CIDR blocks". n8n's C10 tags it as common while Cortex reports it as suspicious, which is confusing in a demo; C14 may filter it. Diego decides; probably a new test IOC, changing `ioc-ip`. To consider in the C14 design (due 2026-10-16).
5. **Small things:**
   - stale backlog statuses;
   - the new "After a checkpoint merge" steps in CONTRIBUTING.md.
