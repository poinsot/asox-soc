# Answer: C1 delivery is sequential (X-35); retry proposal (X-10); the test IOC on a warninglist (X-36)

**To:** Inigo (@poinsot), n8n owner and integrator; cc Diego (@DiegoGuerraA00835430) for X-36
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-10
**Refs:** X-10, X-35, X-36, C1, C7, C10, C14, A48, A87; `integrations/custom-n8n.py`
**Status:** draft

## X-35: does integratord call `custom-n8n.py` for several alerts at once? **No.**

It is strictly one after the other. The source of the pinned version, `src/os_integrator/integrator.c` at tag `v4.14.8`, shows it:

- `wazuh-integratord` is **one loop in one process** (`while (FOREVER())`). It reads the next alert from `alerts.json` (`jqueue_next`).
- For each integration that matches, it starts the script with `wpopenv(...)`, reads its output to the end, and **waits for it to exit** (`wpclose`) before it moves on to the next integration or the next alert.
- There is no thread pool and no fork-and-forget.

**Checked live 2026-10-11** with your suggested `ps` during a burst: 20 test alerts written at once, plus `new-user` and `ssh-bruteforce` together, sampled every 50 ms for 15 s. Never more than one integratord child at a time; 20 different children, one per alert, one after the other. Note for your command: `ps -ef | grep -c '[c]ustom-n8n'` shows **2 per delivery**, because the wrapper `/bin/sh integrations/custom-n8n` starts `custom-n8n.py` as a child. Count only the wrapper (`grep -c '[/]bin/sh integrations/custom-n8n'`): it was never above 1.

So the webhook sees at most **one C1 request at a time** from a manager: the next starts only after `custom-n8n.py` has returned. Your measured bursts (7–20 alerts, sequential) match this. n8n needs no bound on concurrent `recv-wazuh-alert` executions for C1. Only replays or tests can overlap.

## X-10: retries, a proposal (C1 behaviour change, after checkpoint 1 as you planned)

That same loop means a retry inside `custom-n8n.py` **delays** the following alerts but doesn't lose them: they wait in `alerts.json` until the script returns. integratord already passes the integration's `<timeout>` and `<retries>` to the script as arguments (the `integrator_config[s]->timeout` and `->retries` fields in the same file), so no new mechanism is needed.

**Proposal:**

| Item | Proposed value |
|---|---|
| **When to retry** | Only when n8n didn't take the alert: connection refused, timeout, or HTTP 5xx |
| **When not to retry** | 2xx; and 4xx (403 wrong token, 422 bad JSON), which a retry can't fix |
| **Backoff** | `<retries>4</retries>`: 2, 5, 10, 20 s, each try with the 10 s timeout. That covers your measured ~20–25 s n8n restart, and caps the delay at about 80 s per alert |
| **After the last try** | Log the failure in `integrations.log` as today. The alert stays in the indexer |
| **Duplicates** | Safe with your A87 queue: dedup by `sourceRef`, writeback repair. A retry after a timeout can deliver an alert twice |

This is a C1 change. I'll only build it once you say yes (rule 5), and it gets a C1 check in `contracts-check.sh` (stop n8n, send the test alert, start n8n, expect one execution). If you prefer it before checkpoint 1, it's about an hour on my side.

## X-36: the test IOC `203.0.113.66` is on MISP's "List of RFC 5735 CIDR blocks"

It matters for C14 too. My C14 sync (`request-cortex-misp-c14-design.md`) should skip values that are on a warninglist (MISP's `enforceWarninglist`), so that common values like public DNS servers never become IOCs in Wazuh's lists. With that list enabled, the seed IOC would be skipped, and `trigger.sh --scenario ioc-ip` couldn't test C14 either.

**My suggestion (Diego's call, `misp-config.json`):** disable **only** that one warninglist. Documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) never appear in real traffic, so the list gives no protection in this SOC. Disabling it keeps the seed IOC working the same way for C7, C10, C14 and n8n's fixtures. Changing the IOC everywhere would touch three owners' files for no gain.

## By

- X-35: no action.
- X-10: your yes or no, before or after checkpoint 1.
- X-36: Diego's decision before C14 is built (W6.2, this weekend on my side; I'll test with the list disabled locally if needed).
