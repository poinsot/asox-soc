# Reply: C1 retries (X-10), yes after checkpoint 1, with three conditions

**To:** Daniel (@dmelgar1110), Wazuh owner
**From:** Inigo (@poinsot), n8n owner
**Date:** 2026-10-14
**Refs:** X-10, X-35, C1, A48, A78, A87, N8N-1.8, N8N-1.9; your `nodes/core/wazuh/docs/request-n8n-c1-delivery.md` (2026-10-10)
**Status:** n8n's answer; C1 behaviour change, built only after checkpoint 1 (2026-10-20), both owners agreeing first (PROJECT.md 11.1, rule 5). **2026-10-15:** both owners agreed; n8n's condition 3 is built (update at the end). **2026-10-20:** live (PR #31, D51; update at the end)

Thanks for the source reading on X-35 and the proposal. **Yes to retries in `custom-n8n.py`**, built after checkpoint 1, with the three conditions below. Your other points are fine as written: retry on a connection error, a timeout or HTTP 5xx; never on 2xx, 403 or 422; `<retries>4</retries>` with waits of 2, 5, 10 and 20 s and the 10 s timeout per try; the failure logged in `integrations.log` after the last try; a C1 check in `contracts-check.sh` (stop n8n, send the test alert, start n8n, expect one execution).

## Conditions

**1. Also retry on HTTP 404.**
n8n answers 404 when the webhook isn't registered: for a few seconds while n8n starts (the HTTP server is up before the workflows are active), and while `scripts/n8n-import.sh` re-activates the workflows after an import (each workflow is deactivated and activated again). In both cases the next try a few seconds later succeeds. A wrong path in the integration's `<hook_url>` also gives 404, permanently; condition 2 keeps that cheap, and the failure stays in `integrations.log`. 403 (token) and 422 (bad JSON) stay final.

**2. Fast-fail after one exhausted chain.**
integratord is sequential (your X-35 answer), so while n8n is down every alert would wait the whole chain: ~37 s each when the connection is refused, ~87 s when n8n hangs (5 × 10 s + 37 s). An outage of a few minutes would then delay the alerts behind it by tens of minutes after n8n is back. Proposal: once a chain is exhausted, record it (a small state file next to the script, with the time); while that mark is there, the next alerts get **one try only**, no waits. The first success removes the mark and the full chain applies again. Optionally re-arm the full chain after some minutes (e.g. 5) even without a success, so a single lost try doesn't stretch a short outage. Your call on the details; what n8n needs is that a long outage costs one try per alert, not 37–87 s.

**3. n8n deduplicates by alert id at queue insert (n8n's side).**
A retry after a timeout can deliver an alert twice: the first try may have been queued just after `custom-n8n.py` gave up. Today the queue would take both rows, and the drain keeps them from running at the same time (one row waits while another for the same alert id runs), so the second run ends as `duplicate`. That relies on TheHive refusing the second alert, and **TheHive's duplicate refusal isn't atomic (A78)**. So before your retries go live, `recv-wazuh-alert` checks the queue for the alert id before inserting: a row that is pending, running or done (kept 24 h) means the delivery is answered 200 and not inserted again. This is part of N8N-1.9 on my side, built after checkpoint 1 together with your change.

## Questions

1. **Does integratord enforce the integration's `<timeout>` itself**, or does it only pass the value to the script? With retries inside the script, one call can last up to ~87 s. If integratord kills the script after `<timeout>`, the chain is cut short (and the timeout then has to cover the whole chain, not one try).
2. **Alerts still unread in `alerts.json`:** while integratord waits on a chain, later alerts queue up in `alerts.json`. Are they still delivered after the **midnight log rotation** (does integratord follow the rotated file to its end before switching), and after a **manager restart** (does it resume where it stopped, or start at the end of the file and skip them)? If either skips alerts, the retries move the loss instead of removing it, and that should go into C1's wording.

## What changes in C1 when it is built

The table row's interface stays as it is (path, token header, payload). The behaviour text (PROJECT.md 5, the "what a 200 means" paragraph) gains: retries on connection error, timeout, 5xx and 404, the fast-fail rule, and "n8n deduplicates by alert id at queue insert". The integrator updates that text and adds the check at the checkpoint that merges both sides.

## Update 2026-10-15: condition 3 is met (N8N-1.9 built on branch `n8n`)

Thanks for the answers (`nodes/core/wazuh/docs/request-n8n-x10-x37-2026-10-14.md`) and for building all three conditions on `wazuh-x10`. n8n's side is built and tested on the build instance (`full`, `standard`); README "Duplicate deliveries".

**What n8n answers now:** HTTP 200 with `{"status": "queued"}` (new alert), `{"status": "duplicate"}` (an alert id n8n already has: a queue row that is pending, running or done; done rows are kept 24 h), or `{"status": "filtered"}` (below `WAZUH_ALERT_MIN_LEVEL`). All three are 2xx, so your script stops on each of them. A queue row that ended `failed` doesn't count: a new delivery of that alert is queued again.

**Two guards, because the queue lookup isn't atomic.** `recv-wazuh-alert` looks the alert id up before the insert, but the lookup and the insert are separate steps on n8n's SQLite (Data Tables have no unique constraint), so two copies arriving within milliseconds can both be queued. `lib-alert-queue-drain` then finishes the second copy as `duplicate_delivery` without running the playbook (or makes it wait while the first copy runs). Your retries are sequential with waits of 2 s and more, so in practice they hit the first guard.

**Evidence (2026-10-15):**
- Same id twice, the second after the first finished, or while it was still queued: second answer 200 `duplicate`; one queue row, one TheHive alert, one writeback.
- Same id 2 or 5 times at the same instant (4 trials): 3 trials queued two rows, the drain ran only one; one TheHive alert every time.
- Your scenario by hand: n8n stopped → POST refused (connection refused); `docker start` → POST every 0.5 s with the same id: connection reset for ~3.5 s, then **HTTP 404** (`Cannot POST /webhook/wazuh-alert`, webhooks not registered yet) for ~2.6 s, then 200 `queued` 6.6 s after the start; once n8n was healthy, the same id again → 200 `duplicate`. One TheHive alert. Your script retries exactly these (connection errors, 404, 5xx; read from `origin/wazuh-x10`).
- 20 different alerts at the same instant: slowest 200 1.61 s (criterion 5 s), 20 alerts, n8n's peak 595 MiB of its 800 MiB.
- `contracts-check.sh --only C1,C3,C4,C10,C11,E2E`: all PASS.

**What's left:** your pull request with `wazuh-x10` after checkpoint 1 (2026-10-20); the C1 wording and the C1 retry check in `contracts-check.sh` are the integrator's, at that merge. Nothing else is needed from n8n.

## Update 2026-10-20: live

Your retries are merged (PR #31, checkpoint 1) and C1's behaviour is written down on `main`: PROJECT.md 5, "C1 delivery and retries", and decision **D51** (retries on connection errors, timeouts, HTTP 404 and 5xx, waits of 2, 5, 10 and 20 s, the 300 s fast-fail; `duplicate` is a final 2xx). The opt-in check `scripts/contracts-check.sh --only C1-RETRY` (n8n stopped, test alert fired, n8n started) **passes**: the alert was delivered on try 3, 15 s after n8n came back, with one `recv-wazuh-alert` execution and one TheHive alert. X-10 is closed.
