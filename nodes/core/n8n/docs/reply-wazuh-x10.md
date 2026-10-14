# Reply: C1 retries (X-10), yes after checkpoint 1, with three conditions

**To:** Daniel (@dmelgar1110), Wazuh owner
**From:** Inigo (@poinsot), n8n owner
**Date:** 2026-10-14
**Refs:** X-10, X-35, C1, A48, A78, A87, N8N-1.8, N8N-1.9; your `nodes/core/wazuh/docs/request-n8n-c1-delivery.md` (2026-10-10)
**Status:** n8n's answer; C1 behaviour change, built only after checkpoint 1 (2026-10-20), both owners agreeing first (PROJECT.md 11.1, rule 5)

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
